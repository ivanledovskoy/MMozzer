//! A fuzzer using qemu in systemmode for binary-only coverage of kernels
use core::time::Duration;
use std::{env, path::PathBuf, process};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{CalibrationStage, StdMutationalStage},
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::{
    emu::Emulator, executor::QemuExecutor, modules::edges::StdEdgeCoverageClassicModule,
    FastSnapshotManager,
};
use libafl_qemu::{
    sys::libafl_exit_request_timeout, DeviceSnapshotFilter, GuestAddr, Qemu, QemuExitReason, Regs,
};

/// Devices to EXCLUDE from fast-snapshot device save/restore. The firmware flash
/// (`pflash_cfi01`, two of them) must be excluded: saving/restoring its device
/// state across two coexisting snapshots crashes QEMU, and its content is
/// COW-backed anyway (`-snapshot`). Mirrors smufuzz's get_snapshot_dev_filter_list.
fn snapshot_dev_filter() -> DeviceSnapshotFilter {
    DeviceSnapshotFilter::DenyList(vec![
        "pflash_cfi01".to_string(),
        "pflash_cfi01".to_string(),
    ])
}
use libafl::{executors::ExitKind, inputs::HasTargetBytes};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};

// Calibration sync-exit command IDs emitted by the MM core dispatcher when the
// firmware is built with -D MM_CALIBRATE=TRUE (see StandaloneMmPkg Dispatcher.c).
const CMD_LOAD_PRE: u64 = 0x0A10; // x1 = &gMmCalSkip, x2 = &FileName (FFS GUID)
const CMD_LOAD_POST: u64 = 0x0A11; // module entry returned
const CMD_START_VIRT: u64 = 0x0; // NS-world harness handoff (x1 = payload, x2 = cap)

extern "C" fn on_alarm(_sig: libc::c_int) {
    // Make the in-flight qemu.run() return QemuExitReason::Timeout.
    unsafe { libafl_exit_request_timeout() };
}

fn set_timer(secs: i64) {
    let it = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: secs, tv_usec: 0 },
    };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &it, core::ptr::null_mut()) };
}

fn read_guid(qemu: Qemu, addr: GuestAddr) -> [u8; 16] {
    let mut g = [0u8; 16];
    let _ = qemu.read_mem(addr, &mut g);
    g
}

fn guid_str(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Parse "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" into EFI_GUID byte layout.
fn parse_guid(s: &str) -> Option<[u8; 16]> {
    let p: Vec<&str> = s.trim().split('-').collect();
    if p.len() != 5 {
        return None;
    }
    let d1 = u32::from_str_radix(p[0], 16).ok()?;
    let d2 = u16::from_str_radix(p[1], 16).ok()?;
    let d3 = u16::from_str_radix(p[2], 16).ok()?;
    let b3 = hex_bytes(p[3])?;
    let b4 = hex_bytes(p[4])?;
    if b3.len() != 2 || b4.len() != 6 {
        return None;
    }
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&d1.to_le_bytes());
    g[4..6].copy_from_slice(&d2.to_le_bytes());
    g[6..8].copy_from_slice(&d3.to_le_bytes());
    g[8..10].copy_from_slice(&b3);
    g[10..16].copy_from_slice(&b4);
    Some(g)
}

/// FFS-GUIDs of modules to skip at load (comma-separated in MODLOAD_SKIP), e.g. from
/// a one-off run of the standalone calibrator.
fn parse_skip_set() -> Vec<[u8; 16]> {
    env::var("MODLOAD_SKIP")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                parse_guid(s).or_else(|| {
                    eprintln!("MODLOAD: bad MODLOAD_SKIP guid '{s}' - ignored");
                    None
                })
            }
        })
        .collect()
}

fn main() {
    env_logger::init();

    if let Ok(s) = env::var("FUZZ_SIZE") {
        str::parse::<usize>(&s).expect("FUZZ_SIZE was not a number");
    };

    // Hardcoded parameters
    let timeout = Duration::from_secs(30);
    let broker_port = 1340;
    let cores = Cores::from_cmdline("1").unwrap();
    let corpus_dirs = [PathBuf::from("./corpus")];
    let objective_dir = PathBuf::from("./crashes");

    let mut run_client = |state: Option<_>, mut mgr, _client_description| {
        // Initialize QEMU
        let args: Vec<String> = env::args().collect();

        // Create an observation channel using the coverage map
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };

        // Choose modules to use
        let modules = tuple_list!(StdEdgeCoverageClassicModule::builder()
            .map_observer(edges_observer.as_mut())
            .build()?);

        let emu = Emulator::builder()
            .qemu_parameters(args)
            .modules(modules)
            .snapshot_manager(FastSnapshotManager::default())
            .build()?;

        let devices = emu.list_devices();
        println!("Devices = {:?}", devices);

        // ---- Dynamic module-loading calibration + boot to harness (one process) ----
        // Firmware -D MM_CALIBRATE=TRUE emits a LOAD_PRE/LOAD_POST sync-exit around
        // each MM module entry. We take ONE root snapshot at the first module; if a
        // module hangs in its entry (per-module timeout) we record it, root-restore,
        // and REPLAY the dispatch skipping the known-bad ones, until a clean pass
        // reaches the NS harness' START_VIRT. We then PUSH an incremental checkpoint
        // there - that single snapshot object serves BOTH discovery (root restore)
        // AND fuzzing (increment restore), so no second snapshot is needed and syx
        // stays in one clean lifecycle. MODLOAD_SKIP, if set, pre-seeds the skip-set to
        // save replay passes (optional). With no MM_CALIBRATE there are no LOAD_*
        // exits and we go straight to START_VIRT.
        let qemu = emu.qemu();
        let boot_to: i64 = env::var("MODLOAD_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);
        unsafe { libc::signal(libc::SIGALRM, on_alarm as *const () as libc::sighandler_t) };

        let mut skip_set = parse_skip_set();
        let mut root_snap = None;
        let mut root_skip_addr: GuestAddr = 0;
        let mut root_guid = [0u8; 16];
        let mut cur_guid = [0u8; 16];
        let mut in_entry = false;
        let mut idle = 0u32;
        let mut reported_loaded: Vec<[u8; 16]> = Vec::new(); // dedup across replay passes

        let (payload_addr, cap): (GuestAddr, usize) = loop {
            set_timer(boot_to);
            let exit = unsafe { qemu.run() }.expect("qemu.run() failed in calibration phase");
            set_timer(0);
            match exit {
                QemuExitReason::SyncExit => {
                    idle = 0;
                    let cmd = qemu.read_reg(Regs::X0).unwrap_or(0) as u64;
                    let a1 = qemu.read_reg(Regs::X1).unwrap_or(0) as u64;
                    let a2 = qemu.read_reg(Regs::X2).unwrap_or(0) as u64;
                    match cmd {
                        CMD_LOAD_PRE => {
                            let cur_skip_addr = a1 as GuestAddr;
                            cur_guid = read_guid(qemu, a2 as GuestAddr);
                            if root_snap.is_none() {
                                root_snap = Some(qemu.create_fast_snapshot_filter(true, &snapshot_dev_filter()));
                                root_skip_addr = cur_skip_addr;
                                root_guid = cur_guid;
                            }
                            in_entry = true;
                            // Known-bad module: poke its skip flag so it is not run
                            // (silent here; it was already reported HANG on discovery).
                            if skip_set.iter().any(|g| g == &cur_guid) {
                                let _ = qemu.write_mem(cur_skip_addr, &1u64.to_le_bytes());
                            }
                        }
                        CMD_LOAD_POST => {
                            // Module entry returned OK. Report each survivor once
                            // (replays re-run survivors, so dedup the logging).
                            in_entry = false;
                            let g = read_guid(qemu, a1 as GuestAddr);
                            if !reported_loaded.iter().any(|x| x == &g) {
                                reported_loaded.push(g);
                                println!("MODLOAD: loaded {}", guid_str(&g));
                            }
                        }
                        CMD_START_VIRT => break (a1 as GuestAddr, a2 as usize),
                        other => println!("MODLOAD: ignoring sync cmd {other:#x}"),
                    }
                }
                QemuExitReason::Timeout => {
                    if in_entry {
                        if skip_set.iter().any(|g| g == &cur_guid) {
                            eprintln!("MODLOAD: {} still hangs after skip - aborting", guid_str(&cur_guid));
                            process::exit(1);
                        }
                        println!("MODLOAD: HANG {} -> skip & replay", guid_str(&cur_guid));
                        skip_set.push(cur_guid);
                        let r = root_snap.expect("timeout before any snapshot");
                        unsafe { qemu.restore_fast_snapshot(r) };
                        // Positioned just after the first module's LOAD_PRE: account
                        // for being "in" it and set its skip flag if known-bad.
                        cur_guid = root_guid;
                        in_entry = true;
                        let v: u64 = if skip_set.iter().any(|g| g == &root_guid) { 1 } else { 0 };
                        let _ = qemu.write_mem(root_skip_addr, &v.to_le_bytes());
                    } else {
                        idle += 1;
                        if idle > 10 {
                            eprintln!("MODLOAD: no START_VIRT after dispatch - is MmFuzzHarnessLq in the ESP?");
                            process::exit(1);
                        }
                    }
                }
                other => {
                    eprintln!("MODLOAD: unexpected guest exit {other:?} before harness");
                    process::exit(1);
                }
            }
        };
        set_timer(0);
        println!(
            "MODLOAD: done - {} module(s) loaded, {} skipped (hung)",
            reported_loaded.len(),
            skip_set.len()
        );
        if !skip_set.is_empty() {
            print!("MODLOAD: skipped (hung):");
            for g in &skip_set {
                print!(" {}", guid_str(g));
            }
            println!();
        }
        println!("MODLOAD: reached harness START_VIRT (payload={payload_addr:#x} cap={cap:#x}) - start fuzzing");

        // Take the fuzzing snapshot at START_VIRT, then free the discovery root so
        // only ONE snapshot is live during fuzzing. Each iteration does a FULL
        // restore of this snapshot (robust: it does not depend on incremental dirty
        // tracking that could be confused by the earlier root restores).
        // Second concurrent snapshot: must NOT take over the active bdrv cache
        // (the discovery root already did), or syx double-moves it and crashes.
        let fuzz_snap = qemu.create_fast_snapshot_filter_bdrv(true, &snapshot_dev_filter(), false);
        let _ = root_snap; // keep the discovery root alive

        // The harness: write the mutated input into the handler's payload buffer,
        // run one MM_COMMUNICATE (until the harness' END sync-exit), then restore.
        let mut harness = move |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                                _state: &mut _,
                                input: &BytesInput| {
            let qemu = emulator.qemu();
            let target = input.target_bytes();
            let buf = &target[..];
            let len = core::cmp::min(buf.len(), cap);
            unsafe {
                let _ = qemu.write_mem(payload_addr, &buf[..len]);
                let kind = match qemu.run() {
                    Ok(QemuExitReason::SyncExit) => ExitKind::Ok, // harness END
                    Ok(QemuExitReason::Timeout) => ExitKind::Timeout,
                    Ok(QemuExitReason::End(_)) => ExitKind::Crash,
                    Ok(_) => ExitKind::Ok,
                    Err(_) => ExitKind::Crash,
                };
                // Full restore back to the START_VIRT fuzzing snapshot.
                qemu.restore_fast_snapshot_full(fuzz_snap);
                kind
            }
        };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new(&edges_observer),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // Setup an havoc mutator with a mutational stage
        let mutator = HavocScheduledMutator::new(havoc_mutations());
        let calibration_feedback = MaxMapFeedback::new(&edges_observer);
        let mut stages = tuple_list!(
            StdMutationalStage::new(mutator),
            CalibrationStage::new(&calibration_feedback)
        );

        // Create a QEMU in-process executor
        let mut executor = QemuExecutor::new(
            emu,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("Failed to create QemuExecutor");

        // Instead of calling the timeout handler and restart the process, trigger a breakpoint ASAP
        executor.break_on_timeout();

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|err| {
                    println!("Failed to load initial corpus at {corpus_dirs:?}: {err:?}");
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .unwrap();
        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // Build and run a Launcher
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(broker_port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
