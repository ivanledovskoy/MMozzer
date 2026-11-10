# Environment

```
export MMOZZER=`realpath .`
export WORKSPACE=$MMOZZER/build
export GCC_AARCH64_PREFIX=aarch64-none-elf-      # for edk2
export CROSS_COMPILE=aarch64-none-elf-           # for TF-A
export PACKAGES_PATH=$MMOZZER/edk2:$MMOZZER/edk2-platforms:$MMOZZER/edk2-non-osi:$MMOZZER
mkdir -p "$WORKSPACE"
```

# Build standalone MM

```
make -C "$MMOZZER/edk2/BaseTools" -j"$(nproc)"
cd "$MMOZZER/edk2" && set +u && source edksetup.sh BaseTools

cd "$WORKSPACE"
build -a AARCH64 -t GCC -b DEBUG -n "$(nproc)" -p Platform/Qemu/SbsaQemu/StandaloneMm/SbsaQemuStandaloneMm.dsc
```

# Build TF-A
```
cd "$MMOZZER/trusted-firmware-a"
make PLAT=qemu_sbsa DEBUG=1 LOG_LEVEL=40 \
     SPM_MM=1 EL3_EXCEPTION_HANDLING=1 CTX_INCLUDE_FPREGS=1 \
     TRANSFER_LIST=1 HOB_LIST=1 \
     BL32="$WORKSPACE/Build/SbsaQemuStandaloneMm/DEBUG_GCC/FV/STANDALONE_MM.fd" \
     -j"$(nproc)" all fip

B="$MMOZZER/trusted-firmware-a/build/qemu_sbsa/debug"
cp "$B/bl1.bin" "$B/fip.bin" "$MMOZZER/edk2-non-osi/Platform/Qemu/Sbsa/"
```

# Build UEFI

```
cd "$WORKSPACE"
build -a AARCH64 -t GCC -b DEBUG -n "$(nproc)" \
  -p Platform/Qemu/SbsaQemu/SbsaQemu.dsc -D ENABLE_STMM=TRUE
```

# Preparing

```
mkdir -p "$MMOZZER/out"
cp "$WORKSPACE/Build/SbsaQemu/DEBUG_GCC/FV/SBSA_FLASH0.fd" "$MMOZZER/out/"
cp "$WORKSPACE/Build/SbsaQemu/DEBUG_GCC/FV/SBSA_FLASH1.fd" "$MMOZZER/out/"
truncate -s 256M "$MMOZZER/out/SBSA_FLASH0.fd"
truncate -s 256M "$MMOZZER/out/SBSA_FLASH1.fd"
```

# Applications
```
cd "$MMOZZER/edk2" && set +u && source edksetup.sh BaseTools && cd "$WORKSPACE"

build -a AARCH64 -t GCC -b DEBUG -n "$(nproc)" -p Applications/Apps.dsc

mkdir -p "$MMOZZER/out/esp"
cp "$WORKSPACE/Build/Apps/DEBUG_GCC/AARCH64/VarTest.efi" "$MMOZZER/out/esp/"
```

# Run
```
qemu-system-aarch64 -M sbsa-ref -m 2048 -smp 2 \
  -drive if=pflash,format=raw,file="$MMOZZER/out/SBSA_FLASH0.fd" \
  -drive if=pflash,format=raw,file="$MMOZZER/out/SBSA_FLASH1.fd" \
  -drive if=none,id=esp,format=raw,file=fat:rw:"$MMOZZER/out/esp" \
  -device ide-hd,drive=esp,bus=ide.0 \
  -serial mon:stdio \
  -serial file:"$MMOZZER/out/uart1_secure.log" \
  -serial file:"$MMOZZER/out/uart2_stmm.log" \
  -nographic
```

# Run apps (UEFI shell)
```
fs0:
VarTest.efi
```
