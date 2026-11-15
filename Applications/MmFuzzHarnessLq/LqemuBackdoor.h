#ifndef LQEMU_BACKDOOR_H_
#define LQEMU_BACKDOOR_H_
#define LQEMU_CUSTOM_INSN_WORD          0x66f23a0f
#define LIBAFL_QEMU_COMMAND_START_VIRT  0      // libvharness common.h @9a31696
#define LIBAFL_QEMU_COMMAND_END         4
#define LIBAFL_QEMU_END_OK              1
#define _LQEMU_STR2(x)  #x
#define _LQEMU_STR(x)   _LQEMU_STR2 (x)
#if defined (__aarch64__) || defined (MDE_CPU_AARCH64)
static __attribute__ ((noinline)) unsigned long
LqemuCall (unsigned long Cmd, unsigned long Arg1, unsigned long Arg2) {
  register unsigned long x0 __asm__ ("x0") = Cmd;
  register unsigned long x1 __asm__ ("x1") = Arg1;
  register unsigned long x2 __asm__ ("x2") = Arg2;
  __asm__ __volatile__ (".word " _LQEMU_STR (LQEMU_CUSTOM_INSN_WORD) "\n"
    : "+r" (x0) : "r" (x1), "r" (x2) : "memory");
  return x0;
}
#else
#error "LqemuBackdoor.h: only AArch64"
#endif
#endif
