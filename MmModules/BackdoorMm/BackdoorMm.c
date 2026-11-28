/** @file
  BackdoorMm - a StandaloneMM (S-EL0) coverage test module.

  Registers an MMI handler on a dedicated "backdoor" GUID. When the Non-secure
  world sends an MM_COMMUNICATE (SMC) to that GUID, the MM core routes the
  message here and passes CommBuffer = the message payload (the Data[] that
  follows EFI_MM_COMMUNICATE_HEADER). This handler branches 256 ways on the
  first payload byte, each branch a distinct basic block (unique DEBUG string).

  Purpose: prove the LibAFL-QEMU fuzzer collects edge coverage from inside the
  Secure world - the fuzzer mutates CommBuffer[0], every new value takes a new
  secure-world branch, and the corpus grows accordingly.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MmServicesTableLib.h>

//
// Backdoor handler GUID (must match MmFuzzHarness.c HeaderGuid):
// A5E7B1C4-9D3F-4E8A-B6C2-1F0D7A2E5C83
//
STATIC CONST EFI_GUID  mBackdoorGuid = {
  0xA5E7B1C4, 0x9D3F, 0x4E8A, { 0xB6, 0xC2, 0x1F, 0x0D, 0x7A, 0x2E, 0x5C, 0x83 }
};

//
// Volatile sink keeps each branch's work from being optimized/merged away even
// if DEBUG output is disabled, so the 256 branches stay distinct blocks.
//
STATIC volatile UINT32  mBackdoorSink;

/**
  MMI handler: 256-way branch on the first payload byte (CommBuffer[0]).
**/
STATIC
EFI_STATUS
EFIAPI
BackdoorHandler (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context        OPTIONAL,
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  UINT8  b;

  if ((CommBuffer == NULL) || (CommBufferSize == NULL) || (*CommBufferSize < 1)) {
    return EFI_SUCCESS;
  }

  b = ((UINT8 *)CommBuffer)[0];

  UINT32* dead_ptr = (UINT32*)0xdeadbeef;

  switch (b) {
    case 0x00: mBackdoorSink = 0xB000u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x00\n")); break;
    case 0x01: mBackdoorSink = 0xB001u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x01\n")); break;
    case 0x02: mBackdoorSink = 0xB002u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x02\n")); break;
    case 0x03: mBackdoorSink = 0xB003u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x03\n")); break;
    case 0x04: mBackdoorSink = 0xB004u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x04\n")); break;
    case 0x05: mBackdoorSink = 0xB005u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x05\n")); break;
    case 0x06: mBackdoorSink = 0xB006u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x06\n")); break;
    case 0x07: mBackdoorSink = 0xB007u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x07\n")); break;
    case 0x08: mBackdoorSink = 0xB008u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x08\n")); *dead_ptr = 0x10; break;
    case 0x09: {
      // HeapGuard test: allocate a buffer and read ONE byte past its end.
      // The dynamic guard puts a no-access page flush at the 0x40-byte buffer,
      // so p[0x40] (exactly 1 byte past) faults -> OOB-read crash.
      VOID        *p  = NULL;
      EFI_STATUS  st  = gMmst->MmAllocatePool (EfiRuntimeServicesData, 0x40, &p);
      if (!EFI_ERROR (st) && (p != NULL)) {
        volatile UINT8  oob = ((volatile UINT8 *)p)[0x40];  // 1 byte OOB -> guard
        mBackdoorSink = 0xB009u | oob;
        gMmst->MmFreePool (p);
      }
      DEBUG ((DEBUG_INFO, "BKDR: branch 0x09 heap OOB test\n"));
      break;
    }
    case 0x0A: mBackdoorSink = 0xB00Au; DEBUG ((DEBUG_INFO, "BKDR: branch 0x0A\n")); break;
    case 0x0B: mBackdoorSink = 0xB00Bu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x0B\n")); break;
    case 0x0C: mBackdoorSink = 0xB00Cu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x0C\n")); break;
    case 0x0D: mBackdoorSink = 0xB00Du; DEBUG ((DEBUG_INFO, "BKDR: branch 0x0D\n")); break;
    case 0x0E: mBackdoorSink = 0xB00Eu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x0E\n")); break;
    case 0x0F: mBackdoorSink = 0xB00Fu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x0F\n")); break;
    case 0x10: mBackdoorSink = 0xB010u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x10\n")); break;
    case 0x11: mBackdoorSink = 0xB011u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x11\n")); break;
    case 0x12: mBackdoorSink = 0xB012u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x12\n")); break;
    case 0x13: mBackdoorSink = 0xB013u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x13\n")); break;
    case 0x14: mBackdoorSink = 0xB014u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x14\n")); break;
    case 0x15: mBackdoorSink = 0xB015u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x15\n")); break;
    case 0x16: mBackdoorSink = 0xB016u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x16\n")); break;
    case 0x17: mBackdoorSink = 0xB017u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x17\n")); break;
    case 0x18: mBackdoorSink = 0xB018u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x18\n")); break;
    case 0x19: mBackdoorSink = 0xB019u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x19\n")); break;
    case 0x1A: mBackdoorSink = 0xB01Au; DEBUG ((DEBUG_INFO, "BKDR: branch 0x1A\n")); break;
    case 0x1B: mBackdoorSink = 0xB01Bu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x1B\n")); break;
    case 0x1C: mBackdoorSink = 0xB01Cu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x1C\n")); break;
    case 0x1D: mBackdoorSink = 0xB01Du; DEBUG ((DEBUG_INFO, "BKDR: branch 0x1D\n")); break;
    case 0x1E: mBackdoorSink = 0xB01Eu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x1E\n")); break;
    case 0x1F: mBackdoorSink = 0xB01Fu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x1F\n")); break;
    case 0x20: mBackdoorSink = 0xB020u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x20\n")); break;
    case 0x21: mBackdoorSink = 0xB021u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x21\n")); break;
    case 0x22: mBackdoorSink = 0xB022u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x22\n")); break;
    case 0x23: mBackdoorSink = 0xB023u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x23\n")); break;
    case 0x24: mBackdoorSink = 0xB024u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x24\n")); break;
    case 0x25: mBackdoorSink = 0xB025u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x25\n")); break;
    case 0x26: mBackdoorSink = 0xB026u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x26\n")); break;
    case 0x27: mBackdoorSink = 0xB027u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x27\n")); break;
    case 0x28: mBackdoorSink = 0xB028u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x28\n")); break;
    case 0x29: mBackdoorSink = 0xB029u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x29\n")); break;
    case 0x2A: mBackdoorSink = 0xB02Au; DEBUG ((DEBUG_INFO, "BKDR: branch 0x2A\n")); break;
    case 0x2B: mBackdoorSink = 0xB02Bu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x2B\n")); break;
    case 0x2C: mBackdoorSink = 0xB02Cu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x2C\n")); break;
    case 0x2D: mBackdoorSink = 0xB02Du; DEBUG ((DEBUG_INFO, "BKDR: branch 0x2D\n")); break;
    case 0x2E: mBackdoorSink = 0xB02Eu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x2E\n")); break;
    case 0x2F: mBackdoorSink = 0xB02Fu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x2F\n")); break;
    case 0x30: mBackdoorSink = 0xB030u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x30\n")); break;
    case 0x31: mBackdoorSink = 0xB031u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x31\n")); break;
    case 0x32: mBackdoorSink = 0xB032u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x32\n")); break;
    case 0x33: mBackdoorSink = 0xB033u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x33\n")); break;
    case 0x34: mBackdoorSink = 0xB034u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x34\n")); break;
    case 0x35: mBackdoorSink = 0xB035u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x35\n")); break;
    case 0x36: mBackdoorSink = 0xB036u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x36\n")); break;
    case 0x37: mBackdoorSink = 0xB037u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x37\n")); break;
    case 0x38: mBackdoorSink = 0xB038u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x38\n")); break;
    case 0x39: mBackdoorSink = 0xB039u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x39\n")); break;
    case 0x3A: mBackdoorSink = 0xB03Au; DEBUG ((DEBUG_INFO, "BKDR: branch 0x3A\n")); break;
    case 0x3B: mBackdoorSink = 0xB03Bu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x3B\n")); break;
    case 0x3C: mBackdoorSink = 0xB03Cu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x3C\n")); break;
    case 0x3D: mBackdoorSink = 0xB03Du; DEBUG ((DEBUG_INFO, "BKDR: branch 0x3D\n")); break;
    case 0x3E: mBackdoorSink = 0xB03Eu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x3E\n")); break;
    case 0x3F: mBackdoorSink = 0xB03Fu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x3F\n")); break;
    case 0x40: mBackdoorSink = 0xB040u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x40\n")); break;
    case 0x41: mBackdoorSink = 0xB041u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x41\n")); break;
    case 0x42: mBackdoorSink = 0xB042u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x42\n")); break;
    case 0x43: mBackdoorSink = 0xB043u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x43\n")); break;
    case 0x44: mBackdoorSink = 0xB044u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x44\n")); break;
    case 0x45: mBackdoorSink = 0xB045u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x45\n")); break;
    case 0x46: mBackdoorSink = 0xB046u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x46\n")); break;
    case 0x47: mBackdoorSink = 0xB047u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x47\n")); break;
    case 0x48: mBackdoorSink = 0xB048u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x48\n")); break;
    case 0x49: mBackdoorSink = 0xB049u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x49\n")); break;
    case 0x4A: mBackdoorSink = 0xB04Au; DEBUG ((DEBUG_INFO, "BKDR: branch 0x4A\n")); break;
    case 0x4B: mBackdoorSink = 0xB04Bu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x4B\n")); break;
    case 0x4C: mBackdoorSink = 0xB04Cu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x4C\n")); break;
    case 0x4D: mBackdoorSink = 0xB04Du; DEBUG ((DEBUG_INFO, "BKDR: branch 0x4D\n")); break;
    case 0x4E: mBackdoorSink = 0xB04Eu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x4E\n")); break;
    case 0x4F: mBackdoorSink = 0xB04Fu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x4F\n")); break;
    case 0x50: mBackdoorSink = 0xB050u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x50\n")); break;
    case 0x51: mBackdoorSink = 0xB051u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x51\n")); break;
    case 0x52: mBackdoorSink = 0xB052u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x52\n")); break;
    case 0x53: mBackdoorSink = 0xB053u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x53\n")); break;
    case 0x54: mBackdoorSink = 0xB054u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x54\n")); break;
    case 0x55: mBackdoorSink = 0xB055u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x55\n")); break;
    case 0x56: mBackdoorSink = 0xB056u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x56\n")); break;
    case 0x57: mBackdoorSink = 0xB057u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x57\n")); break;
    case 0x58: mBackdoorSink = 0xB058u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x58\n")); break;
    case 0x59: mBackdoorSink = 0xB059u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x59\n")); break;
    case 0x5A: mBackdoorSink = 0xB05Au; DEBUG ((DEBUG_INFO, "BKDR: branch 0x5A\n")); break;
    case 0x5B: mBackdoorSink = 0xB05Bu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x5B\n")); break;
    case 0x5C: mBackdoorSink = 0xB05Cu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x5C\n")); break;
    case 0x5D: mBackdoorSink = 0xB05Du; DEBUG ((DEBUG_INFO, "BKDR: branch 0x5D\n")); break;
    case 0x5E: mBackdoorSink = 0xB05Eu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x5E\n")); break;
    case 0x5F: mBackdoorSink = 0xB05Fu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x5F\n")); break;
    case 0x60: mBackdoorSink = 0xB060u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x60\n")); break;
    case 0x61: mBackdoorSink = 0xB061u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x61\n")); break;
    case 0x62: mBackdoorSink = 0xB062u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x62\n")); break;
    case 0x63: mBackdoorSink = 0xB063u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x63\n")); break;
    case 0x64: mBackdoorSink = 0xB064u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x64\n")); break;
    case 0x65: mBackdoorSink = 0xB065u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x65\n")); break;
    case 0x66: mBackdoorSink = 0xB066u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x66\n")); break;
    case 0x67: mBackdoorSink = 0xB067u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x67\n")); break;
    case 0x68: mBackdoorSink = 0xB068u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x68\n")); break;
    case 0x69: mBackdoorSink = 0xB069u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x69\n")); break;
    case 0x6A: mBackdoorSink = 0xB06Au; DEBUG ((DEBUG_INFO, "BKDR: branch 0x6A\n")); break;
    case 0x6B: mBackdoorSink = 0xB06Bu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x6B\n")); break;
    case 0x6C: mBackdoorSink = 0xB06Cu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x6C\n")); break;
    case 0x6D: mBackdoorSink = 0xB06Du; DEBUG ((DEBUG_INFO, "BKDR: branch 0x6D\n")); break;
    case 0x6E: mBackdoorSink = 0xB06Eu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x6E\n")); break;
    case 0x6F: mBackdoorSink = 0xB06Fu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x6F\n")); break;
    case 0x70: mBackdoorSink = 0xB070u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x70\n")); break;
    case 0x71: mBackdoorSink = 0xB071u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x71\n")); break;
    case 0x72: mBackdoorSink = 0xB072u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x72\n")); break;
    case 0x73: mBackdoorSink = 0xB073u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x73\n")); break;
    case 0x74: mBackdoorSink = 0xB074u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x74\n")); break;
    case 0x75: mBackdoorSink = 0xB075u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x75\n")); break;
    case 0x76: mBackdoorSink = 0xB076u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x76\n")); break;
    case 0x77: mBackdoorSink = 0xB077u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x77\n")); break;
    case 0x78: mBackdoorSink = 0xB078u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x78\n")); break;
    case 0x79: mBackdoorSink = 0xB079u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x79\n")); break;
    case 0x7A: mBackdoorSink = 0xB07Au; DEBUG ((DEBUG_INFO, "BKDR: branch 0x7A\n")); break;
    case 0x7B: mBackdoorSink = 0xB07Bu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x7B\n")); break;
    case 0x7C: mBackdoorSink = 0xB07Cu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x7C\n")); break;
    case 0x7D: mBackdoorSink = 0xB07Du; DEBUG ((DEBUG_INFO, "BKDR: branch 0x7D\n")); break;
    case 0x7E: mBackdoorSink = 0xB07Eu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x7E\n")); break;
    case 0x7F: mBackdoorSink = 0xB07Fu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x7F\n")); break;
    case 0x80: mBackdoorSink = 0xB080u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x80\n")); break;
    case 0x81: mBackdoorSink = 0xB081u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x81\n")); break;
    case 0x82: mBackdoorSink = 0xB082u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x82\n")); break;
    case 0x83: mBackdoorSink = 0xB083u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x83\n")); break;
    case 0x84: mBackdoorSink = 0xB084u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x84\n")); break;
    case 0x85: mBackdoorSink = 0xB085u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x85\n")); break;
    case 0x86: mBackdoorSink = 0xB086u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x86\n")); break;
    case 0x87: mBackdoorSink = 0xB087u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x87\n")); break;
    case 0x88: mBackdoorSink = 0xB088u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x88\n")); break;
    case 0x89: mBackdoorSink = 0xB089u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x89\n")); break;
    case 0x8A: mBackdoorSink = 0xB08Au; DEBUG ((DEBUG_INFO, "BKDR: branch 0x8A\n")); break;
    case 0x8B: mBackdoorSink = 0xB08Bu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x8B\n")); break;
    case 0x8C: mBackdoorSink = 0xB08Cu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x8C\n")); break;
    case 0x8D: mBackdoorSink = 0xB08Du; DEBUG ((DEBUG_INFO, "BKDR: branch 0x8D\n")); break;
    case 0x8E: mBackdoorSink = 0xB08Eu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x8E\n")); break;
    case 0x8F: mBackdoorSink = 0xB08Fu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x8F\n")); break;
    case 0x90: mBackdoorSink = 0xB090u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x90\n")); break;
    case 0x91: mBackdoorSink = 0xB091u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x91\n")); break;
    case 0x92: mBackdoorSink = 0xB092u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x92\n")); break;
    case 0x93: mBackdoorSink = 0xB093u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x93\n")); break;
    case 0x94: mBackdoorSink = 0xB094u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x94\n")); break;
    case 0x95: mBackdoorSink = 0xB095u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x95\n")); break;
    case 0x96: mBackdoorSink = 0xB096u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x96\n")); break;
    case 0x97: mBackdoorSink = 0xB097u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x97\n")); break;
    case 0x98: mBackdoorSink = 0xB098u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x98\n")); break;
    case 0x99: mBackdoorSink = 0xB099u; DEBUG ((DEBUG_INFO, "BKDR: branch 0x99\n")); break;
    case 0x9A: mBackdoorSink = 0xB09Au; DEBUG ((DEBUG_INFO, "BKDR: branch 0x9A\n")); break;
    case 0x9B: mBackdoorSink = 0xB09Bu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x9B\n")); break;
    case 0x9C: mBackdoorSink = 0xB09Cu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x9C\n")); break;
    case 0x9D: mBackdoorSink = 0xB09Du; DEBUG ((DEBUG_INFO, "BKDR: branch 0x9D\n")); break;
    case 0x9E: mBackdoorSink = 0xB09Eu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x9E\n")); break;
    case 0x9F: mBackdoorSink = 0xB09Fu; DEBUG ((DEBUG_INFO, "BKDR: branch 0x9F\n")); break;
    case 0xA0: mBackdoorSink = 0xB0A0u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xA0\n")); break;
    case 0xA1: mBackdoorSink = 0xB0A1u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xA1\n")); break;
    case 0xA2: mBackdoorSink = 0xB0A2u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xA2\n")); break;
    case 0xA3: mBackdoorSink = 0xB0A3u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xA3\n")); break;
    case 0xA4: mBackdoorSink = 0xB0A4u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xA4\n")); break;
    case 0xA5: mBackdoorSink = 0xB0A5u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xA5\n")); break;
    case 0xA6: mBackdoorSink = 0xB0A6u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xA6\n")); break;
    case 0xA7: mBackdoorSink = 0xB0A7u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xA7\n")); break;
    case 0xA8: mBackdoorSink = 0xB0A8u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xA8\n")); break;
    case 0xA9: mBackdoorSink = 0xB0A9u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xA9\n")); break;
    case 0xAA: mBackdoorSink = 0xB0AAu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xAA\n")); break;
    case 0xAB: mBackdoorSink = 0xB0ABu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xAB\n")); break;
    case 0xAC: mBackdoorSink = 0xB0ACu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xAC\n")); break;
    case 0xAD: mBackdoorSink = 0xB0ADu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xAD\n")); break;
    case 0xAE: mBackdoorSink = 0xB0AEu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xAE\n")); break;
    case 0xAF: mBackdoorSink = 0xB0AFu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xAF\n")); break;
    case 0xB0: mBackdoorSink = 0xB0B0u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xB0\n")); break;
    case 0xB1: mBackdoorSink = 0xB0B1u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xB1\n")); break;
    case 0xB2: mBackdoorSink = 0xB0B2u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xB2\n")); break;
    case 0xB3: mBackdoorSink = 0xB0B3u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xB3\n")); break;
    case 0xB4: mBackdoorSink = 0xB0B4u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xB4\n")); break;
    case 0xB5: mBackdoorSink = 0xB0B5u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xB5\n")); break;
    case 0xB6: mBackdoorSink = 0xB0B6u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xB6\n")); break;
    case 0xB7: mBackdoorSink = 0xB0B7u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xB7\n")); break;
    case 0xB8: mBackdoorSink = 0xB0B8u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xB8\n")); break;
    case 0xB9: mBackdoorSink = 0xB0B9u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xB9\n")); break;
    case 0xBA: mBackdoorSink = 0xB0BAu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xBA\n")); break;
    case 0xBB: mBackdoorSink = 0xB0BBu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xBB\n")); break;
    case 0xBC: mBackdoorSink = 0xB0BCu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xBC\n")); break;
    case 0xBD: mBackdoorSink = 0xB0BDu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xBD\n")); break;
    case 0xBE: mBackdoorSink = 0xB0BEu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xBE\n")); break;
    case 0xBF: mBackdoorSink = 0xB0BFu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xBF\n")); break;
    case 0xC0: mBackdoorSink = 0xB0C0u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xC0\n")); break;
    case 0xC1: mBackdoorSink = 0xB0C1u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xC1\n")); break;
    case 0xC2: mBackdoorSink = 0xB0C2u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xC2\n")); break;
    case 0xC3: mBackdoorSink = 0xB0C3u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xC3\n")); break;
    case 0xC4: mBackdoorSink = 0xB0C4u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xC4\n")); break;
    case 0xC5: mBackdoorSink = 0xB0C5u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xC5\n")); break;
    case 0xC6: mBackdoorSink = 0xB0C6u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xC6\n")); break;
    case 0xC7: mBackdoorSink = 0xB0C7u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xC7\n")); break;
    case 0xC8: mBackdoorSink = 0xB0C8u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xC8\n")); break;
    case 0xC9: mBackdoorSink = 0xB0C9u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xC9\n")); break;
    case 0xCA: mBackdoorSink = 0xB0CAu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xCA\n")); break;
    case 0xCB: mBackdoorSink = 0xB0CBu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xCB\n")); break;
    case 0xCC: mBackdoorSink = 0xB0CCu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xCC\n")); break;
    case 0xCD: mBackdoorSink = 0xB0CDu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xCD\n")); break;
    case 0xCE: mBackdoorSink = 0xB0CEu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xCE\n")); break;
    case 0xCF: mBackdoorSink = 0xB0CFu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xCF\n")); break;
    case 0xD0: mBackdoorSink = 0xB0D0u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xD0\n")); break;
    case 0xD1: mBackdoorSink = 0xB0D1u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xD1\n")); break;
    case 0xD2: mBackdoorSink = 0xB0D2u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xD2\n")); break;
    case 0xD3: mBackdoorSink = 0xB0D3u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xD3\n")); break;
    case 0xD4: mBackdoorSink = 0xB0D4u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xD4\n")); break;
    case 0xD5: mBackdoorSink = 0xB0D5u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xD5\n")); break;
    case 0xD6: mBackdoorSink = 0xB0D6u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xD6\n")); break;
    case 0xD7: mBackdoorSink = 0xB0D7u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xD7\n")); break;
    case 0xD8: mBackdoorSink = 0xB0D8u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xD8\n")); break;
    case 0xD9: mBackdoorSink = 0xB0D9u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xD9\n")); break;
    case 0xDA: mBackdoorSink = 0xB0DAu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xDA\n")); break;
    case 0xDB: mBackdoorSink = 0xB0DBu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xDB\n")); break;
    case 0xDC: mBackdoorSink = 0xB0DCu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xDC\n")); break;
    case 0xDD: mBackdoorSink = 0xB0DDu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xDD\n")); break;
    case 0xDE: mBackdoorSink = 0xB0DEu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xDE\n")); break;
    case 0xDF: mBackdoorSink = 0xB0DFu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xDF\n")); break;
    case 0xE0: mBackdoorSink = 0xB0E0u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xE0\n")); break;
    case 0xE1: mBackdoorSink = 0xB0E1u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xE1\n")); break;
    case 0xE2: mBackdoorSink = 0xB0E2u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xE2\n")); break;
    case 0xE3: mBackdoorSink = 0xB0E3u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xE3\n")); break;
    case 0xE4: mBackdoorSink = 0xB0E4u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xE4\n")); break;
    case 0xE5: mBackdoorSink = 0xB0E5u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xE5\n")); break;
    case 0xE6: mBackdoorSink = 0xB0E6u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xE6\n")); break;
    case 0xE7: mBackdoorSink = 0xB0E7u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xE7\n")); break;
    case 0xE8: mBackdoorSink = 0xB0E8u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xE8\n")); break;
    case 0xE9: mBackdoorSink = 0xB0E9u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xE9\n")); break;
    case 0xEA: mBackdoorSink = 0xB0EAu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xEA\n")); break;
    case 0xEB: mBackdoorSink = 0xB0EBu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xEB\n")); break;
    case 0xEC: mBackdoorSink = 0xB0ECu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xEC\n")); break;
    case 0xED: mBackdoorSink = 0xB0EDu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xED\n")); break;
    case 0xEE: mBackdoorSink = 0xB0EEu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xEE\n")); break;
    case 0xEF: mBackdoorSink = 0xB0EFu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xEF\n")); break;
    case 0xF0: mBackdoorSink = 0xB0F0u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xF0\n")); break;
    case 0xF1: mBackdoorSink = 0xB0F1u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xF1\n")); break;
    case 0xF2: mBackdoorSink = 0xB0F2u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xF2\n")); break;
    case 0xF3: mBackdoorSink = 0xB0F3u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xF3\n")); break;
    case 0xF4: mBackdoorSink = 0xB0F4u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xF4\n")); break;
    case 0xF5: mBackdoorSink = 0xB0F5u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xF5\n")); break;
    case 0xF6: mBackdoorSink = 0xB0F6u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xF6\n")); break;
    case 0xF7: mBackdoorSink = 0xB0F7u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xF7\n")); break;
    case 0xF8: mBackdoorSink = 0xB0F8u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xF8\n")); break;
    case 0xF9: mBackdoorSink = 0xB0F9u; DEBUG ((DEBUG_INFO, "BKDR: branch 0xF9\n")); break;
    case 0xFA: mBackdoorSink = 0xB0FAu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xFA\n")); break;
    case 0xFB: mBackdoorSink = 0xB0FBu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xFB\n")); break;
    case 0xFC: mBackdoorSink = 0xB0FCu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xFC\n")); break;
    case 0xFD: mBackdoorSink = 0xB0FDu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xFD\n")); break;
    case 0xFE: mBackdoorSink = 0xB0FEu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xFE\n")); break;
    case 0xFF: mBackdoorSink = 0xB0FFu; DEBUG ((DEBUG_INFO, "BKDR: branch 0xFF\n")); break;
    default:
      break;
  }

  return EFI_SUCCESS;
}

/**
  Module entry point: register the backdoor MMI handler.
**/
EFI_STATUS
EFIAPI
BackdoorMmEntry (
  IN EFI_HANDLE            ImageHandle,
  IN EFI_MM_SYSTEM_TABLE   *MmSystemTable
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  Dispatch;

  Dispatch = NULL;
  Status   = gMmst->MmiHandlerRegister (BackdoorHandler, &mBackdoorGuid, &Dispatch);

  DEBUG ((
    DEBUG_INFO,
    "BKDR: register handler %g -> %r\n",
    &mBackdoorGuid,
    Status
    ));

  return Status;
}
