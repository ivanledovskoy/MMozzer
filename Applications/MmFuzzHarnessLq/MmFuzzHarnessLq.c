#include <Uefi.h>
#include <Protocol/MmCommunication2.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include "LqemuBackdoor.h"

//
// Target MMI handler GUID. Variable service (native): gEfiSmmVariableProtocolGuid
// ED32D533-99E6-4209-9CC0-2D72CDD998A7. Use this for the open-source stand.
//
// Coverage-test target: BackdoorMm handler GUID (256-way switch on payload[0]).
STATIC CONST EFI_GUID  mTargetGuid = {
  0xA5E7B1C4, 0x9D3F, 0x4E8A, { 0xB6, 0xC2, 0x1F, 0x0D, 0x7A, 0x2E, 0x5C, 0x83 }
};

#define MM_HDR_SIZE   (OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data))
#define FUZZ_PAYLOAD  0x1000
#define FUZZ_BUF_SIZE (MM_HDR_SIZE + FUZZ_PAYLOAD)

EFI_STATUS EFIAPI
UefiMain (IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
  EFI_STATUS Status;
  EFI_MM_COMMUNICATION2_PROTOCOL *MmComm;
  EFI_MM_COMMUNICATE_HEADER *Hdr;
  UINT8 *Buf, *Payload;
  UINTN CommSize;

  Print (L"MMFH-LQ: === variable fuzz harness (LibAFL protocol) ===\n");
  
  Status = gBS->LocateProtocol (&gEfiMmCommunication2ProtocolGuid, NULL, (VOID **)&MmComm);
  
  if (EFI_ERROR (Status)) { 
	  Print (L"MMFH-LQ: [FAIL] %r\n", Status); return Status;
  }
  
  Buf = AllocateZeroPool (FUZZ_BUF_SIZE);
  
  if (Buf == NULL) 
	  return EFI_OUT_OF_RESOURCES;
  Hdr = (EFI_MM_COMMUNICATE_HEADER *)Buf;
  CopyGuid (&Hdr->HeaderGuid, &mTargetGuid);
  Hdr->MessageLength = FUZZ_PAYLOAD;
  Payload  = Buf + MM_HDR_SIZE;
  CommSize = FUZZ_BUF_SIZE;
  
  Print (L"MMFH-LQ: payload=0x%lx cap=0x%x - handing off\n",
         (UINT64)(UINTN)Payload, (UINT32)FUZZ_PAYLOAD);
  
  LqemuCall (LIBAFL_QEMU_COMMAND_START_VIRT, (UINTN)Payload, (UINTN)FUZZ_PAYLOAD);
  Status = MmComm->Communicate (MmComm, Buf, Buf, &CommSize);
  LqemuCall (LIBAFL_QEMU_COMMAND_END, LIBAFL_QEMU_END_OK, (UINTN)Status);
  CpuDeadLoop ();
  
  return EFI_SUCCESS;
}
