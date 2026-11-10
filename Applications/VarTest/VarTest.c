/** @file
  VarTest - the simplest possible NS-world client of the UEFI variable service.

  It just calls the architectural Runtime Services:

    gRT->SetVariable (...)   // write a variable
    gRT->GetVariable (...)   // read it back and compare

  On this stand gRT->SetVariable/GetVariable are provided by
  VariableSmmRuntimeDxe, which packs the request into an
  EFI_MM_COMMUNICATE_HEADER and issues SMC MM_COMMUNICATE (TF-A SPM_MM) to the
  StandaloneMM variable handler. So this tiny app exercises the whole
  NS -> MM variable path without touching any MM buffer by hand.

  Output lines are prefixed with "VARTEST:" so they can be grepped from the
  NS UART log. The final verdict is "VARTEST: === RESULT: PASS/FAIL ===".

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#define VAR_NAME  L"VarTestHello"

//
// Private vendor GUID that namespaces our variable.
//
STATIC EFI_GUID  mVarGuid = {
  0x6a1f2b3c, 0x8d4e, 0x4f5a, { 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28 }
};

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  CHAR8       WriteData[] = "Hello, StandaloneMM variable service!";
  UINT32      Attributes  = EFI_VARIABLE_NON_VOLATILE |
                            EFI_VARIABLE_BOOTSERVICE_ACCESS |
                            EFI_VARIABLE_RUNTIME_ACCESS;
  UINT8       ReadData[128];
  UINTN       ReadSize;
  UINT32      ReadAttr;

  Print (L"VARTEST: === simple variable service test ===\n");

  //
  // 1. Write the variable.
  //
  Print (
    L"VARTEST: SetVariable '%s' = \"%a\" (%u bytes)\n",
    VAR_NAME,
    WriteData,
    (UINT32)sizeof (WriteData)
    );
  Status = gRT->SetVariable (
                  VAR_NAME,
                  &mVarGuid,
                  Attributes,
                  sizeof (WriteData),
                  WriteData
                  );
  Print (L"VARTEST: SetVariable -> %r\n", Status);
  if (EFI_ERROR (Status)) {
    Print (L"VARTEST: === RESULT: FAIL (set) ===\n");
    return Status;
  }

  //
  // 2. Read it back.
  //
  ZeroMem (ReadData, sizeof (ReadData));
  ReadSize = sizeof (ReadData);
  ReadAttr = 0;
  Status   = gRT->GetVariable (
                    VAR_NAME,
                    &mVarGuid,
                    &ReadAttr,
                    &ReadSize,
                    ReadData
                    );
  Print (
    L"VARTEST: GetVariable -> %r (size=%u attr=0x%x)\n",
    Status,
    (UINT32)ReadSize,
    ReadAttr
    );
  if (EFI_ERROR (Status)) {
    Print (L"VARTEST: === RESULT: FAIL (get) ===\n");
    return Status;
  }

  Print (L"VARTEST: read back = \"%a\"\n", (CHAR8 *)ReadData);

  //
  // 3. Compare.
  //
  if ((ReadSize == sizeof (WriteData)) &&
      (ReadAttr == Attributes) &&
      (CompareMem (ReadData, WriteData, sizeof (WriteData)) == 0))
  {
    Print (L"VARTEST: === RESULT: PASS ===\n");
    return EFI_SUCCESS;
  }

  Print (L"VARTEST: === RESULT: FAIL (mismatch) ===\n");
  return EFI_DEVICE_ERROR;
}
