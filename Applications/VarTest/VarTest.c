/** @file
  VarTest - NS-world variable test that talks to StandaloneMM via a RAW
  MM_COMMUNICATE (EFI_MM_COMMUNICATION2_PROTOCOL.Communicate), building the
  EFI_MM_COMMUNICATE_HEADER (v1) + SMM_VARIABLE_COMMUNICATE_* payload by hand.

  Why raw instead of gRT->SetVariable/GetVariable: the runtime path goes through
  VariableSmmRuntimeDxe, which uses its own fixed/padded comm buffer and a v3
  header (BufferSize = capacity), so WE don't control the size. Here we set the
  v1 MessageLength ourselves, so the secure CPU driver allocates exactly
  MessageLength + sizeof(EFI_MM_COMMUNICATE_HEADER) - full control over the size.

  Output lines are prefixed "VARTEST:".

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Protocol/MmCommunication2.h>
#include <Protocol/SmmVariable.h>
#include <Guid/SmmVariableCommon.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#define BUF_SIZE      0x1000
#define MM_HDR_SIZE   (OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data))
#define VAR_HDR_SIZE  (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_HEADER, Data))
#define ACCESS_HDR    (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name))

STATIC CONST CHAR16   mVarName[] = L"VarTestHello";
STATIC CONST EFI_GUID mVendorGuid = {
  0x6a1f2b3c, 0x8d4e, 0x4f5a, { 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28 }
};

STATIC EFI_MM_COMMUNICATION2_PROTOCOL  *mMmComm;
STATIC UINT8                           *mBuf;

/**
  Build a v1 MM header routed to the variable handler and send one
  Communicate(). VarPayloadSize = bytes after SMM_VARIABLE_COMMUNICATE_HEADER
  (i.e. the ACCESS_VARIABLE + name + data). We set
  MessageLength = VAR_HDR_SIZE + VarPayloadSize, so the secure per-call alloc is
  exactly MessageLength + MM_HDR_SIZE - entirely under our control.
**/
STATIC
EFI_STATUS
SendVar (
  IN  UINTN       Function,
  IN  UINTN       VarPayloadSize,
  OUT EFI_STATUS  *RetStatus
  )
{
  EFI_MM_COMMUNICATE_HEADER        *Hdr;
  SMM_VARIABLE_COMMUNICATE_HEADER  *VarHdr;
  UINTN                            MsgLen;
  UINTN                            CommSize;
  EFI_STATUS                       Status;

  MsgLen = VAR_HDR_SIZE + VarPayloadSize;

  Hdr = (EFI_MM_COMMUNICATE_HEADER *)mBuf;
  CopyGuid (&Hdr->HeaderGuid, &gEfiSmmVariableProtocolGuid);
  Hdr->MessageLength = MsgLen;

  VarHdr               = (SMM_VARIABLE_COMMUNICATE_HEADER *)(mBuf + MM_HDR_SIZE);
  VarHdr->Function     = Function;
  VarHdr->ReturnStatus = (EFI_STATUS)-1;

  CommSize = MM_HDR_SIZE + MsgLen;

  Print (
    L"VARTEST: -> Function=%lu MessageLength=%lu  (secure alloc = %lu)\n",
    (UINT64)Function,
    (UINT64)MsgLen,
    (UINT64)(MsgLen + MM_HDR_SIZE)
    );

  Status     = mMmComm->Communicate (mMmComm, mBuf, mBuf, &CommSize);
  *RetStatus = VarHdr->ReturnStatus;
  return Status;
}

/**
  Fill SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE at the payload area and return
  the VarPayloadSize (ACCESS header + name + reserved data buffer).
**/
STATIC
UINTN
BuildAccess (
  IN UINT32      Attributes,
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  IN UINTN       DataBufCap
  )
{
  SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE  *Acc;
  UINTN                                     NameSize;

  NameSize = sizeof (mVarName);  // includes trailing L'\0'
  Acc      = (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE *)(mBuf + MM_HDR_SIZE + VAR_HDR_SIZE);

  CopyGuid (&Acc->Guid, &mVendorGuid);
  Acc->NameSize   = NameSize;
  Acc->DataSize   = DataBufCap;
  Acc->Attributes = Attributes;
  CopyMem (Acc->Name, mVarName, NameSize);
  if ((Data != NULL) && (DataSize != 0)) {
    CopyMem ((UINT8 *)Acc->Name + NameSize, Data, DataSize);
  }

  return ACCESS_HDR + NameSize + DataBufCap;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                                Status;
  EFI_STATUS                                Ret;
  CHAR8                                     WriteData[] = "Hello, raw MM_COMMUNICATE!";
  UINT32                                    Attr;
  UINTN                                     PayloadSize;
  SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE  *Acc;

  Attr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;

  Print (L"VARTEST: === raw MM_COMMUNICATE variable test ===\n");

  Status = gBS->LocateProtocol (&gEfiMmCommunication2ProtocolGuid, NULL, (VOID **)&mMmComm);
  if (EFI_ERROR (Status)) {
    Print (L"VARTEST: [FAIL] MmCommunication2 not found: %r\n", Status);
    return Status;
  }

  mBuf = AllocateZeroPool (BUF_SIZE);
  if (mBuf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // 1. SET_VARIABLE
  //
  ZeroMem (mBuf, BUF_SIZE);
  PayloadSize = BuildAccess (Attr, WriteData, sizeof (WriteData), sizeof (WriteData));
  Status      = SendVar (SMM_VARIABLE_FUNCTION_SET_VARIABLE, PayloadSize, &Ret);
  Print (L"VARTEST: SET  comm=%r ret=%r\n", Status, Ret);

  //
  // 2. GET_VARIABLE (reserve 256 bytes for output data)
  //
  ZeroMem (mBuf, BUF_SIZE);
  PayloadSize = BuildAccess (0, NULL, 0, 256);
  Status      = SendVar (SMM_VARIABLE_FUNCTION_GET_VARIABLE, PayloadSize, &Ret);
  Acc         = (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE *)(mBuf + MM_HDR_SIZE + VAR_HDR_SIZE);
  Print (L"VARTEST: GET  comm=%r ret=%r DataSize=%lu\n", Status, Ret, (UINT64)Acc->DataSize);
  if (!EFI_ERROR (Status) && (Ret == EFI_SUCCESS)) {
    Print (L"VARTEST: value = \"%a\"\n", (CHAR8 *)((UINT8 *)Acc->Name + Acc->NameSize));
  }

  Print (L"VARTEST: === done ===\n");
  return EFI_SUCCESS;
}
