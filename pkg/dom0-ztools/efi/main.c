// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
#include <efi.h>
#include <efilib.h>

#define SEC_TO_USEC(value)                  ((value) * 1000 * 1000)
#define SMBIOS_INSTANCE_FROM_THIS(this)     CR(this, SMBIOS_INSTANCE, Smbios, SMBIOS_INSTANCE_SIGNATURE)
#define SMBIOS_ENTRY_FROM_LINK(link)        CR(link, EFI_SMBIOS_ENTRY, Link, EFI_SMBIOS_ENTRY_SIGNATURE)
#define SMBIOS_INSTANCE_SIGNATURE           SIGNATURE_32('S', 'B', 'i', 's')

#define EFI_SMBIOS_RECORD_HEADER_VERSION    0x0100
#define SMBIOS_HANDLE_PI_RESERVED           0xFFFE
#define SMBIOS_TYPE_OEM_STRINGS             11

#define VarLastTriedBootIndex               L"LastTriedBootIndex"
#define VarPlatformConfig                   L"PlatformConfig"
#define CONFIG_DELIMITER                    L':'
#define EVE_FML_RESOUTION                   L"eve.fml.resolution:*"
#define EVE_TRY_ALL_BOOT                    L"eve.try.all.boot.options:*"

EFI_GUID gOvmfPlatformConfigGuid =
    {0x7235c51c, 0x0c80, 0x4cab, {0x87, 0xac, 0x3b, 0x08, 0x4a, 0x63, 0x04, 0xb1}};

EFI_GUID gEfiShellParametersProtocolGuid =
    {0x752f3136, 0x4e16, 0x4fdc, {0xa2, 0x2a, 0xe5, 0xf4, 0x68, 0x12, 0xf4, 0xca}};

EFI_GUID gEfiSmbiosProtocolGuid =
    {0x3583ff6, 0xcb36, 0x4940, {0x94, 0x7e, 0xb9, 0xb3, 0x9f, 0x4a, 0xfa, 0xf7}};

//
// Randmyly generated GUID, rolled a dice!
//
EFI_GUID gEfiCustomNextBootIndexGuid =
    {0xdeadbeef, 0x9abc, 0xdef0, {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}};

UINT16 *gBootOrder;
UINTN gBootOrderSize;

typedef enum
{
  EfiLockUninitialized = 0,
  EfiLockReleased = 1,
  EfiLockAcquired = 2
} EFI_LOCK_STATE;

typedef struct
{
  UINT32 HorizontalResolution;
  UINT32 VerticalResolution;
} PLATFORM_CONFIG;

typedef struct
{
  EFI_TPL Tpl;
  EFI_TPL OwnerTpl;
  EFI_LOCK_STATE Lock;
} EFI_LOCK;

typedef struct EFI_SMBIOS_PROTOCOL
{
  VOID *Add;
  VOID *UpdateString;
  VOID *Remove;
  VOID *GetNext;
  UINT8 MajorVersion;
  UINT8 MinorVersion;
} EFI_SMBIOS_PROTOCOL;

typedef struct
{
  UINT32 Signature;
  EFI_HANDLE Handle;
  EFI_SMBIOS_PROTOCOL Smbios;
  EFI_LOCK DataLock;
  LIST_ENTRY DataListHead;
  LIST_ENTRY AllocatedHandleListHead;
} SMBIOS_INSTANCE;

typedef struct
{
  UINT16 Version;
  UINT16 HeaderSize;
  UINTN RecordSize;
  EFI_HANDLE ProducerHandle;
  UINTN NumberOfStrings;
} EFI_SMBIOS_RECORD_HEADER;

typedef struct
{
  UINT32 Signature;
  LIST_ENTRY Link;
  EFI_SMBIOS_RECORD_HEADER *RecordHeader;
  UINTN RecordSize;
  BOOLEAN Smbios32BitTable;
  BOOLEAN Smbios64BitTable;
} EFI_SMBIOS_ENTRY;

typedef struct
{
  UINT8 Type;
  UINT8 Length;
  UINT16 Handle;
} SMBIOS_STRUCTURE;

typedef struct
{
  SMBIOS_STRUCTURE Hdr;
  UINT8 StringCount;
} SMBIOS_TABLE_TYPE11;

typedef UINT8 EFI_SMBIOS_TYPE;
typedef UINT16 EFI_SMBIOS_HANDLE;
typedef SMBIOS_STRUCTURE EFI_SMBIOS_TABLE_HEADER;

CHAR16 *
StrSplit(
    CHAR16 *Str,
    CHAR16 Delim)
{
  CHAR16 *StrPtr;

  StrPtr = Str;
  if (StrPtr == NULL)
    return NULL;

  while (*StrPtr != L'\0')
  {
    if ((CHAR16)(*StrPtr) == Delim)
      return StrPtr + 1;

    StrPtr++;
  }

  return NULL;
}

EFI_STATUS
SetPlatformResolutions(
    IN PLATFORM_CONFIG *PlatformConfig)
{
  EFI_STATUS Status;
  EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
  UINTN SizeOfInfo, NumModes, ModeNum;

  Status = uefi_call_wrapper(BS->LocateProtocol,
                             3,
                             &GraphicsOutputProtocol,
                             NULL,
                             (VOID **)&GraphicsOutput);
  if (EFI_ERROR(Status))
    return Status;

  NumModes = GraphicsOutput->Mode->MaxMode;
  for (ModeNum = 0; ModeNum < NumModes; ModeNum++)
  {
    Status = uefi_call_wrapper(GraphicsOutput->QueryMode,
                               4,
                               GraphicsOutput,
                               ModeNum,
                               &SizeOfInfo,
                               &Info);
    if (EFI_ERROR(Status))
      continue;

    //
    // Make sure the provided resolution is one of the supported ones,
    // before setting it.
    //
    if (PlatformConfig->HorizontalResolution == Info->HorizontalResolution &&
        PlatformConfig->VerticalResolution == Info->VerticalResolution)
    {
      Status = uefi_call_wrapper(
          RT->SetVariable,
          5,
          VarPlatformConfig,
          &gOvmfPlatformConfigGuid,
          EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
          sizeof *PlatformConfig,
          PlatformConfig);
      if (EFI_ERROR(Status))
        return Status;

      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

EFI_STATUS
SetNextBootOption(
    IN UINT16 BootOptionNumber)
{
  EFI_STATUS Status;

  Status = uefi_call_wrapper(
      RT->SetVariable,
      5,
      VarBootNext,
      &gEfiGlobalVariableGuid,
      EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
      sizeof(BootOptionNumber),
      &BootOptionNumber);
  if (EFI_ERROR(Status))
    return Status;

  return EFI_SUCCESS;
}

EFI_STATUS
ResetSystem(
    EFI_RESET_TYPE ResetType)
{
  EFI_STATUS Status;

  Status = uefi_call_wrapper(
      RT->ResetSystem,
      4,
      ResetType,
      EFI_SUCCESS,
      0,
      NULL);
  if (EFI_ERROR(Status))
    return Status;

  //
  // We should never reach here.
  //
  return EFI_SUCCESS;
}

EFI_STATUS
Sleep(
    UINTN Seconds)
{
  return uefi_call_wrapper(BS->Stall, 1, SEC_TO_USEC(Seconds));
}

EFI_STATUS
GetBootOrder(
    VOID)
{
  EFI_STATUS Status;

  gBootOrderSize = 0;
  Status = uefi_call_wrapper(
      RT->GetVariable,
      5,
      VarBootOrder,
      &gEfiGlobalVariableGuid,
      NULL,
      &gBootOrderSize,
      NULL);
  if (Status != EFI_BUFFER_TOO_SMALL)
    return Status;

  gBootOrder = AllocateZeroPool(gBootOrderSize);
  if (!gBootOrder)
    return EFI_OUT_OF_RESOURCES;

  Status = uefi_call_wrapper(
      RT->GetVariable,
      5,
      VarBootOrder,
      &gEfiGlobalVariableGuid,
      NULL,
      &gBootOrderSize,
      gBootOrder);
  if (EFI_ERROR(Status))
  {
    FreePool(gBootOrder);
    return Status;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
IsValidBootOption(
    UINT16 BootCurrent,
    BOOLEAN *IsValid)
{
  EFI_STATUS Status;
  UINTN Size = 0;
  UINT8 *Data = NULL;
  UINT8 *DataPtr = NULL;
  CHAR16 *Description;
  CHAR16 BootOptionName[32];
  *IsValid = TRUE;

  UnicodeSPrint(BootOptionName,
                sizeof(BootOptionName) / sizeof(CHAR16),
                L"Boot%04x",
                BootCurrent);

  Status = uefi_call_wrapper(
      RT->GetVariable,
      5,
      BootOptionName,
      &gEfiGlobalVariableGuid,
      NULL,
      &Size,
      NULL);
  if (Status != EFI_BUFFER_TOO_SMALL)
    return Status;

  Data = AllocateZeroPool(Size);
  if (!Data)
    return EFI_OUT_OF_RESOURCES;

  Status = uefi_call_wrapper(
      RT->GetVariable,
      5,
      BootOptionName,
      &gEfiGlobalVariableGuid,
      NULL,
      &Size,
      Data);
  if (EFI_ERROR(Status))
  {
    FreePool(Data);
    return Status;
  }

  //
  // Skip the attribute and pathsize and get to the description.
  //
  DataPtr = Data;
  DataPtr += sizeof(UINT32) + sizeof(UINT16);
  Description = (CHAR16 *)DataPtr;

  //
  // UiApp or HTTP or PXE are not valid boot options.
  //
  if (MetaiMatch(Description, L"*UiApp*") ||
      MetaiMatch(Description, L"*HTTP*") ||
      MetaiMatch(Description, L"*PXE*"))
    *IsValid = FALSE;

  FreePool(Data);
  return EFI_SUCCESS;
}

EFI_STATUS
GetLastTriedBootOption(
    UINT16 *LastTriedBootOption)
{
  UINTN Size = sizeof(UINT16);
  EFI_STATUS Status;

  Status = uefi_call_wrapper(
      RT->GetVariable,
      5,
      VarLastTriedBootIndex,
      &gEfiCustomNextBootIndexGuid,
      NULL,
      &Size,
      LastTriedBootOption);

  return Status;
}

EFI_STATUS
SetLastTriedBootOption(
    UINT16 LastTriedBootOption)
{
  UINTN Size = sizeof(UINT16);
  EFI_STATUS Status;

  Status = uefi_call_wrapper(
      RT->SetVariable,
      5,
      VarLastTriedBootIndex,
      &gEfiCustomNextBootIndexGuid,
      EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
      Size,
      &LastTriedBootOption);

  return Status;
}

EFI_STATUS
TryNextBoot(
    VOID)
{
  EFI_STATUS Status;
  UINT16 LastTriedBootOption, NextBoot = 0;
  BOOLEAN IsValid = FALSE;

  Status = GetLastTriedBootOption(&LastTriedBootOption);
  if (EFI_ERROR(Status))
  {
    if (Status != EFI_NOT_FOUND)
    {
      return Status;
    }
    else
    {
      //
      // Create and initialize the LastTriedBootIndex variable.
      //
      Status = SetLastTriedBootOption(0);
      if (EFI_ERROR(Status))
        return Status;
    }
  }

  for (UINTN i = LastTriedBootOption + 1; i < gBootOrderSize / sizeof(UINT16); i++)
  {
    Status = IsValidBootOption(gBootOrder[i], &IsValid);
    if (EFI_ERROR(Status))
      return Status;

    if (IsValid)
    {
      NextBoot = gBootOrder[i];
      LastTriedBootOption = i;
      break;
    }
  }

  //
  // No valid boot option left to try.
  //
  if (!IsValid)
    return EFI_NOT_FOUND;

  Status = SetNextBootOption(NextBoot);
  if (EFI_ERROR(Status))
    return Status;

  // TOOD: Debug remove
  DbgPrint(D_ERROR, (CHAR8 *)"===== Booting to : %d\n", NextBoot);

  Status = SetLastTriedBootOption(LastTriedBootOption);
  return Status;
}


//
// Calling smbios->GetNext() results in either crash or hang,
// so this one is more or less copy-pasted from EDKII's GetNext.
//
EFI_STATUS
SmbiosGetNext(
    CONST EFI_SMBIOS_PROTOCOL *This,
    OUT EFI_SMBIOS_HANDLE *SmbiosHandle,
    EFI_SMBIOS_TABLE_HEADER **Record)
{
  BOOLEAN StartPointFound;
  LIST_ENTRY *Link;
  LIST_ENTRY *Head;
  SMBIOS_INSTANCE *Private;
  EFI_SMBIOS_ENTRY *SmbiosEntry;
  EFI_SMBIOS_TABLE_HEADER *SmbiosTableHeader;

  if (SmbiosHandle == NULL)
    return EFI_INVALID_PARAMETER;

  StartPointFound = FALSE;
  Private = SMBIOS_INSTANCE_FROM_THIS(This);
  Head = &Private->DataListHead;
  for (Link = Head->Flink; Link != Head; Link = Link->Flink)
  {
    SmbiosEntry = SMBIOS_ENTRY_FROM_LINK(Link);
    SmbiosTableHeader = (EFI_SMBIOS_TABLE_HEADER *)(SmbiosEntry->RecordHeader + 1);

    //
    // If SmbiosHandle is 0xFFFE, the first matched SMBIOS record handle will be returned
    //
    if (*SmbiosHandle == SMBIOS_HANDLE_PI_RESERVED)
    {
      *SmbiosHandle = SmbiosTableHeader->Handle;
      *Record = SmbiosTableHeader;
      return EFI_SUCCESS;
    }

    //
    // Start this round search from the next SMBIOS handle
    //
    if (!StartPointFound && (*SmbiosHandle == SmbiosTableHeader->Handle))
    {
      StartPointFound = TRUE;
      continue;
    }

    if (StartPointFound)
    {
      *SmbiosHandle = SmbiosTableHeader->Handle;
      *Record = SmbiosTableHeader;
      return EFI_SUCCESS;
    }
  }

  *SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  return EFI_NOT_FOUND;
}

CHAR8 *
GetSmbiosString(
    SMBIOS_TABLE_TYPE11 *Record,
    UINT8 Index)
{
  //
  // The string arrays starts after the SMBIOS_TABLE_TYPE11 structure and
  // strings are placed one after another with a NULL terminator, so we
  // start by getting the first one and then move to the next one.
  //
  CHAR8 *StringArea = (CHAR8 *)(&Record->StringCount) + sizeof(Record->StringCount);
  for (UINT8 i = 0; i < Index; i++)
    StringArea += strlena(StringArea) + 1;

  return StringArea;
}

EFI_STATUS
GetSmbiosConfigString(
    CHAR16 *ConfigName,
    CHAR16 **ConfigValue)
{
  EFI_STATUS Status;
  EFI_SMBIOS_PROTOCOL *Smbios;
  SMBIOS_STRUCTURE *Record;
  SMBIOS_TABLE_TYPE11 *Type11Record;
  UINT16 Handle;
  *ConfigValue = NULL;

  Status = uefi_call_wrapper(BS->LocateProtocol,
                             3,
                             &gEfiSmbiosProtocolGuid,
                             NULL,
                             (VOID **)&Smbios);
  if (EFI_ERROR(Status))
    return Status;

  Handle = SMBIOS_HANDLE_PI_RESERVED;
  while (SmbiosGetNext(Smbios, &Handle, &Record) != EFI_NOT_FOUND)
  {
    //
    // We are only interested in OEM Strings.
    //
    if (Record->Type != SMBIOS_TYPE_OEM_STRINGS)
      continue;

    //
    // Interpret Record as SMBIOS_TABLE_TYPE11, we can still access the
    // SMBIOS_STRUCTURE as it is part of the SMBIOS_TABLE_TYPE11.
    //
    Type11Record = (SMBIOS_TABLE_TYPE11 *)Record;
    for (UINT8 i = 0; i < Type11Record->StringCount; i++)
    {
      CHAR8 *AsciiOemString = GetSmbiosString(Type11Record, i);
      CHAR16 *UnicodeOemString = PoolPrint(L"%a", AsciiOemString);
      if (MetaiMatch(UnicodeOemString, ConfigName))
      {
        *ConfigValue = StrSplit(UnicodeOemString, CONFIG_DELIMITER);
        if (*ConfigValue != NULL)
          *ConfigValue = PoolPrint(L"%s", *ConfigValue);

        FreePool(UnicodeOemString);
        return (*ConfigValue != NULL) ? EFI_SUCCESS : EFI_NOT_FOUND;
      }

      FreePool(UnicodeOemString);
    }
  }

  return EFI_NOT_FOUND;
}

EFI_STATUS
GetResolutionConfig(
    UINT32 *HorizontalResolution,
    UINT32 *VerticalResolution)
{
  EFI_STATUS Status;
  CHAR16 *ConfigValue;
  CHAR16 *Horizontal;
  CHAR16 *Vertical;

  Status = GetSmbiosConfigString(EVE_FML_RESOUTION, &ConfigValue);
  if (EFI_ERROR(Status))
    return Status;

  Vertical = StrSplit(ConfigValue, L'x');
  if (Vertical == NULL)
  {
    Status = EFI_NOT_FOUND;
    goto _Return;
  }
  *VerticalResolution = Atoi(Vertical);

  ConfigValue[Vertical - ConfigValue - 1] = L'\0';
  Horizontal = ConfigValue;
  if (*Horizontal == L'\0')
  {
    Status = EFI_NOT_FOUND;
    goto _Return;
  }
  *HorizontalResolution = Atoi(ConfigValue);

_Return:
  FreePool(ConfigValue);
  return EFI_SUCCESS;
}

EFI_STATUS
GetBootConfig(
    BOOLEAN *TryBootOptios)
{
  EFI_STATUS Status;
  CHAR16 *ConfigValue;
  *TryBootOptios = FALSE;

  Status = GetSmbiosConfigString(EVE_TRY_ALL_BOOT, &ConfigValue);
  if (EFI_ERROR(Status))
    return Status;

  if (StriCmp(ConfigValue, L"true") == 0)
    *TryBootOptios = TRUE;

  FreePool(ConfigValue);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
efi_main(
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_STATUS Status;
  PLATFORM_CONFIG PlatformConfig = {0};
  BOOLEAN TryAllBootOptions = FALSE;

  InitializeLib(ImageHandle, SystemTable);

  //
  // If config is present, set the resolution.
  //
  Status = GetResolutionConfig(
    &PlatformConfig.HorizontalResolution,
    &PlatformConfig.VerticalResolution);
  if (!EFI_ERROR(Status))
  {
    Status = SetPlatformResolutions(&PlatformConfig);
    if (EFI_ERROR(Status))
    {
      DbgPrint(D_ERROR, (CHAR8 *)"Error: Unable to set resolutions, Status : %r\n", Status);

      //
      // shutdown the system to avoid booting to a wrong resolution and signal
      // the usser that something went wrong.
      //
      ResetSystem(EfiResetShutdown);
    }
  }

  Status = GetBootConfig(&TryAllBootOptions);
  if (!EFI_ERROR(Status))
  {
    //
    // If the boot-brute-force is not enabled, we are done here.
    //
    if (!TryAllBootOptions)
      return EFI_SUCCESS;

    Status = GetBootOrder();
    if (EFI_ERROR(Status))
    {
      DbgPrint(D_ERROR, (CHAR8 *)"Error: Unable to save BootOrder, Status : %r\n", Status);
      ResetSystem(EfiResetShutdown);
    }

    Status = TryNextBoot();
    if (EFI_ERROR(Status))
    {
      DbgPrint(D_ERROR, (CHAR8 *)"Error: Unable to set next boot, Status : %r\n", Status);

      //
      // We have tried all the boot options and none booted successfully,
      // we are going to shutdown the system, so reset the LastTriedBootIndex
      // to give the next explicit power on a chance to try again.
      //
      SetLastTriedBootOption(0);
      ResetSystem(EfiResetShutdown);
    }

    //
    // Trigger a reset to apply BootNext
    //
    ResetSystem(EfiResetCold);
  }

  return EFI_SUCCESS;
}