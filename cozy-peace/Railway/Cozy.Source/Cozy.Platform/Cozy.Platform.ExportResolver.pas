unit Cozy.Platform.ExportResolver;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$IFNDEF MSWINDOWS}
  {$MESSAGE FATAL 'Cozy.Platform.ExportResolver requires Windows.'}
{$ENDIF}
{$IFNDEF CPUX64}
  {$MESSAGE FATAL 'Cozy.Platform.ExportResolver requires the Delphi x64 compiler.'}
{$ENDIF}
{$ALIGN 8}
{$B-}
{$POINTERMATH ON}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Platform,

  Winapi.Windows, System.SysUtils;

{ Current-process, loaded-image helpers. GetModuleBase64 returns a borrowed
  address: callers must keep the DLL loaded and must not race FreeLibrary.
  This is an experimental PEB reader, not a stable Windows loader contract. }
function GetPEB64: Pointer;
function GetModuleBase64(const ModuleName: string): Pointer;
function GetProcAddress64(ModuleBase: Pointer;
  const ProcName: AnsiString): Pointer;

{ Used only during initialization of the EXE's API binding units.
  Holds one loader reference per DLL until process exit. Loads from System32;
  normal named exports use the PE parser, forwarded exports use the OS loader.
  Named compatibility path; no DLL unlinking, hooking, or import-table patching. }
function RequireProcAddress64(const ModuleName: string;
  const ProcName: AnsiString): Pointer;

{ Retain the actual export target module, including forwarded exports, until
  process exit. Intended for the post-binding startup contract gate. }
procedure RetainApiTargetModule(Address: Pointer);
function OptionalSystemProcAddressHash64(const ModuleName: string;
  ProcHash: Cardinal): Pointer;

{ ROR13 INTERFACE BEGIN }
{ Numeric lookup used by the application API binding units. Name-based
  entry points above remain available for compatibility and test comparison. }
function GetProcAddressHash64(ModuleBase: Pointer; ProcHash: Cardinal): Pointer;
function RequireProcAddressHash64(const ModuleName: string;
  ProcHash: Cardinal): Pointer;
{ ROR13 INTERFACE END }

implementation

{ ROR13 USES BEGIN }
uses
  Cozy.Api.ROR13, Cozy.Api.Pointer;
{ ROR13 USES END }

{ DYNAMIC LOADER TYPES BEGIN }
{ ABI declarations only; these are not external imports. Winapi.Windows is
  retained for types/constants. RTL imports are outside this unit's scope. }
type
  TPEBGetProcAddress = function(hModule: HMODULE;
    lpProcName: PAnsiChar): Pointer; stdcall;
  TPEBGetModuleHandleExW = function(dwFlags: DWORD; lpModuleName: PWideChar;
    var phModule: HMODULE): BOOL; stdcall;
  TPEBGetSystemDirectoryW = function(lpBuffer: PWideChar;
    uSize: UINT): UINT; stdcall;
  TPEBLoadLibraryExW = function(lpLibFileName: PWideChar; hFile: THandle;
    dwFlags: DWORD): HMODULE; stdcall;
  TPEBFreeLibrary = function(hLibModule: HMODULE): BOOL; stdcall;
  TPEBForwarderPolicy = (fpRegisteredModule, fpBootstrapCore, fpDirectExportOnly);
{ DYNAMIC LOADER TYPES END }

type
  PPEBListEntry = ^TPEBListEntry;
  TPEBListEntry = record
    Flink, Blink: PPEBListEntry;
  end;
  TPEBUnicodeString = record
    Length, MaximumLength: Word;
    Buffer: PWideChar;
  end;
  { Public Windows SDK winternl.h prefixes only. The trailing private loader
    fields are deliberately not read. Reserved bytes are never interpreted. }
  PPEBPrefix64 = ^TPEBPrefix64;
  TPEBPrefix64 = record
    ReservedHeader: array[0..3] of Byte;
    ReservedPointers: array[0..1] of Pointer;
    Ldr: Pointer;
  end;
  PPEBLdrDataPrefix64 = ^TPEBLdrDataPrefix64;
  TPEBLdrDataPrefix64 = record
    ReservedHeader: array[0..7] of Byte;
    ReservedPointers: array[0..2] of Pointer;
    InMemoryOrderModuleList: TPEBListEntry;
  end;
  PPEBLdrEntry = ^TPEBLdrEntry;
  TPEBLdrEntry = record
    Reserved1: array[0..1] of Pointer;
    InMemoryOrderLinks: TPEBListEntry;
    Reserved2: array[0..1] of Pointer;
    DllBase: Pointer;
    Reserved3: array[0..1] of Pointer;
    FullDllName: TPEBUnicodeString;
  end;
  PExportDirectory64 = ^TExportDirectory64;
  TExportDirectory64 = packed record
    Characteristics, TimeDateStamp: Cardinal;
    MajorVersion, MinorVersion: Word;
    NameRVA, OrdinalBase, NumberOfFunctions, NumberOfNames: Cardinal;
    AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals: Cardinal;
  end;
  TLoadedSystemModule = record
    Name: string;
    Handle: HMODULE;
  end;

var
{ DYNAMIC LOADER VARS BEGIN }
  ApiSlot_PEBGetProcAddress: TEncodedApiPointer;
  ApiSlot_PEBGetModuleHandleExW: TEncodedApiPointer;
  ApiSlot_PEBGetSystemDirectoryW: TEncodedApiPointer;
  ApiSlot_PEBLoadLibraryExW: TEncodedApiPointer;
  ApiSlot_PEBFreeLibrary: TEncodedApiPointer;
  BootstrapGetProcAddress: TPEBGetProcAddress;
  LoaderSlotsReady: Boolean;
{ DYNAMIC LOADER VARS END }
  ModuleLock: TObject;
  LoadedModules: array of TLoadedSystemModule;

{ POINTER LOADER WRAPPERS BEGIN }
function PEBGetProcAddress(hModule: HMODULE;
    lpProcName: PAnsiChar): Pointer; stdcall;
var
  ApiTarget: TPEBGetProcAddress;
begin
  ApiTarget := TPEBGetProcAddress(DecodeApiPointer(ApiSlot_PEBGetProcAddress));
  Result := ApiTarget(hModule, lpProcName);
end;

function PEBGetModuleHandleExW(dwFlags: DWORD; lpModuleName: PWideChar;
    var phModule: HMODULE): BOOL; stdcall;
var
  ApiTarget: TPEBGetModuleHandleExW;
begin
  ApiTarget := TPEBGetModuleHandleExW(DecodeApiPointer(ApiSlot_PEBGetModuleHandleExW));
  Result := ApiTarget(dwFlags, lpModuleName, phModule);
end;

function PEBGetSystemDirectoryW(lpBuffer: PWideChar;
    uSize: UINT): UINT; stdcall;
var
  ApiTarget: TPEBGetSystemDirectoryW;
begin
  ApiTarget := TPEBGetSystemDirectoryW(DecodeApiPointer(ApiSlot_PEBGetSystemDirectoryW));
  Result := ApiTarget(lpBuffer, uSize);
end;

function PEBLoadLibraryExW(lpLibFileName: PWideChar; hFile: THandle;
    dwFlags: DWORD): HMODULE; stdcall;
var
  ApiTarget: TPEBLoadLibraryExW;
begin
  ApiTarget := TPEBLoadLibraryExW(DecodeApiPointer(ApiSlot_PEBLoadLibraryExW));
  Result := ApiTarget(lpLibFileName, hFile, dwFlags);
end;

function PEBFreeLibrary(hLibModule: HMODULE): BOOL; stdcall;
var
  ApiTarget: TPEBFreeLibrary;
begin
  ApiTarget := TPEBFreeLibrary(DecodeApiPointer(ApiSlot_PEBFreeLibrary));
  Result := ApiTarget(hLibModule);
end;
{ POINTER LOADER WRAPPERS END }

function GetPEB64: Pointer;
asm
  mov rax, gs:[60h]
end;

function PEBBootstrapLayoutValid: Boolean;
var PEB: TPEBPrefix64; Ldr: TPEBLdrDataPrefix64; Entry: TPEBLdrEntry;
begin
  { Validate the compiler's actual Win64 packing before bootstrap reads. The
    independent SDK probe also asserts these public winternl.h offsets. }
  Result := (SizeOf(Pointer) = 8) and (SizeOf(TPEBListEntry) = 16) and
    (SizeOf(TPEBUnicodeString) = 16) and (SizeOf(TPEBPrefix64) = 32) and
    (SizeOf(TPEBLdrDataPrefix64) = 48) and (SizeOf(TPEBLdrEntry) = 88) and
    (NativeUInt(@PEB.Ldr) - NativeUInt(@PEB) = 24) and
    (NativeUInt(@Ldr.InMemoryOrderModuleList) - NativeUInt(@Ldr) = 32) and
    (NativeUInt(@Entry.InMemoryOrderLinks) - NativeUInt(@Entry) = 16) and
    (NativeUInt(@Entry.DllBase) - NativeUInt(@Entry) = 48) and
    (NativeUInt(@Entry.FullDllName) - NativeUInt(@Entry) = 72);
end;

function BootstrapSpan(Address: Pointer; Size: NativeUInt): Boolean;
begin
  { No loader APIs can be called before their own bindings exist. Arithmetic
    is checked here; inaccessible or concurrently unmapped memory is handled by
    the surrounding read-only SEH boundary, never interpreted as a detection. }
  Result := (Address <> nil) and (NativeUInt(Address) >= $10000) and
    (Size <> 0) and (Size - 1 <= High(NativeUInt) - NativeUInt(Address));
end;

function GetModuleBase64(const ModuleName: string): Pointer;
var
  PEB: PPEBPrefix64;
  Ldr: PPEBLdrDataPrefix64;
  ListHead, Node: PPEBListEntry;
  Entry: PPEBLdrEntry;
  CurrentName: string;
  Walked: Integer;
  EntryPrefix: TPEBLdrEntry;
  LinkOffset: NativeUInt;
begin
  Result := nil;
  if (ModuleName = '') or (Pos(#0, ModuleName) <> 0) or
    not PEBBootstrapLayoutValid then Exit;
  LinkOffset := NativeUInt(@EntryPrefix.InMemoryOrderLinks) - NativeUInt(@EntryPrefix);
  try
    PEB := PPEBPrefix64(GetPEB64);
    if not BootstrapSpan(PEB, SizeOf(TPEBPrefix64)) then Exit;
    Ldr := PPEBLdrDataPrefix64(PEB^.Ldr);
    if not BootstrapSpan(Ldr, SizeOf(TPEBLdrDataPrefix64)) then Exit;
    ListHead := @Ldr^.InMemoryOrderModuleList;
    Node := ListHead^.Flink;
    Walked := 0;
    while (Node <> nil) and (Node <> ListHead) and (Walked < 4096) do
    begin
      if not BootstrapSpan(Node, SizeOf(TPEBListEntry)) or
        (NativeUInt(Node) < LinkOffset) then Exit;
      Entry := PPEBLdrEntry(NativeUInt(Node) - LinkOffset);
      if not BootstrapSpan(Entry, SizeOf(TPEBLdrEntry)) then Exit;
      if (Entry^.FullDllName.Length > 0) and
        ((Entry^.FullDllName.Length and 1) = 0) and
        (Entry^.FullDllName.Length <= Entry^.FullDllName.MaximumLength) and
        BootstrapSpan(Entry^.FullDllName.Buffer, Entry^.FullDllName.Length) then
      begin
        SetString(CurrentName, Entry^.FullDllName.Buffer,
          Entry^.FullDllName.Length div SizeOf(WideChar));
        if SameText(ExtractFileName(CurrentName), ModuleName) and
          BootstrapSpan(Entry^.DllBase, $40) then
          Exit(Entry^.DllBase);
      end;
      Node := Node^.Flink;
      Inc(Walked);
    end;
  except
    on E: EAccessViolation do Result := nil;
  end;
end;

function ImageRange(ImageSize, RVA: Cardinal; Count: UInt64): Boolean;
begin
  Result := (RVA < ImageSize) and
    (Count <= UInt64(ImageSize) - UInt64(RVA));
end;

function EqualExportName(Base: PByte; ImageSize, NameRVA: Cardinal;
  const Expected: AnsiString): Boolean;
var
  I, Count: Integer;
  Name: PAnsiChar;
begin
  Result := False;
  Count := Length(Expected);
  if not ImageRange(ImageSize, NameRVA, UInt64(Count) + 1) then Exit;
  Name := PAnsiChar(Base + NameRVA);
  for I := 0 to Count - 1 do
    if Name[I] <> Expected[I + 1] then Exit;
  Result := Name[Count] = #0;
end;

function ResolveNamedExport(ModuleBase: Pointer;
  const ProcName: AnsiString): Pointer;
var
  Base, Nt, Optional: PByte;
  NtOffset: LongInt;
  OptionalSize: Word;
  ImageSize, ExportRVA, ExportSize: Cardinal;
  Directory: PExportDirectory64;
  I, NameRVA, FunctionRVA: Cardinal;
  FunctionIndex: Word;
  ForwarderEnd, Cursor: UInt64;
  RegisteredModule: HMODULE;
begin
  Result := nil;
  Base := PByte(ModuleBase);
  if not BootstrapSpan(Base, $40) then Exit;
  if PWord(Base)^ <> $5A4D then Exit;                      { MZ }
  NtOffset := PLongInt(Base + $3C)^;
  if (NtOffset < $40) or (NtOffset > $100000) then Exit;
  if NativeUInt(Base) > High(NativeUInt) - NativeUInt(NtOffset) - $100 then Exit;
  Nt := Base + NtOffset;
  if PCardinal(Nt)^ <> $00004550 then Exit;                { PE signature }
  if PWord(Nt + 4)^ <> $8664 then Exit;                    { AMD64 }
  OptionalSize := PWord(Nt + 20)^;
  if OptionalSize < 120 then Exit;
  Optional := Nt + 24;
  if PWord(Optional)^ <> $020B then Exit;                  { PE32+ }
  ImageSize := PCardinal(Optional + 56)^;
  if (ImageSize = 0) or
    (NativeUInt(Base) > High(NativeUInt) - NativeUInt(ImageSize)) then Exit;
  if not ImageRange(ImageSize, Cardinal(NtOffset),
    UInt64(24) + OptionalSize) then Exit;
  if PCardinal(Optional + 108)^ < 1 then Exit;             { directory count }
  ExportRVA := PCardinal(Optional + 112)^;
  ExportSize := PCardinal(Optional + 116)^;
  if (ExportRVA = 0) or (ExportSize < SizeOf(TExportDirectory64)) or
    not ImageRange(ImageSize, ExportRVA, ExportSize) then Exit;
  Directory := PExportDirectory64(Base + ExportRVA);
  if (Directory^.NumberOfNames = 0) or
    (Directory^.NumberOfFunctions = 0) then Exit;
  if (Directory^.AddressOfNames = 0) or
    (Directory^.AddressOfFunctions = 0) or
    (Directory^.AddressOfNameOrdinals = 0) then Exit;
  if not ImageRange(ImageSize, Directory^.AddressOfNames,
    UInt64(Directory^.NumberOfNames) * SizeOf(Cardinal)) or
    not ImageRange(ImageSize, Directory^.AddressOfFunctions,
    UInt64(Directory^.NumberOfFunctions) * SizeOf(Cardinal)) or
    not ImageRange(ImageSize, Directory^.AddressOfNameOrdinals,
    UInt64(Directory^.NumberOfNames) * SizeOf(Word)) then Exit;

  I := 0;
  while I < Directory^.NumberOfNames do
  begin
    NameRVA := PCardinal(Base + Directory^.AddressOfNames +
      NativeUInt(I) * SizeOf(Cardinal))^;
    if (NameRVA <> 0) and EqualExportName(Base, ImageSize, NameRVA, ProcName) then
    begin
      FunctionIndex := PWord(Base + Directory^.AddressOfNameOrdinals +
        NativeUInt(I) * SizeOf(Word))^;
      if Cardinal(FunctionIndex) >= Directory^.NumberOfFunctions then Exit;
      FunctionRVA := PCardinal(Base + Directory^.AddressOfFunctions +
        NativeUInt(FunctionIndex) * SizeOf(Cardinal))^;
      if (FunctionRVA = 0) or not ImageRange(ImageSize, FunctionRVA, 1) then Exit;
      ForwarderEnd := UInt64(ExportRVA) + ExportSize;
      if (FunctionRVA >= ExportRVA) and (UInt64(FunctionRVA) < ForwarderEnd) then
      begin
        { Never return the forwarder text as executable code. Let Windows
          resolve named/ordinal chains and API-set contracts. Reject an
          unterminated forwarder before calling the loader. }
        Cursor := FunctionRVA;
        while (Cursor < ForwarderEnd) and (Base[NativeUInt(Cursor)] <> 0) do
          Inc(Cursor);
        if (Cursor = ForwarderEnd) or (Cursor = FunctionRVA) then Exit;
        RegisteredModule := 0;
        if not PEBGetModuleHandleExW($00000004 or $00000002,
          PWideChar(ModuleBase), RegisteredModule) then Exit;
        if RegisteredModule <> HMODULE(ModuleBase) then Exit;
        Result := Pointer(PEBGetProcAddress(
          RegisteredModule, PAnsiChar(ProcName)));
      end
      else
        Result := Base + FunctionRVA;
      Exit;
    end;
    Inc(I);
  end;
end;

function GetProcAddress64(ModuleBase: Pointer;
  const ProcName: AnsiString): Pointer;
begin
  Result := nil;
  if (ModuleBase = nil) or (ProcName = '') or
    (Pos(AnsiChar(#0), ProcName) <> 0) then Exit;
  try
    Result := ResolveNamedExport(ModuleBase, ProcName);
  except
    on E: EAccessViolation do Result := nil;
  end;
end;

{ ROR13 RESOLVER BEGIN }
function TryHashExportName(Base: PByte; ImageSize, NameRVA: Cardinal;
  out NameHash: Cardinal): Boolean;
var
  Cursor: Cardinal;
  Octet: Byte;
begin
  Result := False;
  NameHash := 0;
  if (NameRVA = 0) or not ImageRange(ImageSize, NameRVA, 1) then Exit;
  Cursor := NameRVA;
  while Cursor < ImageSize do
  begin
    Octet := Base[NativeUInt(Cursor)];
    if Octet = 0 then
      Exit(Cursor > NameRVA); { Empty/unterminated export names are invalid. }
    NameHash := ApiHashROR13Byte(NameHash, Octet);
    Inc(Cursor);
  end;
end;

function ResolveHashedExport(ModuleBase: Pointer; ProcHash: Cardinal;
  ForwarderPolicy: TPEBForwarderPolicy = fpRegisteredModule): Pointer;
var
  Base, Nt, Optional: PByte;
  NtOffset: LongInt;
  OptionalSize: Word;
  ImageSize, ExportRVA, ExportSize: Cardinal;
  Directory: PExportDirectory64;
  I, NameRVA, NameHash, MatchedNameRVA, FunctionRVA: Cardinal;
  FunctionIndex: Word;
  ForwarderEnd, Cursor: UInt64;
  RegisteredModule: HMODULE;
  Found: Boolean;
begin
  Result := nil;
  Base := PByte(ModuleBase);
  if not BootstrapSpan(Base, $40) then Exit;
  if PWord(Base)^ <> $5A4D then Exit;                      { MZ }
  NtOffset := PLongInt(Base + $3C)^;
  if (NtOffset < $40) or (NtOffset > $100000) then Exit;
  if NativeUInt(Base) > High(NativeUInt) - NativeUInt(NtOffset) - $100 then Exit;
  Nt := Base + NtOffset;
  if PCardinal(Nt)^ <> $00004550 then Exit;                { PE signature }
  if PWord(Nt + 4)^ <> $8664 then Exit;                    { AMD64 }
  OptionalSize := PWord(Nt + 20)^;
  if OptionalSize < 120 then Exit;
  Optional := Nt + 24;
  if PWord(Optional)^ <> $020B then Exit;                  { PE32+ }
  ImageSize := PCardinal(Optional + 56)^;
  if (ImageSize = 0) or
    (NativeUInt(Base) > High(NativeUInt) - NativeUInt(ImageSize)) then Exit;
  if not ImageRange(ImageSize, Cardinal(NtOffset),
    UInt64(24) + OptionalSize) then Exit;
  if PCardinal(Optional + 108)^ < 1 then Exit;             { directory count }
  ExportRVA := PCardinal(Optional + 112)^;
  ExportSize := PCardinal(Optional + 116)^;
  if (ExportRVA = 0) or (ExportSize < SizeOf(TExportDirectory64)) or
    not ImageRange(ImageSize, ExportRVA, ExportSize) then Exit;
  Directory := PExportDirectory64(Base + ExportRVA);
  if (Directory^.NumberOfNames = 0) or
    (Directory^.NumberOfFunctions = 0) then Exit;
  if (Directory^.AddressOfNames = 0) or
    (Directory^.AddressOfFunctions = 0) or
    (Directory^.AddressOfNameOrdinals = 0) then Exit;
  if not ImageRange(ImageSize, Directory^.AddressOfNames,
    UInt64(Directory^.NumberOfNames) * SizeOf(Cardinal)) or
    not ImageRange(ImageSize, Directory^.AddressOfFunctions,
    UInt64(Directory^.NumberOfFunctions) * SizeOf(Cardinal)) or
    not ImageRange(ImageSize, Directory^.AddressOfNameOrdinals,
    UInt64(Directory^.NumberOfNames) * SizeOf(Word)) then Exit;


  Found := False;
  MatchedNameRVA := 0;
  FunctionIndex := 0;
  I := 0;
  while I < Directory^.NumberOfNames do
  begin
    NameRVA := PCardinal(Base + Directory^.AddressOfNames +
      NativeUInt(I) * SizeOf(Cardinal))^;
    if TryHashExportName(Base, ImageSize, NameRVA, NameHash) and
      (NameHash = ProcHash) then
    begin
      { Never pick an arbitrary target when two names share the same hash.
        Finish scanning before resolving any forwarder or returning code. }
      if Found then Exit;
      Found := True;
      MatchedNameRVA := NameRVA;
      FunctionIndex := PWord(Base + Directory^.AddressOfNameOrdinals +
        NativeUInt(I) * SizeOf(Word))^;
    end;
    Inc(I);
  end;
  if not Found then Exit;
  if Cardinal(FunctionIndex) >= Directory^.NumberOfFunctions then Exit;
  FunctionRVA := PCardinal(Base + Directory^.AddressOfFunctions +
    NativeUInt(FunctionIndex) * SizeOf(Cardinal))^;
  if (FunctionRVA = 0) or not ImageRange(ImageSize, FunctionRVA, 1) then Exit;
  ForwarderEnd := UInt64(ExportRVA) + ExportSize;
  if (FunctionRVA >= ExportRVA) and (UInt64(FunctionRVA) < ForwarderEnd) then
  begin
{ DYNAMIC FORWARD GUARD BEGIN }
    { Before the loader itself is bound, never invoke a forwarder or recurse
      into the loader. The bootstrap retries the other already-loaded core DLL. }
    if ForwarderPolicy = fpDirectExportOnly then Exit;
    if ForwarderPolicy = fpBootstrapCore then
    begin
      if not Assigned(BootstrapGetProcAddress) then Exit;
    end
    else if not LoaderSlotsReady then Exit;
{ DYNAMIC FORWARD GUARD END }
    Cursor := FunctionRVA;
    while (Cursor < ForwarderEnd) and (Base[NativeUInt(Cursor)] <> 0) do
      Inc(Cursor);
    if (Cursor = ForwarderEnd) or (Cursor = FunctionRVA) then Exit;
{ DYNAMIC MODULE VALIDATION BEGIN }
    if ForwarderPolicy = fpBootstrapCore then
      { Private initialization path only: ModuleBase was obtained from the
        PEB for kernel32/kernelbase, not from a public caller or an image buffer. }
      RegisteredModule := HMODULE(ModuleBase)
    else
    begin
      if not LoaderSlotsReady then Exit;
      RegisteredModule := 0;
      if not PEBGetModuleHandleExW($00000004 or $00000002,
        PWideChar(ModuleBase), RegisteredModule) then Exit;
      if RegisteredModule <> HMODULE(ModuleBase) then Exit;
    end;
{ DYNAMIC MODULE VALIDATION END }
    { Borrow the matched name from the loaded DLL, not from our own binary.
      Keep Windows handling forwarder chains, ordinals, and API-set mapping. }
    if ForwarderPolicy = fpBootstrapCore then
      Result := BootstrapGetProcAddress(
        RegisteredModule, PAnsiChar(Base + MatchedNameRVA))
    else
      Result := PEBGetProcAddress(
        RegisteredModule, PAnsiChar(Base + MatchedNameRVA));
  end
  else
    Result := Base + FunctionRVA;
end;

function GetProcAddressHash64(ModuleBase: Pointer; ProcHash: Cardinal): Pointer;
begin
  Result := nil;
  if ModuleBase = nil then Exit;
  try
    Result := ResolveHashedExport(ModuleBase, ProcHash);
  except
    on E: EAccessViolation do Result := nil;
  end;
end;
{ ROR13 RESOLVER END }

{ DYNAMIC BOOTSTRAP BEGIN }
procedure InitializeLoaderAPIs;
var
  Kernel32Base, KernelBase: Pointer;
  Address: Pointer;

  function TryCoreExport(ModuleBase: Pointer; ProcHash: Cardinal;
    Policy: TPEBForwarderPolicy): Pointer;
  begin
    Result := nil;
    if ModuleBase = nil then Exit;
    try
      Result := ResolveHashedExport(ModuleBase, ProcHash, Policy);
    except
      on E: EAccessViolation do Result := nil;
    end;
  end;

  function RequireCoreExport(ProcHash: Cardinal): Pointer;
  begin
    Result := TryCoreExport(Kernel32Base, ProcHash, fpBootstrapCore);
    if Result = nil then
      Result := TryCoreExport(KernelBase, ProcHash, fpBootstrapCore);
    if Result = nil then
      raise EInvalidOpException.CreateFmt(CozyText_Platform_ExportResolver_Cannot_initialize_Windows_loader_API_hash_0x_s_84d7037e,
        [IntToHex(Int64(ProcHash), 8)]);
  end;

begin
  { Run once in this EXE unit's initialization, before the application binding
    units. Do not call LoadSystemModule64/RequireProcAddressHash64 here: those
    need the very loader pointers being initialized. No IAT/header is modified. }
  Kernel32Base := GetModuleBase64(CozyText_Platform_ExportResolver_kernel32_dll_276e9510);
  KernelBase := GetModuleBase64(CozyText_Platform_ExportResolver_kernelbase_dll_4b82d848);

  { Seed the standard loader using a DIRECT export only. A forwarder address
    is text, not code. If neither core DLL provides a direct seed export,
    report failure; do not guess an address or use a native-loader fallback. }
  Address := TryCoreExport(Kernel32Base, HASH_GetProcAddress, fpDirectExportOnly);
  if Address = nil then
    Address := TryCoreExport(KernelBase, HASH_GetProcAddress, fpDirectExportOnly);
  if Address = nil then
    raise EInvalidOpException.Create(CozyText_Platform_ExportResolver_Cannot_bootstrap_the_Windows_loader_from_loaded__85d8bcbb);
  BootstrapGetProcAddress := TPEBGetProcAddress(Address);
  try
    { Resolve the four codec/error bridges before encoding any loader slot.
      Forwarder resolution in fpBootstrapCore uses the temporary seed only. }
    InitializeApiPointerCodec(
      RequireCoreExport(HASH_EncodePointer),
      RequireCoreExport(HASH_DecodePointer),
      RequireCoreExport(HASH_GetLastError),
      RequireCoreExport(HASH_SetLastError));
    ConfigureApiPointerStorage(
      RequireCoreExport(HASH_VirtualAlloc),
      RequireCoreExport(HASH_VirtualProtect),
      RequireCoreExport(HASH_VirtualFree),
      RequireCoreExport(HASH_VirtualQuery));
    BindApiPointer(ApiSlot_PEBGetProcAddress, Address);

    { Keep the original module/API binding order and loader behavior. }
    BindApiPointer(ApiSlot_PEBGetModuleHandleExW,
      RequireCoreExport(HASH_GetModuleHandleExW));
    BindApiPointer(ApiSlot_PEBGetSystemDirectoryW,
      RequireCoreExport(HASH_GetSystemDirectoryW));
    BindApiPointer(ApiSlot_PEBLoadLibraryExW,
      RequireCoreExport(HASH_LoadLibraryExW));
    BindApiPointer(ApiSlot_PEBFreeLibrary,
      RequireCoreExport(HASH_FreeLibrary));
    LoaderSlotsReady := True;
  finally
    { Do not retain a second, unencoded copy of the loader seed. }
    BootstrapGetProcAddress := nil;
  end;
end;
{ DYNAMIC BOOTSTRAP END }

function LoadSystemModule64(const ModuleName: string): HMODULE;
var
  I, Count: Integer;
  Name, FullPath: string;
  Directory: array[0..32767] of WideChar;
  Ch: WideChar;
  Size: Cardinal;
begin
  Name := LowerCase(ModuleName);
  if (Length(Name) < 5) or (Copy(Name, Length(Name) - 3, 4) <> CozyText_Platform_ExportResolver_dll_91a5217f) or
    (Pos(CozyText_Platform_ExportResolver_Text_d036592e, Name) <> 0) then
    raise EArgumentException.Create(CozyText_Platform_ExportResolver_A_System32_DLL_basename_is_required_85e5d8f1);
  for Ch in Name do
    if not CharInSet(Ch, ['a'..'z', '0'..'9', '-', '_', '.']) then
      raise EArgumentException.Create(CozyText_Platform_ExportResolver_A_System32_DLL_basename_is_required_85e5d8f1);

  TMonitor.Enter(ModuleLock);
  try
    for I := 0 to High(LoadedModules) do
      if LoadedModules[I].Name = Name then Exit(LoadedModules[I].Handle);
    Size := PEBGetSystemDirectoryW(@Directory[0], Length(Directory));
    if (Size = 0) or (Size >= Cardinal(Length(Directory))) then
      raise EInvalidOpException.Create(CozyText_Platform_ExportResolver_Cannot_locate_the_Windows_system_directory_b1493665);
    SetString(FullPath, PWideChar(@Directory[0]), Integer(Size));
    FullPath := IncludeTrailingPathDelimiter(FullPath) + Name;
    Result := PEBLoadLibraryExW(PWideChar(FullPath), 0, $00000800);
    if Result = 0 then
      raise EInvalidOpException.CreateFmt(CozyText_Platform_ExportResolver_Cannot_load_Windows_API_module_s_bd5421bb, [Name]);
    try
      Count := Length(LoadedModules);
      SetLength(LoadedModules, Count + 1);
      LoadedModules[Count].Name := Name;
      LoadedModules[Count].Handle := Result;
    except
      PEBFreeLibrary(Result);
      raise;
    end;
  finally
    TMonitor.Exit(ModuleLock);
  end;
end;

function RequireProcAddress64(const ModuleName: string;
  const ProcName: AnsiString): Pointer;
var
  Handle: HMODULE;
  Base: Pointer;
begin
  { Loading first prevents a cached address from outliving its DLL. }
  Handle := LoadSystemModule64(ModuleName);
  Base := GetModuleBase64(ModuleName);
  { PEB details are undocumented. Keep the OS-acquired lifetime reference;
    also prefer it if a duplicate basename or an API-set alias is encountered. }
  if Base <> Pointer(Handle) then Base := Pointer(Handle);
  Result := GetProcAddress64(Base, ProcName);
  if Result = nil then
    raise EInvalidOpException.CreateFmt(CozyText_Platform_ExportResolver_Cannot_resolve_Windows_API_s_s_df9eac69,
      [ModuleName, string(ProcName)]);
end;

{ ROR13 REQUIRE BEGIN }
function RequireProcAddressHash64(const ModuleName: string;
  ProcHash: Cardinal): Pointer;
var
  Handle: HMODULE;
  Base: Pointer;
begin
  { Same module lifetime, loading order, and System32 policy as the named path. }
  Handle := LoadSystemModule64(ModuleName);
  Base := GetModuleBase64(ModuleName);
  if Base <> Pointer(Handle) then Base := Pointer(Handle);
  Result := GetProcAddressHash64(Base, ProcHash);
  if Result = nil then
    raise EInvalidOpException.CreateFmt(CozyText_Platform_ExportResolver_Cannot_resolve_Windows_API_hash_s_0x_s_271d0985,
      [ModuleName, IntToHex(Int64(ProcHash), 8)]);
end;
{ ROR13 REQUIRE END }

procedure RetainApiTargetModule(Address: Pointer);
var Module: HMODULE;
begin
  Module := 0;
  if (Address = nil) or not PEBGetModuleHandleExW($00000004 or $00000001,
    PWideChar(Address), Module) or (Module = 0) then
    raise EInvalidOpException.Create(CozyText_Platform_ExportResolver_API_target_module_cannot_be_retained_2b7d8286);
end;

function OptionalSystemProcAddressHash64(const ModuleName: string;
  ProcHash: Cardinal): Pointer;
var Module: HMODULE;
begin
  Module := LoadSystemModule64(ModuleName);
  Result := GetProcAddressHash64(Pointer(Module), ProcHash);
end;

initialization
  if not PEBBootstrapLayoutValid or (SizeOf(TExportDirectory64) <> 40) then
    raise EInvalidOpException.Create(CozyText_Platform_ExportResolver_Unexpected_x64_API_resolver_record_layout_f393ad27);
{ DYNAMIC INITIALIZATION BEGIN }
  InitializeLoaderAPIs;
{ DYNAMIC INITIALIZATION END }
  ModuleLock := TObject.Create;

finalization
  { DLL references intentionally last until process exit: a resolver thread
    or a console control handler may still be returning through one of them.
    This unit is intended for these EXEs, not unloadable runtime packages. }
  LoadedModules := nil;
  ModuleLock.Free;

end.
