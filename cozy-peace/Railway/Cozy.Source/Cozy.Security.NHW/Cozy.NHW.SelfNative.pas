unit Cozy.NHW.SelfNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils;

// Read-only inspection of current-process metadata. All raw addresses are
// validated against NtQueryVirtualMemory before local dereferences.
// The PEB is used ONLY for ProcessParameters (no anti-debug checks).
function CaptureSelfIAT(out Digest: UInt64; out Entries: Cardinal): Boolean;
function CaptureLiveFunctionPointers(out Digest: UInt64;
  out ValidTargets: Boolean): Boolean;
function CaptureProcessParameters(out Digest: UInt64): Boolean;
function ExecutableImageAddress(Address: NativeUInt): Boolean;
function ExecutablePrivateAddress(Address: NativeUInt): Boolean;
function CallbackFingerprint(ConsoleTarget, EtwEventTarget,
  EtwBufferTarget: NativeUInt; out Digest: UInt64;
  out ValidTargets: Boolean): Boolean;
function NextFingerprint(Hash, Value: UInt64): UInt64;

{$IFDEF NHW_NATIVE5D_TESTS}
function TestSelfNativeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.AllocationNative,
  Cozy.NHW.WinPointers,
  Cozy.NHW.Native,
  System.SyncObjs;

const
  DOS_SIGNATURE = $5A4D;
  PE_SIGNATURE = $00004550;
  PE64_MAGIC = $020B;
  MAX_IMAGE_SIZE = 512 * 1024 * 1024;
  MAX_IMPORT_FUNCTIONS = 8192;
  MAX_IMPORT_DESCRIPTORS = 1024;
  MAX_PARAMETER_BYTES = 32768;
  PROCESS_BASIC_CLASS = 0;

type
  TUnicodeString64 = record
    Length: Word;
    MaximumLength: Word;
    Buffer: PWideChar;
  end;

  PParametersPrefix = ^TParametersPrefix;
  TParametersPrefix = record
    Reserved1: array[0..15] of Byte;
    Reserved2: array[0..9] of Pointer;
    ImagePathName: TUnicodeString64;
    CommandLine: TUnicodeString64;
  end;

  TProcessBasicX64 = record
    ExitStatus: LongInt;
    Padding: Cardinal;
    PebBaseAddress: Pointer;
    AffinityMask: NativeUInt;
    BasePriority: LongInt;
    Padding2: Cardinal;
    UniqueProcessId: NativeUInt;
    InheritedFromUniqueProcessId: NativeUInt;
  end;

  TNtQueryInformationProcess = function(ProcessHandle: THandle;
    InformationClass: Cardinal; Info: Pointer; InfoLength: Cardinal;
    ReturnLength: PCardinal): LongInt; stdcall;

var
  QueryProcessPtr: TNtQueryInformationProcess = nil;
  ProcessResolved: Boolean = False;
  ProcessResolveLock: TCriticalSection;

function NextFingerprint(Hash, Value: UInt64): UInt64;
begin
  // Non-cryptographic in-memory change detection; no disk reference or secrets.
  Result := (Hash xor Value) * UInt64($00000100000001B3);
end;

function StartFingerprint: UInt64;
begin
  Result := UInt64($CBF29CE484222325);
end;

function RangePresent(Rva, Len, ImageSize: Cardinal): Boolean;
begin
  Result := False;
  if Rva > ImageSize then Exit;
  Result := Len <= ImageSize - Rva;
end;

function ReadableRange(Address, Bytes: NativeUInt): Boolean;
var
  R: TVirtualRegion;
  Offset: NativeUInt;
begin
  Result := False;
  if (Address < $10000) or (Bytes = 0) then Exit;
  if Bytes > High(NativeUInt) - Address then Exit;
  if not QueryVirtualRegion(WinCurrentProcess, Address, R) then Exit;
  if (R.State <> ALLOC_MEM_COMMIT) or
     ((R.Protect and ALLOC_PAGE_GUARD) <> 0) or
     not ((R.Protect and $FF) in [$02, $04, $08, $20, $40, $80]) then Exit;
  if Address < R.BaseAddress then Exit;
  Offset := Address - R.BaseAddress;
  if Offset >= R.Size then Exit;
  Result := Bytes <= R.Size - Offset;
end;

function ExecutableImageAddress(Address: NativeUInt): Boolean;
var
  R: TVirtualRegion;
begin
  Result := False;
  if Address < $10000 then Exit;
  if not QueryVirtualRegion(THandle(High(NativeUInt)), Address, R) then Exit;
  Result := (R.RegionType = ALLOC_MEM_IMAGE) and RegionIsExecutable(R);
end;

function ExecutablePrivateAddress(Address: NativeUInt): Boolean;
var
  R: TVirtualRegion;
begin
  Result := False;
  if Address < $10000 then Exit;
  if not QueryVirtualRegion(THandle(High(NativeUInt)), Address, R) then Exit;
  Result := (R.RegionType = ALLOC_MEM_PRIVATE) and RegionIsExecutable(R);
end;

function CaptureIATAtBase(Base: NativeUInt; out Digest: UInt64;
  out Entries: Cardinal): Boolean;
var
  ImageSize, ImportsRva, ImportsSize, LocalEntries: Cardinal;
  H: UInt64;

  function ReadImportDirectory: Boolean;
  var
    PE, Optional: NativeUInt;
    HeaderOffset, OptSize, Directories: Cardinal;
  begin
    Result := False;
    if PWord(Pointer(Base))^ <> DOS_SIGNATURE then Exit;
    HeaderOffset := PCardinal(Pointer(Base + $3C))^;
    if (HeaderOffset < $40) or (HeaderOffset > $800) then Exit;
    PE := Base + HeaderOffset;
    if PCardinal(Pointer(PE))^ <> PE_SIGNATURE then Exit;
    OptSize := PWord(Pointer(PE + 20))^;
    if (OptSize < 128) or (OptSize > $500) then Exit;
    Optional := PE + 24;
    if not ReadableRange(Optional, OptSize) then Exit;
    if PWord(Pointer(Optional))^ <> PE64_MAGIC then Exit;
    ImageSize := PCardinal(Pointer(Optional + 56))^;
    if (ImageSize < $1000) or (ImageSize > MAX_IMAGE_SIZE) then Exit;
    if NativeUInt(ImageSize) > High(NativeUInt) - Base then Exit;
    if not RangePresent(HeaderOffset, 24 + OptSize, ImageSize) then Exit;
    Directories := PCardinal(Pointer(Optional + 108))^;
    if (Directories < 2) or (Directories > (OptSize - 112) div 8) then Exit;
    ImportsRva := PCardinal(Pointer(Optional + 120))^;
    ImportsSize := PCardinal(Pointer(Optional + 124))^;
    if not RangePresent(ImportsRva, ImportsSize, ImageSize) or
       (ImportsRva = 0) or (ImportsSize < 20) then Exit;
    Result := True;
  end;

  function HashImportSlots: Boolean;
  var
    Descriptor, Thunk, Target: NativeUInt;
    FirstThunk, I, J, DCount: Cardinal;
    Terminated, HasFinalDescriptor: Boolean;
  begin
    Result := False;
    DCount := ImportsSize div 20;
    if DCount > MAX_IMPORT_DESCRIPTORS then Exit;
    H := StartFingerprint;
    HasFinalDescriptor := False;
    for I := 0 to DCount - 1 do
    begin
      Descriptor := Base + ImportsRva + NativeUInt(I) * 20;
      if not ReadableRange(Descriptor, 20) then Exit;
      FirstThunk := PCardinal(Pointer(Descriptor + 16))^;
      if FirstThunk = 0 then
      begin
        // A terminating IMAGE_IMPORT_DESCRIPTOR is entirely zero.
        // A missing thunk with nonzero fields is malformed, not completion.
        if (PCardinal(Pointer(Descriptor))^ <> 0) or
           (PCardinal(Pointer(Descriptor + 4))^ <> 0) or
           (PCardinal(Pointer(Descriptor + 8))^ <> 0) or
           (PCardinal(Pointer(Descriptor + 12))^ <> 0) then Exit;
        HasFinalDescriptor := True;
        Break;
      end;
      if not RangePresent(FirstThunk, 8, ImageSize) then Exit;
      Terminated := False;
      for J := 0 to 1023 do
      begin
        if not RangePresent(FirstThunk, (J + 1) * 8, ImageSize) then Exit;
        Thunk := Base + FirstThunk + NativeUInt(J) * 8;
        if not ReadableRange(Thunk, 8) then Exit;
        Target := NativeUInt(PUInt64(Pointer(Thunk))^);
        if Target = 0 then
        begin
          Terminated := True;
          Break;
        end;
        Inc(LocalEntries);
        if LocalEntries > MAX_IMPORT_FUNCTIONS then Exit;
        H := NextFingerprint(H, UInt64(Thunk));
        H := NextFingerprint(H, UInt64(Target));
      end;
      if not Terminated then Exit;
    end;
    if not HasFinalDescriptor or (LocalEntries = 0) then Exit;
    Result := True;
  end;

begin
  Result := False;
  Digest := 0;
  Entries := 0;
  LocalEntries := 0;
  if not ReadableRange(Base, $1000) then Exit;
  try
    if not ReadImportDirectory then Exit;
    if not HashImportSlots then Exit;
    Digest := NextFingerprint(H, LocalEntries);
    Entries := LocalEntries;
    Result := True;
  except
    Result := False;
    Digest := 0;
    Entries := 0;
  end;
end;

function CaptureSelfIAT(out Digest: UInt64; out Entries: Cardinal): Boolean;
begin
  Result := CaptureIATAtBase(NativeUInt(HInstance), Digest, Entries);
end;

function FingerprintFunctionArrays(const W, N: TArray<NativeUInt>;
  out Digest: UInt64; out ValidTargets: Boolean): Boolean;
var
  I, Used: Integer;
  H: UInt64;
  LocalValid: Boolean;
begin
  Result := False;
  Digest := 0;
  ValidTargets := False;
  try
    if (Length(W) < 8) or (Length(N) < 3) then Exit;
    H := StartFingerprint;
    LocalValid := True;
    Used := 0;
    for I := 0 to High(W) do
    begin
      // The selected Win32 function pointers must always be initialized.
      if W[I] = 0 then Exit;
      H := NextFingerprint(H, UInt64(I));
      H := NextFingerprint(H, UInt64(W[I]));
      if not ExecutableImageAddress(W[I]) then LocalValid := False;
      Inc(Used);
    end;
    for I := 0 to High(N) do
    begin
      // Some native functions are optional; NULL is not an anomaly.
      H := NextFingerprint(H, UInt64(I) + $10000);
      H := NextFingerprint(H, UInt64(N[I]));
      if (N[I] <> 0) and not ExecutableImageAddress(N[I]) then
        LocalValid := False;
      Inc(Used);
    end;
    if Used < 14 then Exit;
    Digest := H;
    ValidTargets := LocalValid;
    Result := True;
  except
    Result := False;
    Digest := 0;
    ValidTargets := False;
  end;
end;

function CaptureLiveFunctionPointers(out Digest: UInt64;
  out ValidTargets: Boolean): Boolean;
var
  W, N: TArray<NativeUInt>;
begin
  Result := False;
  Digest := 0;
  ValidTargets := False;
  try
    W := SnapshotWinFunctionPointers;
    N := SnapshotNativeFunctionPointers;
    Result := FingerprintFunctionArrays(W, N, Digest, ValidTargets);
  except
    Digest := 0;
    ValidTargets := False;
  end;
end;

procedure ResolveProcessQuery;
var
  M: HMODULE;
  Q: TNtQueryInformationProcess;
begin
  ProcessResolveLock.Acquire;
  try
    if ProcessResolved then Exit;
    M := WinModule('ntdll.dll');
    if M = 0 then Exit;
    Q := TNtQueryInformationProcess(WinExport(M, 'NtQueryInformationProcess'));
    if not Assigned(Q) then Exit;
    QueryProcessPtr := Q;
    ProcessResolved := True;
  finally
    ProcessResolveLock.Release;
  end;
end;

function ReadUnicodeFingerprint(const U: TUnicodeString64;
  out Digest: UInt64): Boolean;
var
  I: Cardinal;
  H: UInt64;
  Ptr: PWord;
begin
  Result := False;
  Digest := 0;
  if ((U.Length and 1) <> 0) or ((U.MaximumLength and 1) <> 0) then Exit;
  if (U.MaximumLength < U.Length) or
     (U.Length > MAX_PARAMETER_BYTES) then Exit;
  H := StartFingerprint;
  H := NextFingerprint(H, NativeUInt(U.Buffer));
  H := NextFingerprint(H, U.Length);
  if U.Length > 0 then
  begin
    if not ReadableRange(NativeUInt(U.Buffer), U.Length) then Exit;
    Ptr := PWord(U.Buffer);
    try
      for I := 0 to (U.Length div 2) - 1 do
      begin
        H := NextFingerprint(H, Ptr^);
        Inc(Ptr);
      end;
    except
      Exit;
    end;
  end;
  Digest := H;
  Result := True;
end;

function CaptureProcessParameters(out Digest: UInt64): Boolean;
var
  B: TProcessBasicX64;
  U: TParametersPrefix;
  Parameters: Pointer;
  Needed: Cardinal;
  A, C: UInt64;
  Peb: NativeUInt;
begin
  Result := False;
  Digest := 0;
  ResolveProcessQuery;
  if not Assigned(QueryProcessPtr) or (SizeOf(B) <> 48) or
     (SizeOf(TUnicodeString64) <> 16) or (SizeOf(U) <> 128) then Exit;
  B := Default(TProcessBasicX64);
  Needed := 0;
  if QueryProcessPtr(WinCurrentProcess, PROCESS_BASIC_CLASS,
    @B, SizeOf(B), @Needed) < 0 then Exit;
  if Needed <> Cardinal(SizeOf(B)) then Exit;
  if B.UniqueProcessId <> NativeUInt(WinCurrentProcessId) then Exit;
  Peb := NativeUInt(B.PebBaseAddress);
  if (Peb < $10000) or (Peb > High(NativeUInt) - $20) then Exit;
  if not ReadableRange(Peb + $20, SizeOf(Pointer)) then Exit;
  try
    Parameters := PPointer(Pointer(Peb + $20))^;
    if not ReadableRange(NativeUInt(Parameters), SizeOf(U)) then Exit;
    U := PParametersPrefix(Parameters)^;
  except
    Exit;
  end;
  if not ReadUnicodeFingerprint(U.ImagePathName, A) or
     not ReadUnicodeFingerprint(U.CommandLine, C) then Exit;
  // No output escapes until all reads have succeeded.
  A := NextFingerprint(NextFingerprint(StartFingerprint,
    UInt64(NativeUInt(Parameters))), A);
  Digest := NextFingerprint(A, C);
  Result := True;
end;

function CallbackFingerprint(ConsoleTarget, EtwEventTarget,
  EtwBufferTarget: NativeUInt; out Digest: UInt64;
  out ValidTargets: Boolean): Boolean;
begin
  Digest := 0;
  ValidTargets := False;
  Result := (ConsoleTarget <> 0) or
    ((EtwEventTarget <> 0) and (EtwBufferTarget <> 0));
  if not Result then Exit;
  Digest := NextFingerprint(StartFingerprint, ConsoleTarget);
  Digest := NextFingerprint(Digest, EtwEventTarget);
  Digest := NextFingerprint(Digest, EtwBufferTarget);
  ValidTargets := (ConsoleTarget = 0) or ExecutableImageAddress(ConsoleTarget);
  if (EtwEventTarget <> 0) and not ExecutableImageAddress(EtwEventTarget) then
    ValidTargets := False;
  if (EtwBufferTarget <> 0) and not ExecutableImageAddress(EtwBufferTarget) then
    ValidTargets := False;
end;

{$IFDEF NHW_NATIVE5D_TESTS}
{$I Cozy.NHW.Native5D.SelfNative.inc}
{$ENDIF}

initialization
  ProcessResolveLock := TCriticalSection.Create;
finalization
  ProcessResolveLock.Free;
end.
