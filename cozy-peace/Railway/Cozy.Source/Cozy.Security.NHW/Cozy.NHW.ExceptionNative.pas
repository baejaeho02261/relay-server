unit Cozy.NHW.ExceptionNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.ExceptionRules;

// Read-only metadata inspection for the current module. Never change .pdata
// or .xdata. No debugger flags, exception injection, or stack unwinding.
// Invalid/incomplete memory reads are UNKNOWN and suppress reporting.
function CaptureExceptionImage(out Snapshot: TExceptionImageState): Boolean;
function RegisterPassThroughExceptionHandler(Handler: Pointer): Pointer;
procedure UnregisterPassThroughExceptionHandler(var Registration: Pointer);
function IsReadableLocalRange(Address, Bytes: NativeUInt): Boolean;

implementation

uses
  System.SysUtils,
  Cozy.NHW.WinPointers,
  Cozy.NHW.AllocationNative,
  Cozy.NHW.NativeSafety;

const
  DOS_SIGNATURE = $5A4D;
  PE_SIGNATURE = $00004550;
  PE64_MAGIC = $020B;
  MAX_IMAGE_BYTES = 512 * 1024 * 1024;
  MAX_RUNTIME_FUNCTIONS = 160000;
  MAX_UNWIND_SAMPLES = 128;
  MAX_LOOKUP_SAMPLES = 32;
  FNV64_BASIS = UInt64($CBF29CE484222325);

type
  TRtlLookupFunctionEntry = function(ControlPc: UInt64;
    var ImageBase: UInt64; HistoryTable: Pointer): PNHWRuntimeFunction; stdcall;
  TAddVectoredExceptionHandler = function(First: Cardinal;
    Handler: Pointer): Pointer; stdcall;
  TRemoveVectoredExceptionHandler = function(Handle: Pointer): Cardinal; stdcall;

var
  LookupFn: TRtlLookupFunctionEntry = nil;
  AddVEH: TAddVectoredExceptionHandler = nil;
  RemoveVEH: TRemoveVectoredExceptionHandler = nil;
  ExportsResolved: Boolean = False;

procedure ResolveExceptionExports;
var
  Nt, K: HMODULE;
begin
  if ExportsResolved then Exit;
  ExportsResolved := True;
  K := WinModule('kernel32.dll');
  Nt := WinModule('ntdll.dll');
  if K <> 0 then
  begin
    LookupFn := TRtlLookupFunctionEntry(WinExport(K, 'RtlLookupFunctionEntry'));
    AddVEH := TAddVectoredExceptionHandler(WinExport(K, 'AddVectoredExceptionHandler'));
    RemoveVEH := TRemoveVectoredExceptionHandler(WinExport(K, 'RemoveVectoredExceptionHandler'));
  end;
  if not Assigned(LookupFn) and (Nt <> 0) then
    LookupFn := TRtlLookupFunctionEntry(WinExport(Nt, 'RtlLookupFunctionEntry'));
end;

function RegisterPassThroughExceptionHandler(Handler: Pointer): Pointer;
begin
  Result := nil;
  ResolveExceptionExports;
  if (Handler <> nil) and Assigned(AddVEH) and Assigned(RemoveVEH) then
    try
      Result := AddVEH(0, Handler);
    except
      Result := nil;
    end;
end;

procedure UnregisterPassThroughExceptionHandler(var Registration: Pointer);
begin
  if Registration <> nil then
  begin
    if Assigned(RemoveVEH) then
      try
        RemoveVEH(Registration);
      except
        // Unregister is best effort at shutdown only.
      end;
    Registration := nil;
  end;
end;

function IsReadableLocalRange(Address, Bytes: NativeUInt): Boolean;
var
  R: TVirtualRegion;
begin
  Result := False;
  if not NHWAddressSpan(Address, Bytes) then Exit;
  if not QueryVirtualRegion(WinCurrentProcess, Address, R) then Exit;
  if (R.State <> ALLOC_MEM_COMMIT) or
     ((R.Protect and ALLOC_PAGE_GUARD) <> 0) or
     ((R.Protect and $FF) = 1) then Exit;
  case R.Protect and $FF of
    $02, $04, $08, $20, $40, $80: ; // explicitly readable protections
  else Exit;
  end;
  Result := NHWContainedSpan(R.BaseAddress, R.Size, Address, Bytes);
end;

function RangeInImage(RVA, Count, ImageSize: Cardinal): Boolean;
begin
  if RVA > ImageSize then Exit(False);
  Result := Count <= ImageSize - RVA;
end;

// Cache the validated VAD span for sequential .pdata entries. Without this
// cache, a large image would issue an NT virtual-memory query for every 12-byte
// record and could itself cause the legacy sampling-overrun warning.
function CachedReadableSpan(Address, Bytes: NativeUInt;
  var CachedStart, CachedEnd: NativeUInt): Boolean;
var
  R: TVirtualRegion;
begin
  Result := False;
  if not NHWAddressSpan(Address, Bytes) then Exit;
  if (Address >= CachedStart) and (Address < CachedEnd) and
     (Bytes <= CachedEnd - Address) then Exit(True);
  if not QueryVirtualRegion(WinCurrentProcess, Address, R) then Exit;
  if (R.State <> ALLOC_MEM_COMMIT) or
     ((R.Protect and ALLOC_PAGE_GUARD) <> 0) or
     ((R.Protect and $FF) = 1) then Exit;
  if (Address < R.BaseAddress) or (R.Size = 0) or
     (R.Size > High(NativeUInt) - R.BaseAddress) then Exit;
  CachedStart := R.BaseAddress;
  CachedEnd := R.BaseAddress + R.Size;
  Result := (Address < CachedEnd) and (Bytes <= CachedEnd - Address);
end;

function CaptureExceptionImage(out Snapshot: TExceptionImageState): Boolean;
var
  Base, TableAddress: NativeUInt;
  ImageSize, PDataRVA, PDataBytes: Cardinal;
  Count, UnwindSamples, LookupSamples: Cardinal;
  DigestTable, DigestRange, DigestUnwind: UInt64;
  ValidRange, ValidUnwind: Boolean;

  function ReadExceptionDirectory: Boolean;
  var
    PE, Optional: NativeUInt;
    HeaderRVA, OptSize, DirCount: Cardinal;
  begin
    Result := False;
    if PWord(Pointer(Base))^ <> DOS_SIGNATURE then Exit;
    HeaderRVA := PCardinal(Pointer(Base + $3C))^;
    if (HeaderRVA < $40) or (HeaderRVA > $800) then Exit;
    PE := Base + HeaderRVA;
    if not IsReadableLocalRange(PE, 24) then Exit;
    if PCardinal(Pointer(PE))^ <> PE_SIGNATURE then Exit;
    OptSize := PWord(Pointer(PE + 20))^;
    if (OptSize < 144) or (OptSize > $500) then Exit;
    Optional := PE + 24;
    if not IsReadableLocalRange(Optional, OptSize) then Exit;
    if PWord(Pointer(Optional))^ <> PE64_MAGIC then Exit;
    ImageSize := PCardinal(Pointer(Optional + 56))^;
    if (ImageSize < $2000) or (ImageSize > MAX_IMAGE_BYTES) then Exit;
    DirCount := PCardinal(Pointer(Optional + 108))^;
    if DirCount < 4 then Exit;
    PDataRVA := PCardinal(Pointer(Optional + 136))^;
    PDataBytes := PCardinal(Pointer(Optional + 140))^;
    if PDataRVA = 0 then Exit;
    Result := True;
  end;

  function ScanRuntimeFunctionTable: Boolean;
  var
    EntryAddress, InfoAddress, CheckPC: NativeUInt;
    I, J, Step, UnwindBytes, PrevBegin: Cardinal;
    Entry, ResolvedEntry: TNHWRuntimeFunction;
    VersionFlags, CodeCount, Header: Byte;
    ImageBaseFromLookup: UInt64;
    LookupEntry: PNHWRuntimeFunction;
    HasPrevious: Boolean;
    CachedStart, CachedEnd: NativeUInt;
  begin
    Result := False;
    PrevBegin := 0;
    HasPrevious := False;
    UnwindSamples := 0;
    LookupSamples := 0;
    Step := Count div MAX_UNWIND_SAMPLES;
    if Step = 0 then Step := 1;
    ValidRange := True;
    ValidUnwind := True;
    CachedStart := 0;
    CachedEnd := 0;

    for I := 0 to Count - 1 do
    begin
      EntryAddress := TableAddress + NativeUInt(I) * SizeOf(TNHWRuntimeFunction);
      if not CachedReadableSpan(EntryAddress, SizeOf(Entry),
         CachedStart, CachedEnd) then Exit;
      Move(PNHWRuntimeFunction(Pointer(EntryAddress))^, Entry, SizeOf(Entry));
      DigestTable := ExceptionFingerprint(DigestTable, Entry.BeginAddress);
      DigestTable := ExceptionFingerprint(DigestTable, Entry.EndAddress);
      DigestTable := ExceptionFingerprint(DigestTable, Entry.UnwindData);
      DigestRange := ExceptionFingerprint(DigestRange, Entry.BeginAddress);
      DigestRange := ExceptionFingerprint(DigestRange, Entry.EndAddress);
      if not ExceptionRangeValid(Entry, ImageSize, PrevBegin, HasPrevious) then
        ValidRange := False;
      PrevBegin := Entry.BeginAddress;
      HasPrevious := True;

      if ((I mod Step) <> 0) or (UnwindSamples >= MAX_UNWIND_SAMPLES) then
        Continue;
      if not RangeInImage(Entry.UnwindData, 4, ImageSize) then
      begin
        ValidUnwind := False;
        Continue;
      end;
      InfoAddress := Base + Entry.UnwindData;
      if not IsReadableLocalRange(InfoAddress, 4) then Exit;
      VersionFlags := PByte(Pointer(InfoAddress))^;
      CodeCount := PByte(Pointer(InfoAddress + 2))^;
      if not ExceptionUnwindHeaderValid(VersionFlags, CodeCount,
        Entry.UnwindData, ImageSize, UnwindBytes) then
      begin
        ValidUnwind := False;
        Continue;
      end;
      if not IsReadableLocalRange(InfoAddress, UnwindBytes) then Exit;
      for J := 0 to UnwindBytes - 1 do
      begin
        Header := PByte(Pointer(InfoAddress + NativeUInt(J)))^;
        DigestUnwind := ExceptionFingerprint(DigestUnwind, Header);
      end;
      Inc(UnwindSamples);

      if Assigned(LookupFn) and (LookupSamples < MAX_LOOKUP_SAMPLES) and
         ExceptionRangeValid(Entry, ImageSize, 0, False) then
      begin
        // The resolver may legitimately return NULL for some code paths.
        // Ignore dynamically installed function tables outside .pdata.
        ImageBaseFromLookup := 0;
        CheckPC := Base + Entry.BeginAddress;
        LookupEntry := LookupFn(UInt64(CheckPC), ImageBaseFromLookup, nil);
        if (LookupEntry <> nil) and
           (ImageBaseFromLookup = UInt64(Base)) and
           (NativeUInt(LookupEntry) >= TableAddress) and
           (NativeUInt(LookupEntry) <= TableAddress + PDataBytes - SizeOf(Entry)) then
        begin
          if not IsReadableLocalRange(NativeUInt(LookupEntry), SizeOf(ResolvedEntry)) then Exit;
          Move(LookupEntry^, ResolvedEntry, SizeOf(ResolvedEntry));
          Snapshot.HasLookupSamples := True;
          // The returned static entry may be a legal enclosing function
          // for chained unwind records. A different range alone is not a
          // malicious result; flag only a range that does not cover the PC.
          if (ResolvedEntry.BeginAddress > Entry.BeginAddress) or
             (ResolvedEntry.EndAddress <= Entry.BeginAddress) or
             (ResolvedEntry.EndAddress > ImageSize) then
            Snapshot.LookupConsistent := False;
          Inc(LookupSamples);
        end;
      end;
    end;
    Result := True;
  end;

begin
  Result := False;
  Snapshot := Default(TExceptionImageState);
  ResolveExceptionExports;
  Base := NativeUInt(HInstance);
  if not IsReadableLocalRange(Base, $1000) then Exit;
  try
    if not ReadExceptionDirectory then Exit;
    Snapshot.ImageBase := Base;
    Snapshot.ImageSize := ImageSize;
    DigestTable := FNV64_BASIS;
    DigestRange := FNV64_BASIS;
    DigestUnwind := FNV64_BASIS;
    DigestTable := ExceptionFingerprint(DigestTable, PDataRVA);
    DigestTable := ExceptionFingerprint(DigestTable, PDataBytes);
    DigestRange := ExceptionFingerprint(DigestRange, PDataBytes);

    Snapshot.RangeValid := RangeInImage(PDataRVA, PDataBytes, ImageSize) and
      ((PDataBytes mod SizeOf(TNHWRuntimeFunction)) = 0) and
      (PDataBytes >= SizeOf(TNHWRuntimeFunction));
    Snapshot.UnwindValid := True;
    Snapshot.LookupConsistent := True;
    if not Snapshot.RangeValid then
    begin
      Snapshot.TableDigest := DigestTable;
      Snapshot.RangeDigest := DigestRange;
      Result := True;
      Exit;
    end;
    Count := PDataBytes div SizeOf(TNHWRuntimeFunction);
    if Count > MAX_RUNTIME_FUNCTIONS then Exit;
    Snapshot.TableCount := Count;
    TableAddress := Base + PDataRVA;
    if not ScanRuntimeFunctionTable then Exit;
    Snapshot.TableDigest := ExceptionFingerprint(DigestTable, Count);
    Snapshot.RangeDigest := ExceptionFingerprint(DigestRange, Count);
    Snapshot.UnwindDigest := ExceptionFingerprint(DigestUnwind, UnwindSamples);
    Snapshot.RangeValid := ValidRange;
    Snapshot.UnwindValid := ValidUnwind and (UnwindSamples > 0);
    Snapshot.HasUnwindSamples := UnwindSamples > 0;
    Result := True;
  except
    Result := False;
    Snapshot := Default(TExceptionImageState);
  end;
end;

end.
