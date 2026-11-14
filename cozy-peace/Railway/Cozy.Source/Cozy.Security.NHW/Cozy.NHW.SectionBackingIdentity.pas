unit Cozy.NHW.SectionBackingIdentity;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TSectionFileIDKind = (sfkUnspecified, sfkFileID128, sfkLegacy64);
  TSectionIdentity = record
    Valid: Boolean;
    Base: NativeUInt;
    MappedNameHash: UInt64;
    // Compatibility fingerprint for existing FileAttestation consumers.
    // The backing monitor compares the complete identity below, not this hash.
    PathFileID: UInt64;
    FileIDKind: TSectionFileIDKind;
    VolumeSerial: UInt64;
    FileID128: array[0..15] of Byte;
    LegacyFileIndex: UInt64;
    FileIDFallbackError: Cardinal;
  end;

  // Mapped-image path and identity of the CURRENT path on disk.
  // This is not proof of the identity of the original SEC_IMAGE file object.
  TSectionBackingMonitor = class
  private
    FBaseline: array[0..3] of TSectionIdentity;
    FPending: array[0..3] of TSectionIdentity;
    FConfirmations: array[0..3] of Integer;
    FPendingSince, FPendingTick: array[0..3] of UInt64;
    FLastTick: UInt64;
    FLastEvidence: UInt64;
    FLastReport: UInt64;
    FHasScan: Boolean;
    procedure ClearCandidate(Index: Integer);
    procedure AdvanceIdentityCandidate(Index: Integer;
      const Current: TSectionIdentity; Tick: UInt64);
    procedure ReportIdentityCandidate(Index: Integer;
      const Current: TSectionIdentity; Tick: UInt64;
      var Detected: TDetectionKinds);
    procedure ObserveIdentity(Index: Integer; QueryOK, Baseline: Boolean;
      const Current: TSectionIdentity; Tick: UInt64;
      var Detected: TDetectionKinds);
  public
    constructor Create;
    procedure Reset;
    procedure Examine(Baseline, ExternalAccess: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function CaptureSectionIdentity(Module: HMODULE;
  out Identity: TSectionIdentity): Boolean;
function SectionBackingCandidate(const Baseline, Current: TSectionIdentity;
  Confirmations: Integer; IndependentEvidence: Boolean): Boolean;

{$IFDEF NHW_NATIVE5G_TESTS}
function TestSectionBackingHardening(out Failure: string;
  out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, System.SyncObjs, Cozy.NHW.WinPointers, Cozy.NHW.PEView;

const
  BACKING_SCAN_MS = 12000;
  BACKING_EVIDENCE_MS = 45000;
  BACKING_COOLDOWN_MS = 60000;
  BACKING_PENDING_MS = 45000;
  BACKING_FILE_ID_INFO_CLASS = 18; // FILE_INFO_BY_HANDLE_CLASS.FileIdInfo

type
  TModuleNameW = function(Module: HMODULE; Buffer: PWideChar;
    Size: Cardinal): Cardinal; stdcall;
  TMappedNameW = function(Process: THandle; Address: Pointer;
    Buffer: PWideChar; Size: Cardinal): Cardinal; stdcall;
  TBackingFileInfoEx = function(Handle: THandle; InfoClass: Integer;
    Info: Pointer; Size: Cardinal): BOOL; stdcall;
  // FILE_ID_INFO: ULONGLONG volume serial + 16-byte FILE_ID_128.
  TBackingFileIDInfo = record
    VolumeSerialNumber: UInt64;
    Identifier: array[0..15] of Byte;
  end;

var
  ModuleNameW: TModuleNameW = nil;
  MappedNameW: TMappedNameW = nil;
  BackingFileInfoEx: TBackingFileInfoEx = nil;
  FunctionsResolved: Boolean = False;
  BackingLock: TCriticalSection;

{$IFDEF NHW_NATIVE5G_TESTS}
type
  TBackingID128Hook = function(Handle: THandle; out Info: TBackingFileIDInfo;
    out Error: Cardinal): Boolean;
  TBackingID64Hook = function(Handle: THandle;
    out Info: BY_HANDLE_FILE_INFORMATION): Boolean;
  TBackingCaptureHook = function(Module: HMODULE;
    out Identity: TSectionIdentity): Boolean;
var
  BackingID128Hook: TBackingID128Hook = nil;
  BackingID64Hook: TBackingID64Hook = nil;
  BackingCaptureHook: TBackingCaptureHook = nil;
{$ENDIF}

procedure ResolveBackingFunctions;
var K, P: HMODULE;
begin
  BackingLock.Acquire;
  try
    if FunctionsResolved then Exit;
    K := WinModule('kernel32.dll');
    if K = 0 then Exit; // permit a later resolution attempt
    ModuleNameW := TModuleNameW(WinExport(K, 'GetModuleFileNameW'));
    MappedNameW := TMappedNameW(WinExport(K, 'K32GetMappedFileNameW'));
    BackingFileInfoEx := TBackingFileInfoEx(
      WinExport(K, 'GetFileInformationByHandleEx'));
    if not Assigned(MappedNameW) then
    begin
      P := WinLoadLibrary('psapi.dll');
      MappedNameW := TMappedNameW(WinExport(P, 'GetMappedFileNameW'));
    end;
    FunctionsResolved := True; // publish after all pointer assignments
  finally BackingLock.Release; end;
end;

function FoldWideHash(const S: string): UInt64;
var I: Integer;
begin
  Result := UInt64($CBF29CE484222325);
  for I := 1 to Length(S) do
    Result := PEHash(Result, Ord(UpCase(S[I])));
end;

function ReadBackingID128(Handle: THandle; out Info: TBackingFileIDInfo;
  out Error: Cardinal): Boolean;
begin
  Info := Default(TBackingFileIDInfo);
  Error := 0;
{$IFDEF NHW_NATIVE5G_TESTS}
  if Assigned(BackingID128Hook) then
    Exit(BackingID128Hook(Handle, Info, Error));
{$ENDIF}
  ResolveBackingFunctions;
  if not Assigned(BackingFileInfoEx) then
  begin Error := ERROR_CALL_NOT_IMPLEMENTED; Exit(False); end;
  if SizeOf(Info) <> 24 then
  begin Error := ERROR_INVALID_DATA; Exit(False); end;
  Result := BackingFileInfoEx(Handle, BACKING_FILE_ID_INFO_CLASS,
    @Info, Cardinal(SizeOf(Info)));
  if not Result then Error := WinGetLastError;
end;

function ReadBackingID64(Handle: THandle;
  out Info: BY_HANDLE_FILE_INFORMATION): Boolean;
begin
  Info := Default(BY_HANDLE_FILE_INFORMATION);
{$IFDEF NHW_NATIVE5G_TESTS}
  if Assigned(BackingID64Hook) then Exit(BackingID64Hook(Handle, Info));
{$ENDIF}
  Result := WinGetFileInformationByHandle(Handle, Info);
end;

function BackingIDUnsupported(Error: Cardinal): Boolean;
begin
  Result := (Error = ERROR_INVALID_FUNCTION) or
    (Error = ERROR_NOT_SUPPORTED) or (Error = ERROR_INVALID_PARAMETER) or
    (Error = ERROR_CALL_NOT_IMPLEMENTED);
end;

procedure StoreFullBackingID(const Full: TBackingFileIDInfo;
  var ID: TSectionIdentity);
var
  I: Integer;
begin
  ID.FileIDKind := sfkFileID128;
  ID.VolumeSerial := Full.VolumeSerialNumber;
  ID.PathFileID := PEHash(UInt64($CBF29CE484222325), ID.VolumeSerial);
  for I := 0 to 15 do
  begin
    ID.FileID128[I] := Full.Identifier[I];
    ID.PathFileID := PEHash(ID.PathFileID, UInt64(ID.FileID128[I]));
  end;
end;

procedure StoreLegacyBackingID(const Legacy: BY_HANDLE_FILE_INFORMATION;
  Index: UInt64; Error: Cardinal; var ID: TSectionIdentity);
begin
  ID.FileIDKind := sfkLegacy64;
  ID.FileIDFallbackError := Error;
  ID.VolumeSerial := UInt64(Legacy.dwVolumeSerialNumber);
  ID.LegacyFileIndex := Index;
  ID.PathFileID := PEHash(ID.VolumeSerial, Index);
end;

function CaptureBackingFileID(Handle: THandle;
  out ID: TSectionIdentity): Boolean;
var
  Full: TBackingFileIDInfo;
  Legacy: BY_HANDLE_FILE_INFORMATION;
  Error: Cardinal;
  Index: UInt64;
begin
  ID := Default(TSectionIdentity);
  Result := False;
  if (Handle = 0) or (Handle = INVALID_HANDLE_VALUE) then Exit;
  if ReadBackingID128(Handle, Full, Error) then
  begin
    StoreFullBackingID(Full, ID);
    Exit(True);
  end;
  // Access-denied/transient failures must NOT silently downgrade precision.
  if not BackingIDUnsupported(Error) then Exit;
  if not ReadBackingID64(Handle, Legacy) then Exit;
  Index := (UInt64(Legacy.nFileIndexHigh) shl 32) or
    UInt64(Legacy.nFileIndexLow);
  // ReFS can return sentinel legacy IDs; these are not stable identities.
  if (Index = 0) or (Index = High(UInt64)) then Exit;
  StoreLegacyBackingID(Legacy, Index, Error, ID);
  Result := True;
end;

function ReadBackingNames(Module: HMODULE; out LocalName,
  MappedName: string): Boolean;
var LocalBuffer, MappedBuffer: array[0..1023] of WideChar;
  N, M: Cardinal;
begin
  LocalName := '';
  MappedName := '';
  Result := False;
  FillChar(LocalBuffer, SizeOf(LocalBuffer), 0);
  FillChar(MappedBuffer, SizeOf(MappedBuffer), 0);
  N := ModuleNameW(Module, @LocalBuffer[0], Length(LocalBuffer));
  M := MappedNameW(WinCurrentProcess, Pointer(Module),
    @MappedBuffer[0], Length(MappedBuffer));
  if (N = 0) or (M = 0) or (N >= Cardinal(Length(LocalBuffer))) or
    (M >= Cardinal(Length(MappedBuffer))) then Exit;
  SetString(LocalName, PWideChar(@LocalBuffer[0]), Integer(N));
  SetString(MappedName, PWideChar(@MappedBuffer[0]), Integer(M));
  if (Pos(#0, LocalName) <> 0) or (Pos(#0, MappedName) <> 0) then Exit;
  Result := True;
end;

function BackingImageUnchanged(Module: HMODULE; const View: TPEView;
  const Path, Mapped: string): Boolean;
var
  PathAfter, MappedAfter: string;
  AfterView: TPEView;
begin
  Result := False;
  if not LoadPEView(NativeUInt(Module), AfterView) or
    (View.Base <> AfterView.Base) or (View.ImageSize <> AfterView.ImageSize) or
    not ReadBackingNames(Module, PathAfter, MappedAfter) then Exit;
  if (PathAfter <> Path) or (MappedAfter <> Mapped) then Exit;
  Result := True;
end;

function CaptureSectionIdentity(Module: HMODULE;
  out Identity: TSectionIdentity): Boolean;
var
  Path, Mapped: string;
  Handle: THandle;
  Candidate: TSectionIdentity;
  View: TPEView;
begin
  Identity := Default(TSectionIdentity);
  Result := False;
{$IFDEF NHW_NATIVE5G_TESTS}
  if Assigned(BackingCaptureHook) then
    Exit(BackingCaptureHook(Module, Identity));
{$ENDIF}
  ResolveBackingFunctions;
  if (Module = 0) or not Assigned(ModuleNameW) or
    not Assigned(MappedNameW) or
    not LoadPEView(NativeUInt(Module), View) then Exit;
  if not ReadBackingNames(Module, Path, Mapped) then Exit;
  Handle := WinCreateFile(PWideChar(Path), 0,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
    nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if Handle = INVALID_HANDLE_VALUE then Exit;
  try
    if not CaptureBackingFileID(Handle, Candidate) then Exit;
    if not BackingImageUnchanged(Module, View, Path, Mapped) then Exit;
    Candidate.Base := NativeUInt(Module);
    Candidate.MappedNameHash := FoldWideHash(Mapped);
    Candidate.Valid := True;
    Identity := Candidate; // never publish partially captured data
    Result := True;
  finally WinCloseHandle(Handle); end;
end;

function SameBackingFile(const A, B: TSectionIdentity): Boolean;
var I: Integer;
begin
  Result := False;
  if A.FileIDKind <> B.FileIDKind then Exit;
  case A.FileIDKind of
    sfkFileID128:
      begin
        if A.VolumeSerial <> B.VolumeSerial then Exit;
        for I := 0 to 15 do
          if A.FileID128[I] <> B.FileID128[I] then Exit;
        Result := True;
      end;
    sfkLegacy64:
      Result := (A.VolumeSerial = B.VolumeSerial) and
        (A.LegacyFileIndex = B.LegacyFileIndex);
    sfkUnspecified:
      // Compatibility with pre-G synthetic rule fixtures. Live capture never
      // marks an unspecified file-identity representation as valid.
      Result := A.PathFileID = B.PathFileID;
  end;
end;

function SameBackingIdentity(const A, B: TSectionIdentity): Boolean;
begin
  Result := A.Valid and B.Valid and (A.Base = B.Base) and
    (A.MappedNameHash = B.MappedNameHash) and SameBackingFile(A, B);
end;

function SectionBackingCandidate(const Baseline, Current: TSectionIdentity;
  Confirmations: Integer; IndependentEvidence: Boolean): Boolean;
begin
  Result := Baseline.Valid and Current.Valid and
    (Baseline.Base = Current.Base) and
    (Baseline.FileIDKind = Current.FileIDKind) and
    not SameBackingIdentity(Baseline, Current) and
    (Confirmations >= 2) and IndependentEvidence;
end;

constructor TSectionBackingMonitor.Create;
begin inherited Create; Reset; end;

procedure TSectionBackingMonitor.ClearCandidate(Index: Integer);
begin
  FPending[Index] := Default(TSectionIdentity);
  FConfirmations[Index] := 0;
  FPendingSince[Index] := 0;
  FPendingTick[Index] := 0;
end;

procedure TSectionBackingMonitor.Reset;
var I: Integer;
begin
  FLastTick := 0;
  FLastEvidence := 0;
  FLastReport := 0;
  FHasScan := False;
  for I := 0 to 3 do
  begin
    FBaseline[I] := Default(TSectionIdentity);
    ClearCandidate(I);
  end;
end;

procedure TSectionBackingMonitor.AdvanceIdentityCandidate(Index: Integer;
  const Current: TSectionIdentity; Tick: UInt64);
begin
  if (FConfirmations[Index] > 0) and
    ((Tick < FPendingTick[Index]) or (Tick < FPendingSince[Index]) or
     (Tick - FPendingSince[Index] > BACKING_PENDING_MS)) then
    ClearCandidate(Index);
  if not SameBackingIdentity(FPending[Index], Current) then
  begin
    FPending[Index] := Current;
    FPendingSince[Index] := Tick;
    FPendingTick[Index] := Tick;
    FConfirmations[Index] := 1;
  end
  else if Tick > FPendingTick[Index] then
  begin
    if FConfirmations[Index] < 3 then Inc(FConfirmations[Index]);
    FPendingTick[Index] := Tick;
  end;
end;

procedure TSectionBackingMonitor.ReportIdentityCandidate(Index: Integer;
  const Current: TSectionIdentity; Tick: UInt64;
  var Detected: TDetectionKinds);
begin
  if SectionBackingCandidate(FBaseline[Index], Current,
    FConfirmations[Index], (FLastEvidence <> 0) and
    (Tick >= FLastEvidence) and
    (Tick - FLastEvidence <= BACKING_EVIDENCE_MS)) and
    ((FLastReport = 0) or (Tick < FLastReport) or
     (Tick - FLastReport >= BACKING_COOLDOWN_MS)) then
  begin
    Include(Detected, dkSectionBacking);
    FLastReport := Tick;
  end;
end;

procedure TSectionBackingMonitor.ObserveIdentity(Index: Integer;
  QueryOK, Baseline: Boolean; const Current: TSectionIdentity;
  Tick: UInt64; var Detected: TDetectionKinds);
begin
  if not QueryOK or not Current.Valid then
  begin ClearCandidate(Index); Exit; end;
  if not FBaseline[Index].Valid or Baseline or
    (FBaseline[Index].Base <> Current.Base) then
  begin
    FBaseline[Index] := Current;
    ClearCandidate(Index);
    Exit;
  end;
  // Precision changes are unknown, not file replacement. Do not overwrite
  // an approved full-ID baseline with a lower-precision fallback.
  if FBaseline[Index].FileIDKind <> Current.FileIDKind then
  begin ClearCandidate(Index); Exit; end;
  if SameBackingIdentity(FBaseline[Index], Current) then
  begin ClearCandidate(Index); Exit; end;
  AdvanceIdentityCandidate(Index, Current, Tick);
  ReportIdentityCandidate(Index, Current, Tick, Detected);
end;

procedure TSectionBackingMonitor.Examine(Baseline,
  ExternalAccess: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds);
var
  Modules: array[0..3] of HMODULE;
  Current: TSectionIdentity;
  I, J: Integer;
  Independent, QueryOK: Boolean;
begin
  if FHasScan and (Tick < FLastTick) then
  begin
    for I := 0 to 3 do ClearCandidate(I);
    FLastEvidence := 0;
    FLastReport := 0;
  end;
  if Baseline then
    for I := 0 to 3 do ClearCandidate(I);
  Independent := ExternalAccess or
    ((Detected * [dkModuleOrigin, dkFileSwap, dkPECodeIntegrity,
      dkImageCOWIntegrity]) <> []);
  if Independent then FLastEvidence := Tick;
  if FHasScan and (Tick >= FLastTick) and
     (Tick - FLastTick < BACKING_SCAN_MS) then Exit;
  FLastTick := Tick;
  FHasScan := True;
  Modules[0] := HMODULE(HInstance);
  Modules[1] := WinModule('ntdll.dll');
  Modules[2] := WinModule('kernel32.dll');
  Modules[3] := WinModule('kernelbase.dll');
  for I := 0 to 3 do
  begin
    Current := Default(TSectionIdentity);
    try
      QueryOK := CaptureSectionIdentity(Modules[I], Current);
      ObserveIdentity(I, QueryOK, Baseline, Current, Tick, Detected);
    except
      for J := 0 to 3 do ClearCandidate(J);
      raise;
    end;
  end;
end;

{$IFDEF NHW_NATIVE5G_TESTS}
{$I Cozy.NHW.Native5G.SectionBacking.inc}
{$ENDIF}

initialization
  BackingLock := TCriticalSection.Create;
finalization
  BackingLock.Free;
end.
