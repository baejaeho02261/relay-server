unit Cozy.NHW.ProcessSnapshot;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TForensicSnapshot = record
    Tick: UInt64;
    ThreadCount: Cardinal;
    HandleCount: Cardinal;
    RegionCount: Cardinal;
    Captured: Boolean;
  end;

  // Bounded PSS metadata only: no VA_CLONE, dumps or disk writes.
  // The monitor instance is owned by the engine thread, not shared.
  TProcessSnapshotMonitor = class
  private
    FCaptureAttempted: Boolean;
    FPrevious: TForensicSnapshot;
    FLastCapture: UInt64;
    FFollowupUntil: UInt64;
    FLastReport: UInt64;
    FConfirmations: Integer;
    procedure BreakContinuity;
  public
    property CaptureAttempted: Boolean read FCaptureAttempted;
    constructor Create;
    procedure Reset;
    procedure Examine(SelfTarget, Baseline, IndependentEvidence: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds;
      FastFollowup: Boolean = False);
  end;

function SnapshotCountDelta(const A, B: TForensicSnapshot;
  Evidence: Boolean): Boolean;
// True means no ambiguous cleanup failure is latched; it does not mean
// a snapshot was successfully captured or that PSS is supported.
function ProcessSnapshotCleanupHealthy(out LastError: Cardinal): Boolean;
{$IFDEF NHW_NATIVE5D_TESTS}
function TestProcessSnapshotHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, System.SyncObjs, Cozy.NHW.WinPointers;

const
  PSS_CAPTURE_HANDLES = $00000004;
  PSS_CAPTURE_THREADS = $00000080;
  PSS_CAPTURE_VA_SPACE = $00000800;
  PSS_QUERY_VA_SPACE_INFORMATION = 3;
  PSS_QUERY_HANDLE_INFORMATION = 4;
  PSS_QUERY_THREAD_INFORMATION = 5;

type
  TPssCaptureSnapshot = function(Process: THandle; Flags, ContextFlags: Cardinal;
    out Snapshot: THandle): Cardinal; stdcall;
  TPssFreeSnapshot = function(Process: THandle; Snapshot: THandle): Cardinal; stdcall;
  TPssQuerySnapshot = function(Snapshot: THandle;
    InformationClass: Cardinal; Buffer: Pointer;
    BufferLength: Cardinal): Cardinal; stdcall;
  TPSSCapturedThreads = record
    ThreadsCaptured: Cardinal;
    ContextLength: Cardinal;
  end;

var
  PSSLock: TCriticalSection;
  CaptureSnapshotFn: TPssCaptureSnapshot = nil;
  FreeSnapshotFn: TPssFreeSnapshot = nil;
  QuerySnapshotFn: TPssQuerySnapshot = nil;
  PSSTried: Boolean = False;
  // One unresolved descriptor at most. After an ambiguous cleanup failure
  // stop this sensor; do not repeatedly free a possibly freed descriptor.
  // Other sensors continue. Reset does NOT clear this process-lifetime latch.
  PSSCleanupUncertain: Boolean = False;
  PSSUncertainSnapshot: THandle = 0;
  PSSLastError: Cardinal = 0;

function ProcessSnapshotCleanupHealthy(out LastError: Cardinal): Boolean;
begin
  PSSLock.Acquire;
  try
    LastError := PSSLastError;
    Result := not PSSCleanupUncertain and (PSSUncertainSnapshot = 0);
  finally
    PSSLock.Release;
  end;
end;

procedure ResolvePSSLocked;
var
  M: HMODULE;
  C: TPssCaptureSnapshot;
  F: TPssFreeSnapshot;
  Q: TPssQuerySnapshot;
begin
  if PSSTried then Exit;
  M := WinModule('kernel32.dll');
  if M = 0 then Exit;
  C := TPssCaptureSnapshot(WinExport(M, 'PssCaptureSnapshot'));
  F := TPssFreeSnapshot(WinExport(M, 'PssFreeSnapshot'));
  Q := TPssQuerySnapshot(WinExport(M, 'PssQuerySnapshot'));
  if not Assigned(C) or not Assigned(F) or not Assigned(Q) then Exit;
  CaptureSnapshotFn := C;
  FreeSnapshotFn := F;
  QuerySnapshotFn := Q;
  PSSTried := True;
end;

function CaptureSnapshotMetadata(Tick: UInt64;
  out Current: TForensicSnapshot; Attempted: PBoolean = nil): Boolean;
var
  Snapshot: THandle;
  Threads: TPSSCapturedThreads;
  Handles, Regions, Status, FreeStatus: Cardinal;
  Valid: Boolean;

  function AcquireSnapshotDescriptor: Boolean;
  begin
    Result := False;
    if PSSCleanupUncertain then Exit;
    ResolvePSSLocked;
    if not Assigned(CaptureSnapshotFn) or not Assigned(FreeSnapshotFn) or
       not Assigned(QuerySnapshotFn) then Exit;
    PSSLastError := 0;
    Snapshot := 0;
    if Attempted <> nil then Attempted^ := True;
    Status := CaptureSnapshotFn(WinCurrentProcess,
      PSS_CAPTURE_HANDLES or PSS_CAPTURE_THREADS or PSS_CAPTURE_VA_SPACE,
      0, Snapshot);
    if Status <> ERROR_SUCCESS then
    begin
      PSSLastError := Status;
      Exit;
    end;
    if Snapshot = 0 then
    begin
      PSSLastError := ERROR_INVALID_HANDLE;
      Exit;
    end;
    Result := True;
  end;

  procedure QuerySnapshotCounts(out Valid: Boolean);
  begin
    Status := QuerySnapshotFn(Snapshot, PSS_QUERY_THREAD_INFORMATION,
      @Threads, SizeOf(Threads));
    if Status = ERROR_SUCCESS then
      Status := QuerySnapshotFn(Snapshot, PSS_QUERY_HANDLE_INFORMATION,
        @Handles, SizeOf(Handles));
    if Status = ERROR_SUCCESS then
      Status := QuerySnapshotFn(Snapshot, PSS_QUERY_VA_SPACE_INFORMATION,
        @Regions, SizeOf(Regions));
    // A current-process capture contains at least its calling thread
    // and address space. Success with unwritten zero counts is incomplete.
    if (Status = ERROR_SUCCESS) and
       ((Threads.ThreadsCaptured = 0) or (Regions = 0)) then
      Status := ERROR_INVALID_DATA;
    PSSLastError := Status;
    Valid := Status = ERROR_SUCCESS;
  end;

  procedure ReleaseSnapshotDescriptor;
  begin
    // Close exactly once. PssFreeSnapshot does not protect against
    // concurrent use, and a repeated free of a freed descriptor is undefined.
    try
      FreeStatus := FreeSnapshotFn(WinCurrentProcess, Snapshot);
    finally
      if FreeStatus <> ERROR_SUCCESS then
      begin
        PSSLastError := FreeStatus;
        PSSUncertainSnapshot := Snapshot;
        PSSCleanupUncertain := True;
      end;
    end;
  end;

begin
  Result := False;
  Current := Default(TForensicSnapshot);
  if Attempted <> nil then Attempted^ := False;
  PSSLock.Acquire;
  try
    if not AcquireSnapshotDescriptor then Exit;
    Threads := Default(TPSSCapturedThreads);
    Handles := 0;
    Regions := 0;
    // Valid is assigned on every normal path through the query block.
    // An exception propagates after cleanup and never reaches its read.
    FreeStatus := ERROR_GEN_FAILURE;
    try
      QuerySnapshotCounts(Valid);
    finally
      ReleaseSnapshotDescriptor;
    end;
    if not Valid or (FreeStatus <> ERROR_SUCCESS) then Exit;
    Current.Tick := Tick;
    Current.ThreadCount := Threads.ThreadsCaptured;
    Current.HandleCount := Handles;
    Current.RegionCount := Regions;
    Current.Captured := True;
    Result := True;
  finally
    PSSLock.Release;
  end;
end;

function SnapshotCountDelta(const A, B: TForensicSnapshot;
  Evidence: Boolean): Boolean;
begin
  Result := A.Captured and B.Captured and Evidence and
    ((A.ThreadCount <> B.ThreadCount) or
     (A.RegionCount <> B.RegionCount) or
     (UInt64(A.HandleCount) + 12 < UInt64(B.HandleCount)) or
     (UInt64(B.HandleCount) + 12 < UInt64(A.HandleCount)));
end;

constructor TProcessSnapshotMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TProcessSnapshotMonitor.BreakContinuity;
begin
  FPrevious := Default(TForensicSnapshot);
  FConfirmations := 0;
end;

procedure TProcessSnapshotMonitor.Reset;
begin
  FCaptureAttempted := False;
  BreakContinuity;
  FLastCapture := 0;
  FFollowupUntil := 0;
  FLastReport := 0;
end;

procedure TProcessSnapshotMonitor.Examine(SelfTarget, Baseline,
  IndependentEvidence: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds; FastFollowup: Boolean);
var
  Current: TForensicSnapshot;
  Cooldown: UInt64;
begin
  FCaptureAttempted := False;
  if not SelfTarget then
  begin
    BreakContinuity;
    FFollowupUntil := 0;
    Exit;
  end;
  if (FLastCapture <> 0) and (Tick < FLastCapture) then Reset;
  if IndependentEvidence then
  begin
    if Tick > High(UInt64) - 15000 then FFollowupUntil := High(UInt64)
    else FFollowupUntil := Tick + 15000;
  end;
  if not Baseline and (FFollowupUntil < Tick) then
  begin
    BreakContinuity;
    Exit;
  end;
  Cooldown := 6000;
  if FastFollowup then Cooldown := 1500;
  if (FLastCapture <> 0) and (Tick - FLastCapture < Cooldown) then Exit;
  FLastCapture := Tick;
  try
    if not CaptureSnapshotMetadata(Tick, Current, @FCaptureAttempted) then
    begin
      BreakContinuity;
      Exit;
    end;
  except
    BreakContinuity;
    raise; // Preserve the engine's existing sensor fault accounting.
  end;
  if Baseline then FConfirmations := 0
  else if SnapshotCountDelta(FPrevious, Current,
    IndependentEvidence or (FFollowupUntil >= Tick)) then
  begin
    if FConfirmations < 2 then Inc(FConfirmations);
  end
  else FConfirmations := 0;
  if (FConfirmations >= 2) and
     ((FLastReport = 0) or
      ((Tick >= FLastReport) and (Tick - FLastReport >= 60000))) then
  begin
    Include(Detected, dkProcessSnapshot);
    FLastReport := Tick;
  end;
  FPrevious := Current;
end;

{$IFDEF NHW_NATIVE5D_TESTS}
{$I Cozy.NHW.Native5D.ProcessSnapshot.inc}
{$ENDIF}

initialization
  PSSLock := TCriticalSection.Create;
finalization
  // Do not retry an ambiguous free during unit teardown. No new capture
  // occurred after the latch; the process will reclaim remaining resources.
  PSSLock.Free;
end.
