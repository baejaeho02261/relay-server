unit Cozy.NHW.ETWFusion;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  Cozy.NHW.ETWTypes,
  Cozy.NHW.Lifecycle,
  Cozy.NHW.Logging;

type
  TKernelProcessStart = record
    Tick: UInt64;
    ParentPID: Cardinal;
  end;

  // Pure event fusion: no ETW session allocation and no file/network output.
  // Time proximity is an observation, not evidence of cause or exploitation.
  TETWFusion = class
  private
    FThreadBegins: TDictionary<Cardinal, UInt64>;
    FProcessBegins: TDictionary<Cardinal, TKernelProcessStart>;
    FGapTick: UInt64;
    FHaveGap: Boolean;
    FLastExternalTick: UInt64;
    FLastRelevantTick: UInt64;
    FLastFileWarning: UInt64;
    FLastRegistryWarning: UInt64;
    FLastFusionWarning: UInt64;
    procedure ExpireOld(Tick: UInt64);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(const Events: TKernelEventList;
      TargetPID: Cardinal; const Threads: TThreadSampleMap;
      ThreadsValid, ExternalAccess, Baseline, Overflow: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE10N_TESTS}
function TestETWFusion10N(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10N_TESTS}
uses System.SysUtils;
{$ENDIF}

const
  TRANSIENT_WINDOW_MS = 2000;
  PROCESS_LIFETIME_MS = 15000;
  FUSION_WINDOW_MS = 3000;
  OUTPUT_COOLDOWN_MS = 10000;
  STATE_RETENTION_MS = 20000;

constructor TETWFusion.Create;
begin
  inherited Create;
  FThreadBegins := TDictionary<Cardinal, UInt64>.Create;
  FProcessBegins := TDictionary<Cardinal, TKernelProcessStart>.Create;
  Reset;
end;

destructor TETWFusion.Destroy;
begin
  FProcessBegins.Free;
  FThreadBegins.Free;
  inherited Destroy;
end;

procedure TETWFusion.Reset;
begin
  FThreadBegins.Clear;
  FProcessBegins.Clear;
  FGapTick := 0;
  FHaveGap := False;
  FLastExternalTick := 0;
  FLastRelevantTick := 0;
  FLastFileWarning := 0;
  FLastRegistryWarning := 0;
  FLastFusionWarning := 0;
end;

procedure TETWFusion.ExpireOld(Tick: UInt64);
var
  ThreadKeys: TList<Cardinal>;
  ProcessKeys: TList<Cardinal>;
  Item: TPair<Cardinal, UInt64>;
  Pair: TPair<Cardinal, TKernelProcessStart>;
  K: Cardinal;
begin
  ThreadKeys := nil;
  ProcessKeys := nil;
  try
    ThreadKeys := TList<Cardinal>.Create;
    ProcessKeys := TList<Cardinal>.Create;
    for Item in FThreadBegins do
      if (Tick < Item.Value) or
         (Tick - Item.Value > STATE_RETENTION_MS) then
        ThreadKeys.Add(Item.Key);
    for Pair in FProcessBegins do
      if (Tick < Pair.Value.Tick) or
         (Tick - Pair.Value.Tick > STATE_RETENTION_MS) then
        ProcessKeys.Add(Pair.Key);
    for K in ThreadKeys do FThreadBegins.Remove(K);
    for K in ProcessKeys do FProcessBegins.Remove(K);
  finally
    ThreadKeys.Free;
    ProcessKeys.Free;
  end;
end;

procedure TETWFusion.Examine(const Events: TKernelEventList;
  TargetPID: Cardinal; const Threads: TThreadSampleMap;
  ThreadsValid, ExternalAccess, Baseline, Overflow: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  E: TKernelEvent;
  RelevantSeen, SnapshotComplete: Boolean;

  procedure ApplyThreadStart(const E: TKernelEvent);
  var
    Started: UInt64;
  begin
    if SnapshotComplete and (E.PID = TargetPID) and (E.ThreadID <> 0) then
    begin
      if not FThreadBegins.TryGetValue(E.ThreadID, Started) or
         (E.Tick > Started) then
        FThreadBegins.AddOrSetValue(E.ThreadID, E.Tick);
      RelevantSeen := True;
    end;
  end;

  procedure ApplyThreadEnd(const E: TKernelEvent);
  var
    Started: UInt64;
    AlreadyThread: Boolean;
  begin
    if SnapshotComplete and (E.PID = TargetPID) then
    begin
      RelevantSeen := True;
      if FThreadBegins.TryGetValue(E.ThreadID, Started) then
      begin
        AlreadyThread := Threads.ContainsKey(E.ThreadID);
        if (not AlreadyThread) and (E.Tick >= Started) and
           (E.Tick - Started <= TRANSIENT_WINDOW_MS) then
          Include(Detected, dkTransientThread);
        if E.Tick >= Started then FThreadBegins.Remove(E.ThreadID);
      end;
    end;
  end;

  procedure ApplyProcessStart(const E: TKernelEvent);
  var
    ProcStart: TKernelProcessStart;
  begin
    if E.ParentPID = TargetPID then
    begin
      if not FProcessBegins.TryGetValue(E.PID, ProcStart) or
         (E.Tick > ProcStart.Tick) then
      begin
        ProcStart.Tick := E.Tick;
        ProcStart.ParentPID := E.ParentPID;
        FProcessBegins.AddOrSetValue(E.PID, ProcStart);
      end;
      RelevantSeen := True;
    end;
  end;

  procedure ApplyProcessEnd(const E: TKernelEvent);
  var
    ProcStart: TKernelProcessStart;
  begin
    if FProcessBegins.TryGetValue(E.PID, ProcStart) then
    begin
      RelevantSeen := True;
      if (E.Tick >= ProcStart.Tick) and
         (E.Tick - ProcStart.Tick <= PROCESS_LIFETIME_MS) then
        Include(Detected, dkProcessLifetime);
      if E.Tick >= ProcStart.Tick then FProcessBegins.Remove(E.PID);
    end;
  end;

  procedure ReportCorrelatedActivity;
  begin
    if RelevantSeen then FLastRelevantTick := Tick;
    if (FLastRelevantTick > 0) and (FLastExternalTick > 0) and
       (Tick >= FLastRelevantTick) and
       (Tick >= FLastExternalTick) and
       (Tick - FLastRelevantTick <= FUSION_WINDOW_MS) and
       (Tick - FLastExternalTick <= FUSION_WINDOW_MS) and
       ((FLastFusionWarning = 0) or
        ((Tick >= FLastFusionWarning) and
         (Tick - FLastFusionWarning >= OUTPUT_COOLDOWN_MS))) then
    begin
      Include(Detected, dkEventFusion);
      FLastFusionWarning := Tick;
    end;
  end;

begin
  if Baseline then
  begin
    Reset;
    Exit;
  end;
  if Overflow then
  begin
    Include(Detected, dkTraceGap);
    FThreadBegins.Clear;
    FProcessBegins.Clear;
    FLastExternalTick := 0;
    FLastRelevantTick := 0;
    FGapTick := Tick;
    FHaveGap := True;
    Exit; // This batch straddles a known loss boundary; do not join it.
  end;
  SnapshotComplete := ThreadsValid and (Threads <> nil);
  if not SnapshotComplete then FThreadBegins.Clear;
  ExpireOld(Tick);
  RelevantSeen := False;
  if ExternalAccess then FLastExternalTick := Tick;

  if Events <> nil then
  for E in Events do
  begin
    if (E.Tick > Tick) or (FHaveGap and (E.Tick <= FGapTick)) then Continue;
    if E.Kind = keThreadStart then
    begin
      ApplyThreadStart(E);
    end
    else if E.Kind = keThreadEnd then
    begin
      ApplyThreadEnd(E);
    end
    else if E.Kind = keProcessStart then
    begin
      ApplyProcessStart(E);
    end
    else if E.Kind = keProcessEnd then
    begin
      ApplyProcessEnd(E);
    end
    else if E.Kind = keFileIO then
    begin
      RelevantSeen := True;
      if (FLastFileWarning = 0) or ((Tick >= FLastFileWarning) and
         (Tick - FLastFileWarning >= OUTPUT_COOLDOWN_MS)) then
      begin
        Include(Detected, dkKernelFileIO);
        FLastFileWarning := Tick;
      end;
    end
    else if E.Kind = keRegistryActivity then
    begin
      RelevantSeen := True;
      if (FLastRegistryWarning = 0) or
         ((Tick >= FLastRegistryWarning) and
          (Tick - FLastRegistryWarning >= OUTPUT_COOLDOWN_MS)) then
      begin
        Include(Detected, dkKernelRegistry);
        FLastRegistryWarning := Tick;
      end;
    end;
  end;

  ReportCorrelatedActivity;
  ExpireOld(Tick);
end;

{$IFDEF NHW_NATIVE10N_TESTS}
{$I Cozy.NHW.Native10N.ETWFusion.inc}
{$ENDIF}

end.
