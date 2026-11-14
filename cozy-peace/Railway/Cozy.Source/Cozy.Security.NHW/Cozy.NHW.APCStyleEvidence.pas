unit Cozy.NHW.APCStyleEvidence;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Types, Cozy.NHW.Logging;

type
  // Passive capability/impact correlation, NOT an observation of APC execution.
  TAPCStyleEvidence = class
  private
    FContextTick, FLastReport, FLastExamine, FEvidenceFloor: UInt64;
    FHaveContext, FReported, FExamined, FHaveFloor: Boolean;
    procedure BreakContext(Tick: UInt64);
  public
    constructor Create;
    procedure Reset;
    procedure ObserveThreadRights(const Holder: TTargetHolder;
      NewlyObserved: Boolean; Baseline: Boolean; Tick: UInt64);
    procedure Examine(OwnTarget, ThreadSnapshotValid, Baseline: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function NHWAPCIndependentImpact(const Detected: TDetectionKinds): Boolean;
{$IFDEF NHW_NATIVE5J_TESTS}
function TestAPC5J(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation
{$IFDEF NHW_NATIVE5J_TESTS}
uses System.SysUtils;
{$ENDIF}

const
  APC_CONTEXT_WINDOW_MS = 10000;
  APC_REPORT_COOLDOWN_MS = 30000;

function NHWAPCIndependentImpact(const Detected: TDetectionKinds): Boolean;
begin
  Result := (Detected * [dkPECodeIntegrity, dkWriteIntegrity,
    dkPrivateExecRegion, dkImageCOWIntegrity, dkExecutableLifecycle,
    dkControlFlow, dkCodeProvenance]) <> [];
end;

constructor TAPCStyleEvidence.Create;
begin inherited Create; Reset; end;

procedure TAPCStyleEvidence.Reset;
begin
  FContextTick := 0; FLastReport := 0; FLastExamine := 0; FEvidenceFloor := 0;
  FHaveContext := False; FReported := False;
  FExamined := False; FHaveFloor := False;
end;

procedure TAPCStyleEvidence.BreakContext(Tick: UInt64);
begin
  FContextTick := 0;
  FHaveContext := False;
  FEvidenceFloor := Tick;
  FHaveFloor := True;
  // A baseline/failed observation is not permission to reset the cooldown.
end;

procedure TAPCStyleEvidence.ObserveThreadRights(
  const Holder: TTargetHolder; NewlyObserved, Baseline: Boolean; Tick: UInt64);
begin
  if Baseline then begin BreakContext(Tick); Exit; end;
  if not NewlyObserved or not Holder.IsThread or
     (Holder.PID <= 4) or (Holder.CreateTime = 0) then Exit;
  if (Holder.RightsUnion and THREAD_SET_CONTEXT_RIGHT) = 0 then Exit;
  if FExamined and (Tick < FLastExamine) then
  begin BreakContext(Tick); Exit; end;
  if FHaveFloor and (Tick <= FEvidenceFloor) then Exit;
  if FHaveContext and (Tick < FContextTick) then Exit;
  FContextTick := Tick;
  FHaveContext := True;
end;

function PrepareAPCObservation(Monitor: TAPCStyleEvidence;
  OwnTarget, ThreadSnapshotValid, Baseline: Boolean; Tick: UInt64): Boolean;
var Rollback: Boolean;
begin
  Result := False;
  Rollback := Monitor.FExamined and (Tick < Monitor.FLastExamine);
  Monitor.FLastExamine := Tick;
  Monitor.FExamined := True;
  if not OwnTarget or not ThreadSnapshotValid or Baseline or Rollback then
  begin Monitor.BreakContext(Tick); Exit; end;
  if not Monitor.FHaveContext then Exit;
  if (Tick < Monitor.FContextTick) or
     (Tick - Monitor.FContextTick > APC_CONTEXT_WINDOW_MS) then
  begin Monitor.BreakContext(Tick); Exit; end;
  Result := True;
end;

function APCReportAllowed(Monitor: TAPCStyleEvidence; Tick: UInt64;
  const Detected: TDetectionKinds): Boolean;
begin
  Result := NHWAPCIndependentImpact(Detected);
  if not Result then Exit;
  Result := not (Monitor.FReported and (Tick >= Monitor.FLastReport) and
    (Tick - Monitor.FLastReport < APC_REPORT_COOLDOWN_MS));
end;

procedure ReportAPCStyleEvidence(Monitor: TAPCStyleEvidence; Tick: UInt64;
  var Detected: TDetectionKinds);
begin
  Include(Detected, dkAPCStyleEvidence);
  Monitor.FLastReport := Tick;
  Monitor.FReported := True;
end;

procedure TAPCStyleEvidence.Examine(
  OwnTarget, ThreadSnapshotValid, Baseline: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
begin
  if not PrepareAPCObservation(Self, OwnTarget, ThreadSnapshotValid,
    Baseline, Tick) then Exit;
  if not APCReportAllowed(Self, Tick, Detected) then Exit;
  ReportAPCStyleEvidence(Self, Tick, Detected);
end;

{$IFDEF NHW_NATIVE5J_TESTS}
{$I Cozy.NHW.Native5J.APC.inc}
{$ENDIF}
end.
