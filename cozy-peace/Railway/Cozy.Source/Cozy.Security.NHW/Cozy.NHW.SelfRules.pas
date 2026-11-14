unit Cozy.NHW.SelfRules;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

type
  // A stable, previously unseen value must be observed twice before reporting.
  // A failed query preserves the baseline but breaks candidate continuity.
  TStableFingerprint = record
    HasBaseline: Boolean;
    Baseline: UInt64;
    Candidate: UInt64;
    CandidateCount: Integer;
    AlreadyReported: Boolean;
  end;

function ObserveFingerprint(var State: TStableFingerprint;
  Value: UInt64; Valid: Boolean): Boolean;
function WithinBoundaryWindow(NowTick, EarlierTick: UInt64;
  WindowMS: Cardinal): Boolean;

{$IFDEF NHW_NATIVE10P_TESTS}
function TestSelfRules10P(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10P_TESTS}
uses System.SysUtils;
{$ENDIF}

procedure BreakFingerprintCandidate(var State: TStableFingerprint);
begin
  State.CandidateCount := 0;
  if not State.AlreadyReported then State.Candidate := State.Baseline;
end;

procedure EstablishFingerprintBaseline(var State: TStableFingerprint;
  Value: UInt64);
begin
  State.HasBaseline := True;
  State.Baseline := Value;
  State.Candidate := Value;
  State.CandidateCount := 0;
  State.AlreadyReported := False;
end;

procedure ObserveFingerprintBaselineValue(var State: TStableFingerprint;
  Value: UInt64);
begin
  State.Candidate := Value;
  State.CandidateCount := 0;
  State.AlreadyReported := False;
end;

function ObserveChangedFingerprint(var State: TStableFingerprint;
  Value: UInt64): Boolean;
begin
  Result := False;
  if State.Candidate <> Value then
  begin
    State.Candidate := Value;
    State.CandidateCount := 1;
    State.AlreadyReported := False;
    Exit;
  end;
  if State.CandidateCount < 3 then Inc(State.CandidateCount);
  if (State.CandidateCount >= 2) and not State.AlreadyReported then
  begin
    State.AlreadyReported := True;
    Result := True;
  end;
end;

function ObserveFingerprint(var State: TStableFingerprint;
  Value: UInt64; Valid: Boolean): Boolean;
begin
  Result := False;
  if not Valid then
  begin
    BreakFingerprintCandidate(State);
    Exit;
  end;
  if not State.HasBaseline then
  begin
    EstablishFingerprintBaseline(State, Value);
    Exit;
  end;
  if Value = State.Baseline then
  begin
    ObserveFingerprintBaselineValue(State, Value);
    Exit;
  end;
  Result := ObserveChangedFingerprint(State, Value);
end;

function WithinBoundaryWindow(NowTick, EarlierTick: UInt64;
  WindowMS: Cardinal): Boolean;
begin
  Result := (EarlierTick <> 0) and (NowTick >= EarlierTick) and
    (NowTick - EarlierTick <= WindowMS);
end;

{$IFDEF NHW_NATIVE10P_TESTS}
{$I Cozy.NHW.Native10P.SelfRules.inc}
{$ENDIF}

end.
