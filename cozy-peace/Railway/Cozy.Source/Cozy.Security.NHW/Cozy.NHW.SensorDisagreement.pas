unit Cozy.NHW.SensorDisagreement;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

type
  TSensorDisagreementKind = (sdUnknown, sdConcordant,
    sdCoverageGap, sdUncorroborated);
  TSensorDisagreementState = record
    Tick: UInt64;
    Kind: TSensorDisagreementKind;
    Consecutive: Cardinal;
    LastWarningTick: UInt64;
  end;

  // v97: differences between sampled observations are not by themselves
  // evidence of injection, tampering, or malicious intent.
  TSensorDisagreement = class
  private
    FState: TSensorDisagreementState;
    FHasObservation: Boolean;
  public
    constructor Create;
    procedure Reset;
    procedure Observe(IdentityValid, ThreadsValid,
      TraceAvailable, TraceLost, ObservedETW,
      IndependentActivity: Boolean; Tick: UInt64);
    property State: TSensorDisagreementState read FState;
  end;

function NHWDisagreementKind(IdentityValid, ThreadsValid,
  TraceAvailable, TraceLost, ObservedETW,
  IndependentActivity: Boolean): TSensorDisagreementKind;

{$IFDEF NHW_NATIVE10O_TESTS}
function TestSensorDisagreement10O(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10O_TESTS}
uses System.SysUtils;
{$ENDIF}

const
  DISAGREEMENT_MAX_GAP_MS = UInt64(30000);

function NHWDisagreementKind(IdentityValid, ThreadsValid,
  TraceAvailable, TraceLost, ObservedETW,
  IndependentActivity: Boolean): TSensorDisagreementKind;
begin
  Result := sdUnknown;
  if not IdentityValid or not ThreadsValid or
     not TraceAvailable then Exit;
  if TraceLost then Exit(sdCoverageGap);
  if IndependentActivity and not ObservedETW then
    Exit(sdUncorroborated);
  Result := sdConcordant;
end;

constructor TSensorDisagreement.Create;
begin inherited Create; Reset; end;

procedure TSensorDisagreement.Reset;
begin
  FState := Default(TSensorDisagreementState);
  FHasObservation := False;
end;

function HandleDisagreementBoundary(Monitor: TSensorDisagreement;
  K: TSensorDisagreementKind; Tick: UInt64): Boolean;
begin
  Result := False;
  if Monitor.FHasObservation and (Tick < Monitor.FState.Tick) then
  begin
    Monitor.Reset;
    Monitor.FState.Tick := Tick;
    Monitor.FHasObservation := True;
    Result := True;
    Exit; // backwards clock is an unknown boundary, not a confirmation
  end;
  if Monitor.FHasObservation and (Tick = Monitor.FState.Tick) then
  begin
    // Duplicates cannot confirm. Conflicting/failed duplicates also must not
    // preserve a sequence which no longer has continuous valid coverage.
    if (K <> Monitor.FState.Kind) or (K in [sdUnknown, sdCoverageGap]) then
    begin
      Monitor.FState.Consecutive := 0;
      if K in [sdUnknown, sdCoverageGap] then Monitor.FState.Kind := K
      else Monitor.FState.Kind := sdUnknown;
    end;
    Result := True;
    Exit;
  end;
end;

function DisagreementContinuous(Monitor: TSensorDisagreement;
  K: TSensorDisagreementKind; Tick: UInt64): Boolean;
begin
  Result := Monitor.FHasObservation and
    (Tick - Monitor.FState.Tick <= DISAGREEMENT_MAX_GAP_MS) and
    (K = Monitor.FState.Kind);
end;

procedure ApplyDisagreementObservation(Monitor: TSensorDisagreement;
  K: TSensorDisagreementKind; Tick: UInt64; Continuous: Boolean);
begin
  if K in [sdUnknown, sdCoverageGap] then Monitor.FState.Consecutive := 0
  else if Continuous then
  begin
    if Monitor.FState.Consecutive < High(Cardinal) then
      Inc(Monitor.FState.Consecutive);
  end
  else
    Monitor.FState.Consecutive := 1;
  Monitor.FState.Tick := Tick;
  Monitor.FState.Kind := K;
  Monitor.FHasObservation := True;
end;

procedure TSensorDisagreement.Observe(IdentityValid, ThreadsValid,
  TraceAvailable, TraceLost, ObservedETW,
  IndependentActivity: Boolean; Tick: UInt64);
var
  K: TSensorDisagreementKind;
  Continuous: Boolean;
begin
  K := NHWDisagreementKind(IdentityValid, ThreadsValid,
    TraceAvailable, TraceLost, ObservedETW, IndependentActivity);
  if HandleDisagreementBoundary(Self, K, Tick) then Exit;
  Continuous := DisagreementContinuous(Self, K, Tick);
  ApplyDisagreementObservation(Self, K, Tick, Continuous);
  // Metadata only; no additional detector or console output.
end;

{$IFDEF NHW_NATIVE10O_TESTS}
  {$I Cozy.NHW.Native10O.SensorDisagreement.inc}
{$ENDIF}

end.
