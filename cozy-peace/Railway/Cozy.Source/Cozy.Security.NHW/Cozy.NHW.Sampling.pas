unit Cozy.NHW.Sampling;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Types;

type
  TSamplingHealth = record
    WarningPending: Boolean;
    PreviousScanMS: UInt64;
    HasPreviousScan: Boolean;
    CurrentTick: UInt64;
    LastWarningTick: UInt64;
    HasReportedWarning: Boolean;
    HasCurrentTick: Boolean;
  end;

procedure UpdateSampling(var Health: TSamplingHealth;
  const Stats: TScanStats; IntervalMS: Cardinal; CurrentTick: UInt64);
procedure EmitPendingSamplingWarning(var Health: TSamplingHealth);

{$IFDEF NHW_FINAL12_TESTS}
function TestSamplingFinal12(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.Logging
{$IFDEF NHW_FINAL12_TESTS}
  , System.SysUtils
{$ENDIF}
  ;

const
  PAUSE_WARNING_EXTRA_MS = 6000;
  PAUSE_WARNING_COOLDOWN_MS = 30000;

function SamplingExceedsExpected(Value, Expected: UInt64): Boolean;
begin
  Result := False;
  if Value <= Expected then Exit;
  Result := Value - Expected > PAUSE_WARNING_EXTRA_MS;
end;

function SamplingWarningDue(const Health: TSamplingHealth): Boolean;
begin
  Result := False;
  if not Health.WarningPending or (Health.CurrentTick = 0) then Exit;
  if not Health.HasReportedWarning then Exit(True);
  if Health.CurrentTick < Health.LastWarningTick then Exit;
  Result := Health.CurrentTick - Health.LastWarningTick >= PAUSE_WARNING_COOLDOWN_MS;
end;

function BeginSamplingUpdate(var Health: TSamplingHealth;
  CurrentTick: UInt64): Boolean;
begin
  Result := False;
  if CurrentTick = 0 then
  begin
    Health.WarningPending := False;
    Health.HasPreviousScan := False;
    Health.HasCurrentTick := False;
    Health.CurrentTick := 0;
    Exit;
  end;
  // A known report from a previous clock epoch must not block forever.
  if Health.HasReportedWarning and (CurrentTick < Health.LastWarningTick) then
    Health.LastWarningTick := CurrentTick;
  if Health.HasCurrentTick then
  begin
    if CurrentTick < Health.CurrentTick then
    begin
      Health.CurrentTick := CurrentTick;
      Health.HasPreviousScan := False;
      Health.WarningPending := False;
      if Health.HasReportedWarning then Health.LastWarningTick := CurrentTick;
      Exit;
    end;
    if CurrentTick = Health.CurrentTick then Exit;
  end;
  Health.HasCurrentTick := True;
  Health.CurrentTick := CurrentTick;
  Result := True;
end;

function ExpectedSamplingMS(const Health: TSamplingHealth;
  IntervalMS: Cardinal): UInt64;
begin
  Result := UInt64(IntervalMS);
  if Health.HasPreviousScan and (Health.PreviousScanMS > Result) then
    Result := Health.PreviousScanMS;
end;

procedure RecordSamplingSample(var Health: TSamplingHealth;
  const Stats: TScanStats; ExpectedMS: UInt64);
begin
  // Compare differences after ordering; Expected+6000 could overflow UInt64.
  if SamplingExceedsExpected(Stats.GapMS, ExpectedMS) or
     SamplingExceedsExpected(Stats.ScanMS, ExpectedMS) then
    Health.WarningPending := True;
  Health.PreviousScanMS := Stats.ScanMS;
  Health.HasPreviousScan := True;
end;

procedure UpdateSampling(var Health: TSamplingHealth;
  const Stats: TScanStats; IntervalMS: Cardinal; CurrentTick: UInt64);
var ExpectedMS: UInt64;
begin
  if not BeginSamplingUpdate(Health, CurrentTick) then Exit;
  ExpectedMS := ExpectedSamplingMS(Health, IntervalMS);
  RecordSamplingSample(Health, Stats, ExpectedMS);
end;

procedure EmitPendingSamplingWarning(var Health: TSamplingHealth);
begin
  if not Health.WarningPending then Exit;
  // Keep the original spelling/output, but avoid duplicate warnings <30s apart.
  if SamplingWarningDue(Health) then
  begin
    ReportSamplingWarning;
    Health.LastWarningTick := Health.CurrentTick;
    Health.HasReportedWarning := True;
  end;
  Health.WarningPending := False;
end;

{$IFDEF NHW_FINAL12_TESTS}
{$I Cozy.NHW.Final12.Sampling.inc}
{$ENDIF}

end.
