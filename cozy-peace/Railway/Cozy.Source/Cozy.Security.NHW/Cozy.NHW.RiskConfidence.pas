unit Cozy.NHW.RiskConfidence;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  TRiskFamily = (rfExternal, rfThread, rfMemory, rfModule,
    rfIndependentObserver, rfTelemetryGap);
  TRiskFamilies = set of TRiskFamily;

  // v69: a score is an explanation of CORROBORATION, not proof of an attacker.
  TRiskConfidenceMonitor = class
  private
    FLastReport: UInt64;
    FLastTick: UInt64;
  public
    constructor Create;
    procedure Reset;
    function Evaluate(const Detected: TDetectionKinds;
      ExternalAccess, TraceLost, ObserverMismatch, IdentityValid: Boolean;
      Tick: UInt64; out Score: Integer;
      var OutKinds: TDetectionKinds;
      ObservationValid: Boolean = True): TRiskFamilies;
  end;

function ComputeEvidenceConfidence(Families: TRiskFamilies): Integer;
function IndependentFamilyCount(Families: TRiskFamilies): Integer;

implementation

function IndependentFamilyCount(Families: TRiskFamilies): Integer;
var F: TRiskFamily;
begin
  Result := 0;
  for F := Low(TRiskFamily) to High(TRiskFamily) do
    if (F <> rfTelemetryGap) and (F in Families) then Inc(Result);
end;

function ComputeEvidenceConfidence(Families: TRiskFamilies): Integer;
begin
  Result := 0;
  if rfExternal in Families then Inc(Result, 25);
  if rfThread in Families then Inc(Result, 23);
  if rfMemory in Families then Inc(Result, 28);
  if rfModule in Families then Inc(Result, 20);
  if rfIndependentObserver in Families then Inc(Result, 12);
  if rfTelemetryGap in Families then Dec(Result, 25);
  if Result < 0 then Result := 0;
  if Result > 100 then Result := 100;
end;

constructor TRiskConfidenceMonitor.Create;
begin inherited Create; Reset; end;

procedure TRiskConfidenceMonitor.Reset;
begin FLastReport := 0; FLastTick := 0; end;

function TRiskConfidenceMonitor.Evaluate(
  const Detected: TDetectionKinds;
  ExternalAccess, TraceLost, ObserverMismatch, IdentityValid: Boolean;
  Tick: UInt64; out Score: Integer;
  var OutKinds: TDetectionKinds; ObservationValid: Boolean): TRiskFamilies;
var
  Fresh, ClockValid: Boolean;
  Families: TRiskFamilies;

  procedure UpdateClockState;
  begin
    Fresh := False;
    ClockValid := Tick <> 0;
    if not ClockValid then Exit;
    if (FLastTick <> 0) and (Tick < FLastTick) then
    begin
      ClockValid := False;
      FLastTick := Tick;
      // Rebase an existing report cooldown rather than treating rollback
      // as permission to emit the same conclusion again.
      if FLastReport <> 0 then FLastReport := Tick;
    end
    else if Tick > FLastTick then
    begin
      FLastTick := Tick;
      Fresh := True;
    end;
  end;

  procedure CollectRiskFamilies;
  begin
    Families := [];
    if ExternalAccess or ((Detected * [dkProcess, dkThread,
      dkEscalation, dkTemporalHandleGraph]) <> []) then
      Include(Families, rfExternal);
    if (Detected * [dkPrivateThread, dkRemoteThread,
      dkExecutionProvenance, dkThreadStackOrigin,
      dkThreadProvenance, dkThreadSpawn]) <> [] then
      Include(Families, rfThread);
    if (Detected * [dkPECodeIntegrity, dkImageCOWIntegrity,
      dkExecutableLifecycle, dkTLSCallbackIntegrity,
      dkImportRedirect, dkPrivateExecRegion, dkWriteIntegrity]) <> [] then
      Include(Families, rfMemory);
    if (Detected * [dkModuleOrigin, dkSectionBacking,
      dkFileSwap, dkFileLink, dkFileAttestation,
      dkLoaderCrossView]) <> [] then
      Include(Families, rfModule);
    if ObserverMismatch then Include(Families, rfIndependentObserver);
    if TraceLost or not IdentityValid or not ObservationValid or
       not ClockValid then Include(Families, rfTelemetryGap);
  end;

  function ReportAllowed: Boolean;
  begin
    Result := Fresh and ClockValid and ObservationValid and
      (IndependentFamilyCount(Families) >= 3) and (Score >= 75) and
      not TraceLost and IdentityValid;
    if not Result then Exit;
    if FLastReport <> 0 then
    begin
      if Tick < FLastReport then Exit(False);
      if Tick - FLastReport < 60000 then Exit(False);
    end;
  end;
begin
  UpdateClockState;
  CollectRiskFamilies;
  Score := ComputeEvidenceConfidence(Families);
  Result := Families;
  if not ReportAllowed then Exit;
  Include(OutKinds, dkRiskConfidence);
  FLastReport := Tick;
end;

end.
