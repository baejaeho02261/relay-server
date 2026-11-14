unit Cozy.NHW.KernelDMAIOMMUTrust;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.PlatformNative;

type
  TKernelDMAIOMMUTrustMonitor = class
  private
    FPrimed: Boolean;
    FBaselineProtected: Boolean;
    FBaselinePolicyRequiredDMA: Boolean;
    FConfirmations: Byte;
    FLastTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(const Platform: TPlatformSecuritySnapshot;
      Corroborated: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
  end;

function KernelDMAIOMMUTrustCandidate(BaselineProtected, CurrentDMAAvailable,
  FirmwareEnabled, PolicyDowngraded, Corroborated: Boolean;
  Confirmations: Byte): Boolean;

implementation

const
  DMA_CONFIRMATIONS = 3;
  DMA_REPORT_MS = 60000;
  REQUIRE_DMA_BIT = $00000002;

function KernelDMAIOMMUTrustCandidate(BaselineProtected, CurrentDMAAvailable,
  FirmwareEnabled, PolicyDowngraded, Corroborated: Boolean;
  Confirmations: Byte): Boolean;
begin
  Result := BaselineProtected and not CurrentDMAAvailable and
    (not FirmwareEnabled or PolicyDowngraded) and Corroborated and
    (Confirmations >= DMA_CONFIRMATIONS);
end;

constructor TKernelDMAIOMMUTrustMonitor.Create;
begin inherited Create; Reset; end;

procedure TKernelDMAIOMMUTrustMonitor.ClearCandidate;
begin FConfirmations := 0; FLastTick := 0; end;

procedure TKernelDMAIOMMUTrustMonitor.Reset;
begin FPrimed := False; FBaselineProtected := False;
  FBaselinePolicyRequiredDMA := False; FLastReport := 0; ClearCandidate; end;

procedure TKernelDMAIOMMUTrustMonitor.Examine(
  const Platform: TPlatformSecuritySnapshot; Corroborated: Boolean;
  Tick: UInt64; var Detected: TDetectionKinds);
var PolicyNow, PolicyDown, Candidate, CanReport: Boolean;
begin
  if not Platform.DeviceGuardValid or not Platform.DMAPropertyObserved then
  begin ClearCandidate; Exit; end;
  PolicyNow := Platform.RequirePlatformSecurityValid and
    ((Platform.RequirePlatformSecurityFeatures and REQUIRE_DMA_BIT) <> 0);
  if not FPrimed then
  begin
    FPrimed := True;
    FBaselineProtected := Platform.DMAProtectionAvailable and
      ((not Platform.VirtFirmwareValid) or Platform.VirtFirmwareEnabled);
    FBaselinePolicyRequiredDMA := PolicyNow;
    Exit;
  end;
  if not FBaselineProtected then Exit;
  PolicyDown := FBaselinePolicyRequiredDMA and
    Platform.RequirePlatformSecurityValid and not PolicyNow;
  Candidate := not Platform.DMAProtectionAvailable and Corroborated and
    ((Platform.VirtFirmwareValid and not Platform.VirtFirmwareEnabled) or
      PolicyDown);
  if not Candidate then begin ClearCandidate; Exit; end;
  if (FLastTick <> 0) and (Tick < FLastTick) then begin ClearCandidate; Exit; end;
  if Tick > FLastTick then begin if FConfirmations < DMA_CONFIRMATIONS then Inc(FConfirmations); FLastTick := Tick; end;
  if not KernelDMAIOMMUTrustCandidate(FBaselineProtected,
       Platform.DMAProtectionAvailable,
       (not Platform.VirtFirmwareValid) or Platform.VirtFirmwareEnabled,
       PolicyDown, Corroborated, FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= DMA_REPORT_MS);
  if CanReport then begin Include(Detected, dkKernelDMAIOMMUTrust); FLastReport := Tick; end;
end;

end.
