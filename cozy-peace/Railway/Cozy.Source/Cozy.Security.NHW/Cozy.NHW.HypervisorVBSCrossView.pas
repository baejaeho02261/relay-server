unit Cozy.NHW.HypervisorVBSCrossView;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native,
  Cozy.NHW.KernelTrust.PlatformNative;

type
  THypervisorVBSCrossViewMonitor = class
  private
    FPrimed: Boolean;
    FBaselineStrong: Boolean;
    FPendingMask: Byte;
    FConfirmations: Byte;
    FLastTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(const Platform: TPlatformSecuritySnapshot;
      const CI: TCodeIntegritySnapshot; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function HypervisorVBSCrossViewMask(const Platform: TPlatformSecuritySnapshot;
  const CI: TCodeIntegritySnapshot; BaselineStrong: Boolean): Byte;
function HypervisorVBSCrossViewCandidate(Mask: Byte;
  Confirmations: Byte): Boolean;

implementation

const
  HV_VBS_STATUS = $01;
  HV_HYPERVISOR = $02;
  HV_FIRMWARE = $04;
  HV_HVCI = $08;
  HV_CONFIRMATIONS = 3;
  HV_REPORT_MS = 60000;

function CountBits(V: Byte): Integer;
begin
  Result := 0;
  while V <> 0 do begin Inc(Result); V := V and (V - 1); end;
end;

function StrongPlatform(const Platform: TPlatformSecuritySnapshot;
  const CI: TCodeIntegritySnapshot): Boolean;
begin
  Result := Platform.DeviceGuardValid and Platform.HypervisorViewValid and
    Platform.VirtFirmwareValid and CI.NativeValid and
    (Platform.VBSStatus = 2) and Platform.HypervisorPresent and
    Platform.VirtFirmwareEnabled and
    ((CI.Options and CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) <> 0);
end;

function HypervisorVBSCrossViewMask(const Platform: TPlatformSecuritySnapshot;
  const CI: TCodeIntegritySnapshot; BaselineStrong: Boolean): Byte;
begin
  Result := 0;
  if not BaselineStrong then Exit;
  if Platform.DeviceGuardValid and (Platform.VBSStatus <> 2) then
    Result := Result or HV_VBS_STATUS;
  if Platform.HypervisorViewValid and not Platform.HypervisorPresent then
    Result := Result or HV_HYPERVISOR;
  if Platform.VirtFirmwareValid and not Platform.VirtFirmwareEnabled then
    Result := Result or HV_FIRMWARE;
  if CI.NativeValid and
     ((CI.Options and CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) = 0) then
    Result := Result or HV_HVCI;
end;

function HypervisorVBSCrossViewCandidate(Mask: Byte;
  Confirmations: Byte): Boolean;
begin
  Result := (CountBits(Mask) >= 2) and (Confirmations >= HV_CONFIRMATIONS);
end;

constructor THypervisorVBSCrossViewMonitor.Create;
begin inherited Create; Reset; end;

procedure THypervisorVBSCrossViewMonitor.ClearCandidate;
begin FPendingMask := 0; FConfirmations := 0; FLastTick := 0; end;

procedure THypervisorVBSCrossViewMonitor.Reset;
begin FPrimed := False; FBaselineStrong := False; FLastReport := 0; ClearCandidate; end;

procedure THypervisorVBSCrossViewMonitor.Examine(
  const Platform: TPlatformSecuritySnapshot; const CI: TCodeIntegritySnapshot;
  Tick: UInt64; var Detected: TDetectionKinds);
var Mask: Byte; CanReport: Boolean;
begin
  if not (Platform.DeviceGuardValid and Platform.HypervisorViewValid and
          Platform.VirtFirmwareValid and CI.NativeValid) then
  begin ClearCandidate; Exit; end;
  if not FPrimed then
  begin FPrimed := True; FBaselineStrong := StrongPlatform(Platform, CI); Exit; end;
  if not FBaselineStrong then Exit;
  Mask := HypervisorVBSCrossViewMask(Platform, CI, True);
  if CountBits(Mask) < 2 then begin ClearCandidate; Exit; end;
  if (Mask <> FPendingMask) or ((FLastTick <> 0) and (Tick < FLastTick)) then
  begin FPendingMask := Mask; FConfirmations := 1; FLastTick := Tick; Exit; end;
  if Tick > FLastTick then begin if FConfirmations < HV_CONFIRMATIONS then Inc(FConfirmations); FLastTick := Tick; end;
  if not HypervisorVBSCrossViewCandidate(Mask, FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= HV_REPORT_MS);
  if CanReport then begin Include(Detected, dkHypervisorVBSCrossView); FLastReport := Tick; end;
end;

end.
