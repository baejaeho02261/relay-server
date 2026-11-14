unit Cozy.NHW.KernelTrustDowngrade;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native;

type
  TKernelTrustDowngradeMonitor = class
  private
    FPrimed: Boolean;
    FBaselineOptions: Cardinal;
    FPendingMask: Cardinal;
    FConfirmations: Byte;
    FLastConfirmTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(const Snapshot: TCodeIntegritySnapshot; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function KernelTrustDowngradeMask(BaselineOptions,
  CurrentOptions: Cardinal): Cardinal;
function KernelTrustDowngradeCandidate(ChangeMask: Cardinal;
  Confirmations: Byte): Boolean;

implementation

const
  TRUST_DOWN_CONFIRMATIONS = 3;
  TRUST_DOWN_REPORT_MS = 60000;
  TRUST_UNSAFE_MASK = CODEINTEGRITY_OPTION_TESTSIGN or
    CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;

function KernelTrustDowngradeMask(BaselineOptions,
  CurrentOptions: Cardinal): Cardinal;
var Lost, GainedUnsafe: Cardinal;
begin
  Lost := 0;
  if ((BaselineOptions and CODEINTEGRITY_OPTION_ENABLED) <> 0) and
     ((CurrentOptions and CODEINTEGRITY_OPTION_ENABLED) = 0) then
    Lost := CODEINTEGRITY_OPTION_ENABLED;
  GainedUnsafe := (CurrentOptions and TRUST_UNSAFE_MASK) and
    not (BaselineOptions and TRUST_UNSAFE_MASK);
  Result := Lost or GainedUnsafe;
end;

function KernelTrustDowngradeCandidate(ChangeMask: Cardinal;
  Confirmations: Byte): Boolean;
begin
  Result := (ChangeMask <> 0) and
    (Confirmations >= TRUST_DOWN_CONFIRMATIONS);
end;

constructor TKernelTrustDowngradeMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TKernelTrustDowngradeMonitor.ClearCandidate;
begin
  FPendingMask := 0;
  FConfirmations := 0;
  FLastConfirmTick := 0;
end;

procedure TKernelTrustDowngradeMonitor.Reset;
begin
  FPrimed := False;
  FBaselineOptions := 0;
  FLastReport := 0;
  ClearCandidate;
end;

procedure TKernelTrustDowngradeMonitor.Examine(
  const Snapshot: TCodeIntegritySnapshot; Tick: UInt64;
  var Detected: TDetectionKinds);
var Mask: Cardinal; CanReport: Boolean;
begin
  if not Snapshot.NativeValid then
  begin
    ClearCandidate;
    Exit;
  end;
  if not FPrimed then
  begin
    FPrimed := True;
    FBaselineOptions := Snapshot.Options;
    ClearCandidate;
    Exit;
  end;
  Mask := KernelTrustDowngradeMask(FBaselineOptions, Snapshot.Options);
  if Mask = 0 then
  begin
    ClearCandidate;
    Exit;
  end;
  if (FPendingMask <> Mask) or
     ((FLastConfirmTick <> 0) and (Tick < FLastConfirmTick)) then
  begin
    FPendingMask := Mask;
    FConfirmations := 1;
    FLastConfirmTick := Tick;
    Exit;
  end;
  if Tick > FLastConfirmTick then
  begin
    if FConfirmations < TRUST_DOWN_CONFIRMATIONS then Inc(FConfirmations);
    FLastConfirmTick := Tick;
  end;
  if not KernelTrustDowngradeCandidate(Mask, FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= TRUST_DOWN_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkKernelTrustDowngrade);
    FLastReport := Tick;
  end;
end;

end.
