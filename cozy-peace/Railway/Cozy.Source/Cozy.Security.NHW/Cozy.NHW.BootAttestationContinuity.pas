unit Cozy.NHW.BootAttestationContinuity;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native;

type
  TBootAttestationContinuityMonitor = class
  private
    FPrimed: Boolean;
    FBaseline: TBootIdentity;
    FPending: TBootIdentity;
    FConfirmations: Byte;
    FLastConfirmTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(IdentityValid: Boolean; const Identity: TBootIdentity;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function SameBootIdentity(const A, B: TBootIdentity): Boolean;
function BootAttestationContinuityCandidate(const BaselineIdentity,
  CurrentIdentity: TBootIdentity; Confirmations: Byte): Boolean;

implementation

const
  BOOT_ATTEST_CONFIRMATIONS = 3;
  BOOT_ATTEST_REPORT_MS = 60000;

function SameBootIdentity(const A, B: TBootIdentity): Boolean;
begin
  Result := (A.LowPart = B.LowPart) and (A.HighPart = B.HighPart);
end;

function BootAttestationContinuityCandidate(const BaselineIdentity,
  CurrentIdentity: TBootIdentity; Confirmations: Byte): Boolean;
begin
  Result := ((BaselineIdentity.LowPart <> 0) or
    (BaselineIdentity.HighPart <> 0)) and
    ((CurrentIdentity.LowPart <> 0) or (CurrentIdentity.HighPart <> 0)) and
    not SameBootIdentity(BaselineIdentity, CurrentIdentity) and
    (Confirmations >= BOOT_ATTEST_CONFIRMATIONS);
end;

constructor TBootAttestationContinuityMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TBootAttestationContinuityMonitor.ClearCandidate;
begin
  FPending := Default(TBootIdentity);
  FConfirmations := 0;
  FLastConfirmTick := 0;
end;

procedure TBootAttestationContinuityMonitor.Reset;
begin
  FPrimed := False;
  FBaseline := Default(TBootIdentity);
  FLastReport := 0;
  ClearCandidate;
end;

procedure TBootAttestationContinuityMonitor.Examine(IdentityValid: Boolean;
  const Identity: TBootIdentity; Tick: UInt64; var Detected: TDetectionKinds);
var CanReport: Boolean;
begin
  if not IdentityValid or
     ((Identity.LowPart = 0) and (Identity.HighPart = 0)) then
  begin
    ClearCandidate;
    Exit;
  end;
  if not FPrimed then
  begin
    FPrimed := True;
    FBaseline := Identity;
    ClearCandidate;
    Exit;
  end;
  if SameBootIdentity(Identity, FBaseline) then
  begin
    ClearCandidate;
    Exit;
  end;
  if not SameBootIdentity(FPending, Identity) or
     ((FLastConfirmTick <> 0) and (Tick < FLastConfirmTick)) then
  begin
    FPending := Identity;
    FConfirmations := 1;
    FLastConfirmTick := Tick;
    Exit;
  end;
  if Tick > FLastConfirmTick then
  begin
    if FConfirmations < BOOT_ATTEST_CONFIRMATIONS then Inc(FConfirmations);
    FLastConfirmTick := Tick;
  end;
  if not BootAttestationContinuityCandidate(FBaseline, Identity,
       FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= BOOT_ATTEST_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkBootAttestationContinuity);
    FLastReport := Tick;
  end;
end;

end.
