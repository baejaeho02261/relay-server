unit Cozy.NHW.BootTrust;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native;

type
  TBootTrustMonitor = class
  private
    FProtectionSeen: Boolean;
    FLastObservedEnabled: Boolean;
    FConfirmations: Byte;
    FLastConfirmTick: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(const Snapshot: TSecureBootSnapshot; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

function BootTrustDowngradeCandidate(ProtectionSeen, NativeValid,
  NativeEnabled: Boolean; Confirmations: Byte): Boolean;

implementation

const
  BOOT_TRUST_CONFIRMATIONS = 3;
  BOOT_TRUST_REPORT_MS = 60000;

function BootTrustDowngradeCandidate(ProtectionSeen, NativeValid,
  NativeEnabled: Boolean; Confirmations: Byte): Boolean;
begin
  Result := ProtectionSeen and NativeValid and (not NativeEnabled) and
    (Confirmations >= BOOT_TRUST_CONFIRMATIONS);
end;

constructor TBootTrustMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TBootTrustMonitor.ClearCandidate;
begin
  FConfirmations := 0;
  FLastConfirmTick := 0;
end;

procedure TBootTrustMonitor.Reset;
begin
  FProtectionSeen := False;
  FLastObservedEnabled := False;
  FLastReport := 0;
  ClearCandidate;
end;

procedure TBootTrustMonitor.Examine(const Snapshot: TSecureBootSnapshot;
  Tick: UInt64; var Detected: TDetectionKinds);
var CanReport: Boolean;
begin
  // Unsupported/unreadable is UNKNOWN, never a negative trust signal.
  if not Snapshot.NativeValid then
  begin
    ClearCandidate;
    Exit;
  end;
  if Snapshot.SecureBootEnabled then
  begin
    FProtectionSeen := True;
    FLastObservedEnabled := True;
    ClearCandidate;
    Exit;
  end;
  if not FProtectionSeen then
  begin
    // A machine that started with Secure Boot disabled is a platform policy
    // choice, not evidence of an attack. Remember it without reporting.
    FLastObservedEnabled := False;
    ClearCandidate;
    Exit;
  end;
  if FLastObservedEnabled then ClearCandidate;
  FLastObservedEnabled := False;
  if (FConfirmations = 0) or (Tick > FLastConfirmTick) then
  begin
    if FConfirmations < BOOT_TRUST_CONFIRMATIONS then Inc(FConfirmations);
    FLastConfirmTick := Tick;
  end;
  if not BootTrustDowngradeCandidate(FProtectionSeen, Snapshot.NativeValid,
       Snapshot.SecureBootEnabled, FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= BOOT_TRUST_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkBootTrust);
    FLastReport := Tick;
  end;
end;

end.
