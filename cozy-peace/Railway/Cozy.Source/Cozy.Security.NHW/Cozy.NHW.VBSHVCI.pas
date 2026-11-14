unit Cozy.NHW.VBSHVCI;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.Logging,
  Cozy.NHW.KernelTrust.Native;

type
  TVBSHVCIMonitor = class
  private
    FHVCISeen: Boolean;
    FLastObservedEnabled: Boolean;
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

function HVCIRuntimeEnabled(const Snapshot: TCodeIntegritySnapshot): Boolean;
function HVCIDowngradeCandidate(ProtectionSeen, NativeValid,
  RuntimeEnabled: Boolean; Confirmations: Byte): Boolean;

implementation

const
  HVCI_CONFIRMATIONS = 3;
  HVCI_REPORT_MS = 60000;

function HVCIRuntimeEnabled(const Snapshot: TCodeIntegritySnapshot): Boolean;
begin
  Result := Snapshot.NativeValid and
    ((Snapshot.Options and CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) <> 0);
end;

function HVCIDowngradeCandidate(ProtectionSeen, NativeValid,
  RuntimeEnabled: Boolean; Confirmations: Byte): Boolean;
begin
  Result := ProtectionSeen and NativeValid and (not RuntimeEnabled) and
    (Confirmations >= HVCI_CONFIRMATIONS);
end;

constructor TVBSHVCIMonitor.Create;
begin inherited Create; Reset; end;

procedure TVBSHVCIMonitor.ClearCandidate;
begin
  FConfirmations := 0;
  FLastConfirmTick := 0;
end;

procedure TVBSHVCIMonitor.Reset;
begin
  FHVCISeen := False;
  FLastObservedEnabled := False;
  FLastReport := 0;
  ClearCandidate;
end;

procedure TVBSHVCIMonitor.Examine(const Snapshot: TCodeIntegritySnapshot;
  Tick: UInt64; var Detected: TDetectionKinds);
var Enabled, CanReport: Boolean;
begin
  if not Snapshot.NativeValid then
  begin
    ClearCandidate;
    Exit;
  end;
  Enabled := HVCIRuntimeEnabled(Snapshot);
  if Enabled then
  begin
    FHVCISeen := True;
    FLastObservedEnabled := True;
    ClearCandidate;
    Exit;
  end;
  if not FHVCISeen then
  begin
    // HVCI being disabled from startup is not an attack indication by itself.
    FLastObservedEnabled := False;
    ClearCandidate;
    Exit;
  end;
  if FLastObservedEnabled then ClearCandidate;
  FLastObservedEnabled := False;
  if (FConfirmations = 0) or (Tick > FLastConfirmTick) then
  begin
    if FConfirmations < HVCI_CONFIRMATIONS then Inc(FConfirmations);
    FLastConfirmTick := Tick;
  end;
  if not HVCIDowngradeCandidate(FHVCISeen, Snapshot.NativeValid, Enabled,
       FConfirmations) then Exit;
  CanReport := (FLastReport = 0) or (Tick < FLastReport) or
    (Tick - FLastReport >= HVCI_REPORT_MS);
  if CanReport then
  begin
    Include(Detected, dkVBSHVCI);
    FLastReport := Tick;
  end;
end;

end.
