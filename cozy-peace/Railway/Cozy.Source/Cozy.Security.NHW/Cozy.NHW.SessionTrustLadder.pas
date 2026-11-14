unit Cozy.NHW.SessionTrustLadder;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Cozy.NHW.Logging;

type
  TKernelSessionTrust = (kstNormal, kstGuarded, kstDegraded, kstUntrusted);

  TSessionTrustLadderMonitor = class
  private
    FFamilyTick: array[0..5] of UInt64;
    FState: TKernelSessionTrust;
    FPendingState: TKernelSessionTrust;
    FConfirmations: Byte;
    FLastTick: UInt64;
    FLastReport: UInt64;
    procedure ObserveFamilies(const Kinds: TDetectionKinds; Tick: UInt64);
    function FreshFamilyMask(Tick: UInt64): Byte;
  public
    constructor Create;
    procedure Reset;
    procedure Observe(const Kinds: TDetectionKinds; Tick: UInt64;
      var Detected: TDetectionKinds);
    property State: TKernelSessionTrust read FState;
  end;

function DesiredKernelSessionTrust(FamilyMask: Byte): TKernelSessionTrust;

implementation

const
  STF_BOOT = $01;
  STF_DRIVER = $02;
  STF_VIEW = $04;
  STF_INTEGRITY = $08;
  STF_MAPPING = $10;
  STF_TELEMETRY = $20;
  SESSION_EVAL_MS = 5000;
  SESSION_EVIDENCE_MS = 60000;
  SESSION_RECOVERY_MS = 120000;
  SESSION_UP_CONFIRMATIONS = 2;
  SESSION_REPORT_MS = 60000;

function BitCount8(V: Byte): Integer;
begin
  Result := 0;
  while V <> 0 do
  begin
    Inc(Result);
    V := V and (V - 1);
  end;
end;

function DesiredKernelSessionTrust(FamilyMask: Byte): TKernelSessionTrust;
var N: Integer;
begin
  N := BitCount8(FamilyMask);
  if (((FamilyMask and STF_MAPPING) <> 0) and (N >= 2)) or (N >= 3) then
    Exit(kstUntrusted);
  if N >= 2 then Exit(kstDegraded);
  if N = 1 then Exit(kstGuarded);
  Result := kstNormal;
end;

constructor TSessionTrustLadderMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TSessionTrustLadderMonitor.Reset;
begin
  FillChar(FFamilyTick, SizeOf(FFamilyTick), 0);
  FState := kstNormal;
  FPendingState := kstNormal;
  FConfirmations := 0;
  FLastTick := 0;
  FLastReport := 0;
end;

procedure TSessionTrustLadderMonitor.ObserveFamilies(
  const Kinds: TDetectionKinds; Tick: UInt64);
begin
  if (Kinds * [dkBootTrust, dkVBSHVCI, dkBootAttestationContinuity,
      dkHypervisorVBSCrossView]) <> [] then
    FFamilyTick[0] := Tick;
  if (Kinds * [dkVulnerableDriver, dkDriverTimelineKernel,
      dkDriverLoadProvenance, dkDriverServiceTimeline]) <> [] then
    FFamilyTick[1] := Tick;
  if (Kinds * [dkDriverIdentity, dkDriverCrossView,
      dkSystemViewDisagreement]) <> [] then
    FFamilyTick[2] := Tick;
  if (Kinds * [dkKernelTrustDowngrade, dkCodeIntegrityPolicy,
      dkCodeIntegrityEventCorrelation, dkDriverSignerAttestation,
      dkKernelDMAIOMMUTrust]) <> [] then
    FFamilyTick[3] := Tick;
  if dkKernelMappingEvidence in Kinds then FFamilyTick[4] := Tick;
  if dkKernelTelemetryGap in Kinds then FFamilyTick[5] := Tick;
end;

function TSessionTrustLadderMonitor.FreshFamilyMask(Tick: UInt64): Byte;
var I: Integer;
begin
  Result := 0;
  for I := 0 to 5 do
    if (FFamilyTick[I] <> 0) and (Tick >= FFamilyTick[I]) and
       (Tick - FFamilyTick[I] <= SESSION_EVIDENCE_MS) then
      Result := Result or Byte(1 shl I);
end;

procedure TSessionTrustLadderMonitor.Observe(const Kinds: TDetectionKinds;
  Tick: UInt64; var Detected: TDetectionKinds);
var
  Mask: Byte;
  Desired: TKernelSessionTrust;
  I: Integer;
  AnyRecent, CanReport: Boolean;
begin
  ObserveFamilies(Kinds, Tick);
  if FLastTick <> 0 then
  begin
    if Tick < FLastTick then
    begin
      Reset;
      FLastTick := Tick;
      Exit;
    end;
    if Tick - FLastTick < SESSION_EVAL_MS then Exit;
  end;
  FLastTick := Tick;
  Mask := FreshFamilyMask(Tick);
  Desired := DesiredKernelSessionTrust(Mask);

  if Ord(Desired) > Ord(FState) then
  begin
    if FPendingState <> Desired then
    begin
      FPendingState := Desired;
      FConfirmations := 1;
    end
    else if FConfirmations < SESSION_UP_CONFIRMATIONS then
      Inc(FConfirmations);
    if FConfirmations >= SESSION_UP_CONFIRMATIONS then
    begin
      FState := Desired;
      FPendingState := FState;
      FConfirmations := 0;
    end;
  end
  else
  begin
    FPendingState := FState;
    FConfirmations := 0;
    if Desired = kstNormal then
    begin
      AnyRecent := False;
      for I := 0 to 5 do
        if (FFamilyTick[I] <> 0) and (Tick >= FFamilyTick[I]) and
           (Tick - FFamilyTick[I] <= SESSION_RECOVERY_MS) then
        begin
          AnyRecent := True;
          Break;
        end;
      if not AnyRecent then FState := kstNormal;
    end;
  end;

  if FState = kstUntrusted then
  begin
    CanReport := (FLastReport = 0) or (Tick < FLastReport) or
      (Tick - FLastReport >= SESSION_REPORT_MS);
    if CanReport then
    begin
      Include(Detected, dkSessionTrustUntrusted);
      FLastReport := Tick;
    end;
  end;
end;

end.
