unit Cozy.NHW.UnwindConsistency;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, Cozy.NHW.Logging;

type
  // Confirmed cross-check of the current x64 static unwind table.
  // Runtime-registered dynamic/JIT function tables remain out of scope.
  TUnwindConsistencyMonitor = class
  private
    FPrimed: Boolean;
    FBaseHash: UInt64;
    FPendingHash: UInt64;
    FPendingTick: UInt64;
    FConfirmations: Integer;
    FLastTick: UInt64;
    FLastEvidence: UInt64;
    FLastReport: UInt64;
    procedure ClearCandidate;
  public
    constructor Create;
    procedure Reset;
    procedure Examine(Baseline, ExternalEvidence: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds);
  end;

function UnwindStructuralCandidate(BaseHash, ObservedHash: UInt64;
  Confirmations: Integer; IndependentEvidence: Boolean): Boolean;

{$IFDEF NHW_NATIVE5F_TESTS}
function TestUnwindHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SysUtils, Cozy.NHW.ExceptionNative, Cozy.NHW.ExceptionRules,
  Cozy.NHW.PEView, Cozy.NHW.NativeSafety;

const
  UNWIND_INTERVAL_MS = 8000;
  UNWIND_EVIDENCE_MS = 30000;
  UNWIND_COOLDOWN_MS = 60000;

{$IFDEF NHW_NATIVE5F_TESTS}
type TUnwindCaptureHook = function(out Snapshot: TExceptionImageState): Boolean;
var UnwindCaptureHook: TUnwindCaptureHook = nil;
{$ENDIF}

function ReadUnwindSnapshot(out Snapshot: TExceptionImageState): Boolean;
begin
  Snapshot := Default(TExceptionImageState);
{$IFDEF NHW_NATIVE5F_TESTS}
  if Assigned(UnwindCaptureHook) then Exit(UnwindCaptureHook(Snapshot));
{$ENDIF}
  Result := CaptureExceptionImage(Snapshot);
end;

function UnwindStructuralCandidate(BaseHash, ObservedHash: UInt64;
  Confirmations: Integer; IndependentEvidence: Boolean): Boolean;
begin
  Result := (BaseHash <> ObservedHash) and
    (Confirmations >= 2) and IndependentEvidence;
end;

constructor TUnwindConsistencyMonitor.Create;
begin inherited Create; Reset; end;

procedure TUnwindConsistencyMonitor.ClearCandidate;
begin
  FPendingHash := 0;
  FPendingTick := 0;
  FConfirmations := 0;
end;

procedure TUnwindConsistencyMonitor.Reset;
begin
  FPrimed := False;
  FBaseHash := 0;
  ClearCandidate;
  FLastTick := 0;
  FLastEvidence := 0;
  FLastReport := 0;
end;

procedure TUnwindConsistencyMonitor.Examine(Baseline,
  ExternalEvidence: Boolean; Tick: UInt64; var Detected: TDetectionKinds);
var
  Digest: UInt64;

  function PrepareInspection: Boolean;
  begin
    if (FLastTick <> 0) and (Tick < FLastTick) then
    begin
      ClearCandidate;
      FLastEvidence := 0;
      FLastReport := 0;
    end;
    // Expire OLD evidence before refreshing it with a new event. A new event
    // must not resurrect a candidate left over from an expired evidence epoch.
    if ((FLastEvidence <> 0) and
        NHWExpired(FLastEvidence, Tick, UNWIND_EVIDENCE_MS)) or
      ((FConfirmations <> 0) and
        NHWExpired(FPendingTick, Tick, UNWIND_EVIDENCE_MS)) or Baseline then
      ClearCandidate;
    if ExternalEvidence or ((Detected * [dkUnwind, dkFunctionTable,
      dkExceptionRange, dkPECodeIntegrity, dkImageCOWIntegrity]) <> []) then
      FLastEvidence := Tick;
    // Preserve the existing idle policy; original v33 inspection is unchanged.
    if FPrimed and not Baseline and
      ((FLastEvidence = 0) or (Tick < FLastEvidence) or
      (Tick - FLastEvidence > UNWIND_EVIDENCE_MS)) then
    begin
      ClearCandidate;
      Exit(False);
    end;
    if (FLastTick <> 0) and (Tick >= FLastTick) and
      (Tick - FLastTick < UNWIND_INTERVAL_MS) then Exit(False);
    FLastTick := Tick;
    Result := True;
  end;

  function TryCollectDigest: Boolean;
  var
    Snap: TExceptionImageState;
  begin
    try
      if not ReadUnwindSnapshot(Snap) then
      begin ClearCandidate; Exit(False); end;
      if (Snap.ImageBase <> NativeUInt(HInstance)) or
        not Snap.RangeValid or not Snap.UnwindValid or
        (Snap.TableCount = 0) or not Snap.HasUnwindSamples then
      begin ClearCandidate; Exit(False); end;
      Digest := PEHash(Snap.TableDigest, Snap.UnwindDigest);
      Digest := PEHash(Digest, Snap.RangeDigest);
    except
      ClearCandidate;
      raise;
    end;
    Result := True;
  end;

  procedure ApplyDigestObservation;
  begin
    if not FPrimed or Baseline then
    begin
      FPrimed := True;
      FBaseHash := Digest;
      ClearCandidate;
      Exit;
    end;
    if Digest = FBaseHash then
    begin ClearCandidate; Exit; end;
    if (FConfirmations > 0) and (FPendingHash = Digest) then
    begin
      if FConfirmations < 2 then Inc(FConfirmations);
    end
    else
    begin
      FPendingHash := Digest;
      FPendingTick := Tick;
      FConfirmations := 1;
    end;
    if UnwindStructuralCandidate(FBaseHash, Digest, FConfirmations,
      (FLastEvidence <> 0) and (Tick >= FLastEvidence) and
      (Tick - FLastEvidence <= UNWIND_EVIDENCE_MS)) and
      ((FLastReport = 0) or ((Tick >= FLastReport) and
      (Tick - FLastReport >= UNWIND_COOLDOWN_MS))) then
    begin
      Include(Detected, dkUnwindStructural);
      FLastReport := Tick;
    end;
  end;

begin
  if not PrepareInspection then Exit;
  if not TryCollectDigest then Exit;
  ApplyDigestObservation;
end;

{$IFDEF NHW_NATIVE5F_TESTS}
{$I Cozy.NHW.Native5F.Unwind.inc}
{$ENDIF}

end.
