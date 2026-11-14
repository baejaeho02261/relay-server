unit Cozy.NHW.InjectionEvidence;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.Logging;

type
  // v42: own-PID-only, passive, multi-signal evidence. No injection,
  // blocking, memory writes, thread manipulation or debugger checks.
  TInjectionEvidenceMonitor = class
  private
    FExternalTick: UInt64;
    FThreadTick: UInt64;
    FImpactTick: UInt64;
    FLastReport: UInt64;
    FLastTick: UInt64;
  public
    constructor Create;
    procedure Reset;
    procedure ObservationGap;
    procedure Examine(OwnTarget, Baseline, HighExternalAccess: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds;
      ObservationValid: Boolean = True);
  end;

{$IFDEF NHW_NATIVE10Q_TESTS}
function TestInjectionEvidence10Q(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.SignalCorrelation
  {$IFDEF NHW_NATIVE10Q_TESTS}, System.SysUtils{$ENDIF};

const
  EVIDENCE_WINDOW_MS = 10000;
  EVIDENCE_COOLDOWN_MS = 30000;

constructor TInjectionEvidenceMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TInjectionEvidenceMonitor.Reset;
begin
  FExternalTick := 0;
  FThreadTick := 0;
  FImpactTick := 0;
  FLastReport := 0;
  FLastTick := 0;
end;

procedure TInjectionEvidenceMonitor.ObservationGap;
begin
  FExternalTick := 0;
  FThreadTick := 0;
  FImpactTick := 0;
  // Preserve output cooldown: a collection gap is not a new incident.
end;

procedure TInjectionEvidenceMonitor.Examine(OwnTarget, Baseline,
  HighExternalAccess: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds; ObservationValid: Boolean);

  function AcceptObservationTick: Boolean;
  begin
    Result := False;
    if not ObservationValid or (Tick = 0) then
    begin
      ObservationGap;
      if Tick > FLastTick then FLastTick := Tick;
      Exit;
    end;
    if FLastTick <> 0 then
    begin
      if Tick < FLastTick then
      begin
        ObservationGap;
        FLastTick := Tick;
        Exit; // clock boundary is not evidence
      end;
      if Tick = FLastTick then Exit;
      if Tick - FLastTick > EVIDENCE_WINDOW_MS then ObservationGap;
    end;
    FLastTick := Tick;
    Result := True;
  end;

  procedure ObserveEvidenceSignals;
  begin
    if HighExternalAccess then FExternalTick := Tick;
    // Actual observed origin/thread anomalies, not every ordinary thread start.
    if (Detected * [dkRemoteThread, dkPrivateThread]) <> [] then
      FThreadTick := Tick;
    // A changed executable region / code image, OR an independent verified
    // ETW image-load correlation: neither ordinary module loads nor a single
    // writable-process handle are sufficient by themselves.
    if (Detected * [dkPrivateExecRegion, dkPECodeIntegrity,
      dkWriteIntegrity, dkETWImageFusion]) <> [] then FImpactTick := Tick;
  end;

  procedure ReportEvidenceIfCorrelated;
  begin
    if RecentSignal(FExternalTick, Tick, EVIDENCE_WINDOW_MS) and
       RecentSignal(FThreadTick, Tick, EVIDENCE_WINDOW_MS) and
       RecentSignal(FImpactTick, Tick, EVIDENCE_WINDOW_MS) and
       ((FLastReport = 0) or
        not RecentSignal(FLastReport, Tick, EVIDENCE_COOLDOWN_MS)) then
    begin
      Include(Detected, dkInjectionEvidence);
      FLastReport := Tick;
    end;
  end;
begin
  if Baseline or not OwnTarget then
  begin
    Reset;
    Exit;
  end;
  if not AcceptObservationTick then Exit;
  ObserveEvidenceSignals;
  ReportEvidenceIfCorrelated;
end;

{$IFDEF NHW_NATIVE10Q_TESTS}
{$I Cozy.NHW.Native10Q.InjectionEvidence.inc}
{$ENDIF}

end.
