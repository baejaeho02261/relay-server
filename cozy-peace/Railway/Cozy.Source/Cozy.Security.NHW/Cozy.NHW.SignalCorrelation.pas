unit Cozy.NHW.SignalCorrelation;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.Logging;

type
  // v37: bounded, in-process timeline, with independent signal families.
  // It records evidence proximity only. It NEVER attributes an action to a PID.
  TSignalCorrelationMonitor = class
  private
    FAccessTick: UInt64;
    FThreadTick: UInt64;
    FMemoryTick: UInt64;
    FLastReport: UInt64;
    FLastTick: UInt64;
  public
    constructor Create;
    procedure Reset;
    procedure ObservationGap;
    procedure Examine(Baseline, HighExternalAccess: Boolean;
      Tick: UInt64; var Detected: TDetectionKinds;
      ObservationValid: Boolean = True);
  end;

function RecentSignal(Observed, Current, WindowMS: UInt64): Boolean;

{$IFDEF NHW_NATIVE10Q_TESTS}
function TestSignalCorrelation10Q(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10Q_TESTS}
uses System.SysUtils;
{$ENDIF}

const
  CORRELATION_WINDOW_MS = 8000;
  CORRELATION_COOLDOWN_MS = 15000;

function RecentSignal(Observed, Current, WindowMS: UInt64): Boolean;
begin
  Result := (Observed <> 0) and (Current >= Observed) and
    (Current - Observed <= WindowMS);
end;

constructor TSignalCorrelationMonitor.Create;
begin
  inherited Create;
  Reset;
end;

procedure TSignalCorrelationMonitor.Reset;
begin
  FAccessTick := 0;
  FThreadTick := 0;
  FMemoryTick := 0;
  FLastReport := 0;
  FLastTick := 0;
end;

procedure TSignalCorrelationMonitor.ObservationGap;
begin
  FAccessTick := 0;
  FThreadTick := 0;
  FMemoryTick := 0;
  // Preserve output cooldown: a collection gap is not a new incident.
end;

function PrepareCorrelationObservation(Monitor: TSignalCorrelationMonitor;
  Baseline, ObservationValid: Boolean; Tick: UInt64): Boolean;
begin
  Result := False;
  if Baseline then
  begin
    Monitor.Reset;
    Exit;
  end;
  if not ObservationValid or (Tick = 0) then
  begin
    Monitor.ObservationGap;
    if Tick > Monitor.FLastTick then Monitor.FLastTick := Tick;
    Exit;
  end;
  if Monitor.FLastTick <> 0 then
  begin
    if Tick < Monitor.FLastTick then
    begin
      Monitor.ObservationGap;
      Monitor.FLastTick := Tick;
      Exit; // clock boundary is not evidence
    end;
    if Tick = Monitor.FLastTick then Exit;
    if Tick - Monitor.FLastTick > CORRELATION_WINDOW_MS then
      Monitor.ObservationGap;
  end;
  Monitor.FLastTick := Tick;
  Result := True;
end;

procedure UpdateCorrelationSignals(Monitor: TSignalCorrelationMonitor;
  HighExternalAccess: Boolean; Tick: UInt64;
  const Detected: TDetectionKinds);
begin
  // A newly observed dangerous handle capability is NOT evidence of a write.
  // Require a separate class of signal within a bounded time window.
  if HighExternalAccess then Monitor.FAccessTick := Tick;
  if (Detected * [dkRemoteThread, dkPrivateThread, dkThreadRegion,
    dkThreadSpawn, dkThreadCreation]) <> [] then Monitor.FThreadTick := Tick;
  if (Detected * [dkExecuteProtect, dkRWX, dkProtectTransition,
    dkImageProtection, dkWriteIntegrity, dkPECodeIntegrity,
    dkPrivateExecRegion]) <> [] then Monitor.FMemoryTick := Tick;
end;

function CorrelationReady(Monitor: TSignalCorrelationMonitor;
  Tick: UInt64): Boolean;
begin
  Result := RecentSignal(Monitor.FAccessTick, Tick, CORRELATION_WINDOW_MS) and
    (RecentSignal(Monitor.FThreadTick, Tick, CORRELATION_WINDOW_MS) or
     RecentSignal(Monitor.FMemoryTick, Tick, CORRELATION_WINDOW_MS)) and
    ((Monitor.FLastReport = 0) or
     (not RecentSignal(Monitor.FLastReport, Tick, CORRELATION_COOLDOWN_MS)));
end;

procedure TSignalCorrelationMonitor.Examine(Baseline,
  HighExternalAccess: Boolean; Tick: UInt64;
  var Detected: TDetectionKinds; ObservationValid: Boolean);
begin
  if not PrepareCorrelationObservation(Self, Baseline,
    ObservationValid, Tick) then Exit;
  UpdateCorrelationSignals(Self, HighExternalAccess, Tick, Detected);
  if CorrelationReady(Self, Tick) then
  begin
    Include(Detected, dkMultiSignal);
    FLastReport := Tick;
  end;
end;

{$IFDEF NHW_NATIVE10Q_TESTS}
{$I Cozy.NHW.Native10Q.SignalCorrelation.inc}
{$ENDIF}

end.
