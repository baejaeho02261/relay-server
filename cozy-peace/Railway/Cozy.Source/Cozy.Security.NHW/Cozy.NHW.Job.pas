unit Cozy.NHW.Job;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.Logging;

type
  TJobMonitor = class
  private
    FPrimed: Boolean;
    FLastInJob: Boolean;
    FLastTick: UInt64;
    FHaveAttempt: Boolean;
  public
    procedure Reset;
    procedure Examine(TargetHandle: THandle; Tick: UInt64;
      var Detected: TDetectionKinds);
  end;

{$IFDEF NHW_NATIVE10N_TESTS}
function TestJob10N(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  {$IFDEF NHW_NATIVE10N_TESTS} System.SysUtils, {$ENDIF}
  Cozy.NHW.Native;

{$IFDEF NHW_NATIVE10N_TESTS}
type TJobQuery10N = function(H: THandle; out InJob: Boolean): Boolean;
var JobQuery10N: TJobQuery10N = nil;
{$ENDIF}

const
  JOB_QUERY_INTERVAL_MS = 2000;

procedure TJobMonitor.Reset;
begin
  FPrimed := False;
  FLastInJob := False;
  FLastTick := 0;
  FHaveAttempt := False;
end;

function BeginJobQuery(Monitor: TJobMonitor; Tick: UInt64): Boolean;
begin
  Result := False;
  if Monitor.FHaveAttempt then
    if (Tick >= Monitor.FLastTick) and
       (Tick - Monitor.FLastTick < JOB_QUERY_INTERVAL_MS) then Exit;
  Monitor.FLastTick := Tick;
  Monitor.FHaveAttempt := True;
  Result := True;
end;

function ReadJobObservation(TargetHandle: THandle; out InJob: Boolean): Boolean;
begin
  {$IFDEF NHW_NATIVE10N_TESTS}
  if Assigned(JobQuery10N) then
  begin
    Result := JobQuery10N(TargetHandle, InJob);
    Exit;
  end;
  {$ENDIF}
  Result := QueryNativeJobState(TargetHandle, InJob);
end;

procedure ApplyJobObservation(Monitor: TJobMonitor; InJob: Boolean;
  var Detected: TDetectionKinds);
begin
  if not Monitor.FPrimed then
  begin
    Monitor.FPrimed := True;
    Monitor.FLastInJob := InJob;
    Exit;
  end;
  if Monitor.FLastInJob <> InJob then
  begin
    Monitor.FLastInJob := InJob;
    Include(Detected, dkJob);
  end;
end;

procedure TJobMonitor.Examine(TargetHandle: THandle; Tick: UInt64;
  var Detected: TDetectionKinds);
var InJob: Boolean;
begin
  if not BeginJobQuery(Self, Tick) then Exit;
  if not ReadJobObservation(TargetHandle, InJob) then Exit;
  ApplyJobObservation(Self, InJob, Detected);
end;

{$IFDEF NHW_NATIVE10N_TESTS}
{$I Cozy.NHW.Native10N.Job.inc}
{$ENDIF}

end.
