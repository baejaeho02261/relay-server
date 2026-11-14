unit Cozy.NHW.SensorFaultIsolation;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses System.SysUtils;

const NHW_SENSOR_SLOT_COUNT = 128;

type
  // IDs are stable within this build.
  TSensorSlot = 0..NHW_SENSOR_SLOT_COUNT - 1;
  TSensorFaultClass = (sfcNone, sfcRecoverable, sfcFatalRuntime);
  TSensorFaultState = record
    Attempts, Successes, Failures, Skipped: UInt64;
    LastStarted, LastSuccess, LastFailure, RetryAt: UInt64;
    ConsecutiveFailures: Byte;
    Running, NeedsReset: Boolean;
    LastFault: TSensorFaultClass;
  end;

  // Main-monitor-thread owner only. No callbacks, threads, strings or IO.
  // Ordinary sensor exceptions are isolated. Memory-corruption/resource
  // exceptions are recorded but MUST be re-raised by the caller.
  TSensorFaultIsolation = class
  private
    FStates: array[TSensorSlot] of TSensorFaultState;
    FCycleIncomplete: Boolean;
    FLastWarning: UInt64;
    FWarningIssued: Boolean;
  public
    constructor Create;
    procedure Reset;
    procedure BeginCycle;
    function TryBegin(Sensor: TSensorSlot; Tick: UInt64;
      out ResetRequired: Boolean): Boolean;
    procedure Succeeded(Sensor: TSensorSlot; Tick: UInt64);
    procedure Failed(Sensor: TSensorSlot; Tick: UInt64;
      Fault: TSensorFaultClass);
    function Snapshot(Sensor: TSensorSlot): TSensorFaultState;
    function TakeCoverageWarning(Tick: UInt64): Boolean;
    property CycleIncomplete: Boolean read FCycleIncomplete;
  end;

function NHWFatalSensorException(E: Exception): Boolean;
function NHWClassifySensorException(E: Exception): TSensorFaultClass;

implementation

uses Cozy.NHW.NativeSafety;

function NHWFatalSensorException(E: Exception): Boolean;
begin
  // Never resume arbitrary execution after memory corruption / exhaustion.
  Result := (E is EOutOfMemory) or (E is EInvalidPointer) or
    (E is EExternalException);
end;

function NHWClassifySensorException(E: Exception): TSensorFaultClass;
begin
  if NHWFatalSensorException(E) then Result := sfcFatalRuntime
  else Result := sfcRecoverable;
end;

constructor TSensorFaultIsolation.Create;
begin inherited Create; Reset; end;

procedure TSensorFaultIsolation.Reset;
begin
  FillChar(FStates, SizeOf(FStates), 0);
  FCycleIncomplete := False;
  FLastWarning := 0;
  FWarningIssued := False;
end;

procedure TSensorFaultIsolation.BeginCycle;
begin FCycleIncomplete := False; end;

function TSensorFaultIsolation.TryBegin(Sensor: TSensorSlot;
  Tick: UInt64; out ResetRequired: Boolean): Boolean;
var S: TSensorFaultState;
begin
  ResetRequired := False;
  S := FStates[Sensor];
  Result := not S.Running;
  if S.NeedsReset and (Tick >= S.LastFailure) and (Tick < S.RetryAt) then
    Result := False;
  if not Result then
  begin
    S.Skipped := NHWSaturatingAdd(S.Skipped, 1);
    FCycleIncomplete := True;
  end
  else
  begin
    S.Running := True;
    S.LastStarted := Tick;
    S.Attempts := NHWSaturatingAdd(S.Attempts, 1);
    ResetRequired := S.NeedsReset;
  end;
  FStates[Sensor] := S;
end;

procedure TSensorFaultIsolation.Succeeded(Sensor: TSensorSlot; Tick: UInt64);
var S: TSensorFaultState;
begin
  S := FStates[Sensor];
  if not S.Running then Exit;
  S.Running := False;
  S.NeedsReset := False;
  S.ConsecutiveFailures := 0;
  S.RetryAt := 0;
  S.LastFault := sfcNone;
  S.LastSuccess := Tick;
  S.Successes := NHWSaturatingAdd(S.Successes, 1);
  FStates[Sensor] := S;
end;

procedure TSensorFaultIsolation.Failed(Sensor: TSensorSlot;
  Tick: UInt64; Fault: TSensorFaultClass);
var S: TSensorFaultState; DelayMS: UInt64; J: Integer;
begin
  S := FStates[Sensor];
  S.Running := False;
  S.NeedsReset := True;
  S.LastFailure := Tick;
  S.LastFault := Fault;
  S.Failures := NHWSaturatingAdd(S.Failures, 1);
  if S.ConsecutiveFailures < 6 then Inc(S.ConsecutiveFailures);
  DelayMS := 250;
  for J := 2 to S.ConsecutiveFailures do DelayMS := DelayMS * 2;
  if DelayMS > 8000 then DelayMS := 8000;
  S.RetryAt := NHWSaturatingAdd(Tick, DelayMS);
  FStates[Sensor] := S;
  FCycleIncomplete := True;
end;

function TSensorFaultIsolation.Snapshot(Sensor: TSensorSlot): TSensorFaultState;
begin Result := FStates[Sensor]; end;

function TSensorFaultIsolation.TakeCoverageWarning(Tick: UInt64): Boolean;
begin
  Result := FCycleIncomplete and ((not FWarningIssued) or
    (Tick < FLastWarning) or (Tick - FLastWarning >= 30000));
  if Result then
  begin
    FLastWarning := Tick;
    FWarningIssued := True;
  end;
end;

end.
