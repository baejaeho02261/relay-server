unit Cozy.NHW.EventDrivenWake;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.SysUtils;

type
  // v82: any ETW notification can wake a sleeping scan, while a lower bound
  // prevents an ETW burst from causing tight-loop full scans.
  TEventDrivenWake = class
  private
    FLastEarlyWake: UInt64;
    function DelayBeforeWake(ScanStarted, NowTick: UInt64): Cardinal;
  public
    constructor Create;
    procedure Reset;
    function MayWake(ScanStarted, NowTick: UInt64): Boolean;
  end;

// Called only on main monitoring thread. Handles remain owned by TETWMonitor.
procedure SleepUntilDueOrEvent(PeriodMS: Cardinal; WakeHandle: THandle;
  ScanStarted: UInt64; WakePolicy: TEventDrivenWake;
  StopFlag: PLongInt; const Cancelled: TFunc<Boolean> = nil);

{$IFDEF NHW_NATIVE5K_TESTS}
function TestEventDrivenWake5K(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses System.SyncObjs;

const MIN_EARLY_SCAN_SEPARATION_MS = 250;

{$IFDEF NHW_NATIVE5K_TESTS}
type
  TWake5KTick = function: UInt64;
  TWake5KWait = function(Handle: THandle; Timeout: Cardinal): Cardinal;
  TWake5KSleep = procedure(Timeout: Cardinal);
var
  Wake5KTick: TWake5KTick = nil;
  Wake5KWait: TWake5KWait = nil;
  Wake5KSleep: TWake5KSleep = nil;
{$ENDIF}

function WakeNow: UInt64;
begin
{$IFDEF NHW_NATIVE5K_TESTS}
  if Assigned(Wake5KTick) then Exit(Wake5KTick());
{$ENDIF}
  Result := GetTickCount64;
end;

function WakeWait(Handle: THandle; Timeout: Cardinal): Cardinal;
begin
{$IFDEF NHW_NATIVE5K_TESTS}
  if Assigned(Wake5KWait) then Exit(Wake5KWait(Handle, Timeout));
{$ENDIF}
  Result := WaitForSingleObject(Handle, Timeout);
end;

procedure WakeSleep(Timeout: Cardinal);
begin
{$IFDEF NHW_NATIVE5K_TESTS}
  if Assigned(Wake5KSleep) then
  begin Wake5KSleep(Timeout); Exit; end;
{$ENDIF}
  Sleep(Timeout);
end;

function TEventDrivenWake.DelayBeforeWake(ScanStarted, NowTick: UInt64): Cardinal;
var Elapsed: UInt64; D: Cardinal;
begin
  Result := 0;
  if NowTick < ScanStarted then Exit(MIN_EARLY_SCAN_SEPARATION_MS);
  Elapsed := NowTick - ScanStarted;
  if Elapsed < MIN_EARLY_SCAN_SEPARATION_MS then
    Result := MIN_EARLY_SCAN_SEPARATION_MS - Cardinal(Elapsed);
  if (FLastEarlyWake <> 0) and (NowTick >= FLastEarlyWake) then
  begin
    Elapsed := NowTick - FLastEarlyWake;
    if Elapsed < MIN_EARLY_SCAN_SEPARATION_MS then
    begin
      D := MIN_EARLY_SCAN_SEPARATION_MS - Cardinal(Elapsed);
      if D > Result then Result := D;
    end;
  end;
end;

constructor TEventDrivenWake.Create;
begin inherited Create; Reset; end;

procedure TEventDrivenWake.Reset;
begin FLastEarlyWake := 0; end;

function TEventDrivenWake.MayWake(ScanStarted, NowTick: UInt64): Boolean;
begin
  Result := (NowTick >= ScanStarted) and
    (NowTick - ScanStarted >= MIN_EARLY_SCAN_SEPARATION_MS) and
    ((FLastEarlyWake = 0) or (NowTick < FLastEarlyWake) or
     (NowTick - FLastEarlyWake >= MIN_EARLY_SCAN_SEPARATION_MS));
  if Result then FLastEarlyWake := NowTick;
end;

function PrepareWakeIteration(PeriodMS: Cardinal; StartTime,
  ScanStarted: UInt64; WakePending: Boolean; WakePolicy: TEventDrivenWake;
  out Chunk: Cardinal): Boolean;
var
  NowTick, SinceStart: UInt64;
  Delay: Cardinal;
begin
  Result := True;
  Chunk := 0;
  NowTick := WakeNow;
  if NowTick < StartTime then Exit; // do not underflow the elapsed counter
  SinceStart := NowTick - StartTime;
  if SinceStart >= PeriodMS then Exit;
  if WakePending and (WakePolicy <> nil) and
    WakePolicy.MayWake(ScanStarted, NowTick) then Exit;
  Chunk := Cardinal(UInt64(PeriodMS) - SinceStart);
  if Chunk > 50 then Chunk := 50;
  if WakePending and (WakePolicy <> nil) then
  begin
    Delay := WakePolicy.DelayBeforeWake(ScanStarted, NowTick);
    if (Delay <> 0) and (Delay < Chunk) then Chunk := Delay;
  end;
  Result := False;
end;

procedure WaitWakeChunk(WakeHandle: THandle; Chunk: Cardinal;
  var WakePending, WaitUsable: Boolean);
var Res: DWORD;
begin
  if WaitUsable and not WakePending then
  begin
    Res := WakeWait(WakeHandle, Chunk);
    if Res = WAIT_OBJECT_0 then
      WakePending := True
    else if Res <> WAIT_TIMEOUT then
    begin
      WaitUsable := False; // failure/unsupported wait: timed fallback
      WakeSleep(Chunk);
    end;
  end
  else
    // The wake is latched locally. Re-waiting on a still-signaled event
    // would spin; never reset/close the event owned by the ETW monitor.
    WakeSleep(Chunk);
end;

procedure SleepUntilDueOrEvent(PeriodMS: Cardinal; WakeHandle: THandle;
  ScanStarted: UInt64; WakePolicy: TEventDrivenWake;
  StopFlag: PLongInt; const Cancelled: TFunc<Boolean>);
var
  StartTime: UInt64;
  Chunk: Cardinal;
  WakePending, WaitUsable: Boolean;
begin
  StartTime := WakeNow;
  WakePending := False;
  WaitUsable := (WakeHandle <> 0) and
    (WakeHandle <> INVALID_HANDLE_VALUE) and (WakePolicy <> nil);
  repeat
    if Assigned(Cancelled) then
      if Cancelled() then Exit;
    if StopFlag <> nil then
      if TInterlocked.CompareExchange(StopFlag^, 0, 0) <> 0 then Exit;
    if PrepareWakeIteration(PeriodMS, StartTime, ScanStarted, WakePending,
      WakePolicy, Chunk) then Exit;
    WaitWakeChunk(WakeHandle, Chunk, WakePending, WaitUsable);
  until False;
end;

{$IFDEF NHW_NATIVE5K_TESTS}
{$I Cozy.NHW.Native5K.EventDrivenWake.inc}
{$ENDIF}

end.
