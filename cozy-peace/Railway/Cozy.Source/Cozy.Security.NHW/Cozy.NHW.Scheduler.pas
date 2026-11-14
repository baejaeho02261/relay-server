unit Cozy.NHW.Scheduler;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Lifecycle,
  Cozy.NHW.Logging,
  Cozy.NHW.Scheduler.Rules;

type
  TProcessScheduleState = Cozy.NHW.Scheduler.Rules.TProcessScheduleState;
  TThreadScheduleState = Cozy.NHW.Scheduler.Rules.TThreadScheduleState;

  TSchedulerMonitor = class
  private
    FPrevious: TProcessScheduleState;
    FProcessPrimed: Boolean;
    FThreads: TDictionary<Cardinal, TThreadScheduleState>;
    FLastTick: UInt64;
    procedure SampleProcess(Target: THandle; PID: Cardinal;
      Baseline: Boolean; var Detected: TDetectionKinds);
    procedure SampleThreads(PID: Cardinal; Threads: TThreadSampleMap;
      Baseline: Boolean; var Detected: TDetectionKinds);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Examine(Target: THandle; PID: Cardinal;
      Threads: TThreadSampleMap; ThreadsValid: Boolean;
      Tick: UInt64; Baseline: Boolean; var Detected: TDetectionKinds);
  end;


// Pure comparators for deterministic regression tests. Unknown information
// never generates an event; both snapshots must contain the same field.
function CompareProcessSchedule(const OldState, NewState: TProcessScheduleState): TDetectionKinds;
function CompareThreadSchedule(const OldState, NewState: TThreadScheduleState): TDetectionKinds;

{$IFDEF NHW_NATIVE10P_TESTS}
function TestScheduler10P(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.Types,
  Cozy.NHW.Native,
  Cozy.NHW.SchedulerNative,
  Cozy.NHW.WinPointers;

const
  SCHEDULER_INTERVAL_MS = 1000;

function CompareProcessSchedule(const OldState, NewState: TProcessScheduleState): TDetectionKinds;
begin
  Result := Cozy.NHW.Scheduler.Rules.CompareProcessSchedule(OldState, NewState);
end;

function CompareThreadSchedule(const OldState, NewState: TThreadScheduleState): TDetectionKinds;
begin
  Result := Cozy.NHW.Scheduler.Rules.CompareThreadSchedule(OldState, NewState);
end;

constructor TSchedulerMonitor.Create;
begin
  inherited Create;
  FThreads := TDictionary<Cardinal, TThreadScheduleState>.Create;
  Reset;
end;

destructor TSchedulerMonitor.Destroy;
begin
  FThreads.Free;
  inherited Destroy;
end;

procedure TSchedulerMonitor.Reset;
begin
  FPrevious := Default(TProcessScheduleState);
  FProcessPrimed := False;
  FThreads.Clear;
  FLastTick := 0;
end;

procedure ReadProcessSchedule(Target: THandle; PID: Cardinal;
  out Current: TProcessScheduleState);
var
  Handle: THandle;
  OwnHandle: Boolean;
  ClassValue, Flags: Cardinal;
  Mask: NativeUInt;
  Groups: string;
  Disabled: BOOL;
  I: Integer;
begin
  Current := Default(TProcessScheduleState);
  Handle := OpenNativeProcess(PID, ACCESS_QUERY_INFORMATION);
  OwnHandle := Handle <> 0;
  if not OwnHandle then Handle := Target;
  try
    if GetNativePriorityClass(Handle, ClassValue) then
    begin
      Current.ClassKnown := True;
      Current.PriorityClass := ClassValue;
    end;
    if GetNativeProcessAffinity(Handle, Mask) then
    begin
      Current.AffinityKnown := True;
      Current.ProcessMask := Mask;
    end;
    if GetNativeProcessGroups(Handle, Groups) then
    begin
      Current.GroupsKnown := True;
      Current.Groups := Groups;
    end;
    if GetNativeProcessBoost(Handle, Disabled) then
    begin
      Current.BoostKnown := True;
      Current.BoostDisabled := Disabled <> False;
    end;
    if OwnHandle then
      for I := Low(MITIGATION_POLICIES) to High(MITIGATION_POLICIES) do
        if GetNativeMitigation(Handle, MITIGATION_POLICIES[I], Flags) then
        begin
          Current.MitigationKnown[I] := True;
          Current.MitigationFlags[I] := Flags;
        end;
  finally
    if OwnHandle then CloseNativeProcess(Handle);
  end;
end;

procedure TSchedulerMonitor.SampleProcess(Target: THandle; PID: Cardinal;
  Baseline: Boolean; var Detected: TDetectionKinds);
var
  Current: TProcessScheduleState;
begin
  ReadProcessSchedule(Target, PID, Current);

  if FProcessPrimed and not Baseline then
    Detected := Detected + CompareProcessSchedule(FPrevious, Current);
  FPrevious := Current;
  FProcessPrimed := True;
end;

{$IFDEF NHW_NATIVE10P_TESTS}
type TReadSchedule10PHook = function(PID, ThreadID: Cardinal;
  out State: TThreadScheduleState): Boolean;
var ReadSchedule10PHook: TReadSchedule10PHook = nil;
{$ENDIF}

function ReadThreadSchedule(PID, ThreadID: Cardinal;
  out State: TThreadScheduleState): Boolean;
var
  Handle: THandle;
  Created, Exited, KernelTime, UserTime: TFileTime;
  Current: TThreadScheduleState;
  Prio: Integer;
  Group: Word;
  Mask: NativeUInt;
  Disabled: BOOL;
  ControlMask, StateMask: Cardinal;
begin
  Result := False;
  State := Default(TThreadScheduleState);
  if (PID = 0) or (ThreadID = 0) then Exit;
{$IFDEF NHW_NATIVE10P_TESTS}
  if Assigned(ReadSchedule10PHook) then
    Exit(ReadSchedule10PHook(PID, ThreadID, State));
{$ENDIF}
  Handle := OpenNativeThread(PID, ThreadID, THREAD_QUERY_INFORMATION_RIGHT);
  if Handle = 0 then
    Handle := OpenNativeThread(PID, ThreadID, THREAD_QUERY_LIMITED_INFORMATION_RIGHT);
  if Handle = 0 then Exit;
  try
    if not WinGetThreadTimes(Handle, Created, Exited, KernelTime, UserTime) then Exit;
    Current := Default(TThreadScheduleState);
    Current.CreationTime := (UInt64(Created.dwHighDateTime) shl 32) or
      UInt64(Created.dwLowDateTime);
    // lpExitTime is undefined for a live thread; never interpret it as liveness.
    if Current.CreationTime = 0 then Exit;
    if GetNativeThreadPriority(Handle, Prio) then
    begin Current.PriorityKnown := True; Current.Priority := Prio; end;
    if GetNativeThreadGroup(Handle, Group, Mask) then
    begin
      Current.GroupKnown := True;
      Current.Group := Group;
      Current.AffinityMask := Mask;
    end;
    if GetNativeThreadBoost(Handle, Disabled) then
    begin Current.BoostKnown := True; Current.BoostDisabled := Disabled <> False; end;
    if GetNativeThreadPower(Handle, ControlMask, StateMask) then
    begin
      Current.PowerKnown := True;
      Current.PowerControl := ControlMask;
      Current.PowerState := StateMask;
    end;
    State := Current;
    Result := True;
  finally
    CloseNativeProcess(Handle);
  end;
end;

procedure TSchedulerMonitor.SampleThreads(PID: Cardinal;
  Threads: TThreadSampleMap; Baseline: Boolean;
  var Detected: TDetectionKinds);
var
  Item: TPair<Cardinal, TThreadSample>;
  Previous, Current: TThreadScheduleState;
  KnownKeys: TList<Cardinal>;
  Key: Cardinal;
  PendingKinds: TDetectionKinds;
begin
  if (PID = 0) or (Threads = nil) then
  begin FThreads.Clear; Exit; end;
  if Threads.Count > MAX_TARGET_THREADS then
  begin FThreads.Clear; Exit; end;
  KnownKeys := nil;
  PendingKinds := [];
  try
    try
      for Item in Threads do
      begin
        if (Item.Key = 0) or (Item.Value.ThreadID <> Item.Key) then
        begin
          FThreads.Clear;
          Exit; // Structurally invalid collection: publish no partial result.
        end;
        if not ReadThreadSchedule(PID, Item.Key, Current) or
           (Current.CreationTime = 0) then
        begin
          FThreads.Remove(Item.Key);
          Continue;
        end;
        if FThreads.TryGetValue(Item.Key, Previous) and
           (Previous.CreationTime = Current.CreationTime) and not Baseline then
          PendingKinds := PendingKinds + CompareThreadSchedule(Previous, Current);
        // Unknown individual fields replace their old Known=True flag.
        FThreads.AddOrSetValue(Item.Key, Current);
      end;
      KnownKeys := TList<Cardinal>.Create;
      for Key in FThreads.Keys do
        if not Threads.ContainsKey(Key) then KnownKeys.Add(Key);
      for Key in KnownKeys do FThreads.Remove(Key);
      Detected := Detected + PendingKinds;
    except
      FThreads.Clear;
      raise;
    end;
  finally
    KnownKeys.Free;
  end;
end;

procedure TSchedulerMonitor.Examine(Target: THandle; PID: Cardinal;
  Threads: TThreadSampleMap; ThreadsValid: Boolean; Tick: UInt64;
  Baseline: Boolean; var Detected: TDetectionKinds);
begin
  if not ThreadsValid or (Threads = nil) then FThreads.Clear;
  if not SchedulerAvailable then
  begin
    FThreads.Clear;
    FPrevious := Default(TProcessScheduleState);
    FProcessPrimed := False;
    Exit;
  end;
  if (FLastTick <> 0) and (Tick < FLastTick) then Reset;
  if FLastTick <> 0 then
  begin
    if Tick - FLastTick < SCHEDULER_INTERVAL_MS then Exit;
  end;
  FLastTick := Tick;
  try
    SampleProcess(Target, PID, Baseline, Detected);
    if ThreadsValid and (Threads <> nil) then
      SampleThreads(PID, Threads, Baseline, Detected);
  except
    FThreads.Clear;
    FPrevious := Default(TProcessScheduleState);
    FProcessPrimed := False;
    raise;
  end;
end;

{$IFDEF NHW_NATIVE10P_TESTS}
{$I Cozy.NHW.Native10P.Scheduler.inc}
{$ENDIF}

end.
