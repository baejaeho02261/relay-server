unit Cozy.NHW.SchedulerNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils;

type
  // Equivalent of SDK GROUP_AFFINITY on Win64: 16 bytes.
  TNativeGroupAffinity = record
    Mask: NativeUInt;
    Group: Word;
    Reserved: array[0..2] of Word;
  end;

  TNativePowerThrottling = record
    Version: Cardinal;
    ControlMask: Cardinal;
    StateMask: Cardinal;
  end;

// Read-only queries; no scheduler policy or mitigation is set here.
function SchedulerAvailable: Boolean;
function GetNativePriorityClass(Process: THandle; out Value: Cardinal): Boolean;
function GetNativeThreadPriority(Thread: THandle; out Value: Integer): Boolean;
function GetNativeProcessAffinity(Process: THandle; out Mask: NativeUInt): Boolean;
function GetNativeThreadGroup(Thread: THandle; out Group: Word; out Mask: NativeUInt): Boolean;
function GetNativeProcessGroups(Process: THandle; out Groups: string): Boolean;
function GetNativeProcessBoost(Process: THandle; out Disabled: BOOL): Boolean;
function GetNativeThreadBoost(Thread: THandle; out Disabled: BOOL): Boolean;
function GetNativeThreadPower(Thread: THandle; out ControlMask, StateMask: Cardinal): Boolean;
function GetNativeMitigation(Process: THandle; PolicyIndex: Cardinal; out Flags: Cardinal): Boolean;

{$IFDEF NHW_NATIVE5C_TESTS}
function TestSchedulerHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SyncObjs, System.Generics.Collections, Cozy.NHW.WinPointers;

type
  TPriorityClass = function(Process: THandle): Cardinal; stdcall;
  TThreadPriority = function(Thread: THandle): Integer; stdcall;
  TProcessAffinity = function(Process: THandle; var ProcessMask, SystemMask: NativeUInt): BOOL; stdcall;
  TThreadGroup = function(Thread: THandle; var Affinity: TNativeGroupAffinity): BOOL; stdcall;
  TProcessGroups = function(Process: THandle; var Count: Word; Groups: PWord): BOOL; stdcall;
  TProcessBoost = function(Process: THandle; var Disabled: BOOL): BOOL; stdcall;
  TThreadBoost = function(Thread: THandle; var Disabled: BOOL): BOOL; stdcall;
  TThreadInformation = function(Thread: THandle; InfoClass: Cardinal; Buffer: Pointer;
    BufferSize: Cardinal): BOOL; stdcall;
  TMitigation = function(Process: THandle; PolicyIndex: Cardinal; Buffer: Pointer;
    Size: NativeUInt): BOOL; stdcall;

var
  ResolveLock: TCriticalSection;
  Resolved: Integer = 0;
  PriorityClassPtr: TPriorityClass = nil;
  ThreadPriorityPtr: TThreadPriority = nil;
  ProcessAffinityPtr: TProcessAffinity = nil;
  ThreadGroupPtr: TThreadGroup = nil;
  ProcessGroupsPtr: TProcessGroups = nil;
  ProcessBoostPtr: TProcessBoost = nil;
  ThreadBoostPtr: TThreadBoost = nil;
  ThreadInformationPtr: TThreadInformation = nil;
  MitigationPtr: TMitigation = nil;

procedure ResolvePriorityAndAffinity(K: HMODULE);
begin
  PriorityClassPtr := TPriorityClass(WinExport(K, 'GetPriorityClass'));
  ThreadPriorityPtr := TThreadPriority(WinExport(K, 'GetThreadPriority'));
  ProcessAffinityPtr := TProcessAffinity(WinExport(K, 'GetProcessAffinityMask'));
  ThreadGroupPtr := TThreadGroup(WinExport(K, 'GetThreadGroupAffinity'));
  ProcessGroupsPtr := TProcessGroups(WinExport(K, 'GetProcessGroupAffinity'));
end;

procedure ResolveBoostAndPower(K: HMODULE);
begin
  ProcessBoostPtr := TProcessBoost(WinExport(K, 'GetProcessPriorityBoost'));
  ThreadBoostPtr := TThreadBoost(WinExport(K, 'GetThreadPriorityBoost'));
  ThreadInformationPtr := TThreadInformation(WinExport(K, 'GetThreadInformation'));
end;

procedure ResolveMitigationQuery(K: HMODULE);
begin
  MitigationPtr := TMitigation(WinExport(K, 'GetProcessMitigationPolicy'));
end;

procedure ResolveScheduler;
var K: HMODULE;
begin
  if TInterlocked.CompareExchange(Resolved, 0, 0) <> 0 then Exit;
  ResolveLock.Acquire;
  try
    if Resolved <> 0 then Exit;
    K := WinModule('kernel32.dll');
    if K = 0 then Exit;
    ResolvePriorityAndAffinity(K);
    ResolveBoostAndPower(K);
    ResolveMitigationQuery(K);
    TInterlocked.Exchange(Resolved, 1);
  finally
    ResolveLock.Release;
  end;
end;

function SchedulerAvailable: Boolean;
begin
  ResolveScheduler;
  Result := Assigned(PriorityClassPtr) and Assigned(ThreadPriorityPtr);
end;

function GetNativePriorityClass(Process: THandle; out Value: Cardinal): Boolean;
var Candidate: Cardinal;
begin
  Result := False;
  Value := 0;
  if Process = 0 then Exit;
  ResolveScheduler;
  if not Assigned(PriorityClassPtr) then Exit;
  Candidate := PriorityClassPtr(Process);
  if Candidate = 0 then Exit;
  Value := Candidate;
  Result := True;
end;

function GetNativeThreadPriority(Thread: THandle; out Value: Integer): Boolean;
var Candidate: Integer;
begin
  Result := False;
  Value := 0;
  if Thread = 0 then Exit;
  ResolveScheduler;
  if not Assigned(ThreadPriorityPtr) then Exit;
  Candidate := ThreadPriorityPtr(Thread);
  if Candidate = MaxInt then Exit;
  Value := Candidate;
  Result := True;
end;

function GetNativeProcessAffinity(Process: THandle; out Mask: NativeUInt): Boolean;
var Candidate, SystemMask: NativeUInt;
begin
  Result := False;
  Mask := 0;
  if Process = 0 then Exit;
  ResolveScheduler;
  if not Assigned(ProcessAffinityPtr) then Exit;
  Candidate := 0;
  SystemMask := 0;
  if not ProcessAffinityPtr(Process, Candidate, SystemMask) then Exit;
  // Zero is not a meaningful affinity observation on multi-group systems.
  if Candidate = 0 then Exit;
  Mask := Candidate;
  Result := True;
end;

function GetNativeThreadGroup(Thread: THandle; out Group: Word;
  out Mask: NativeUInt): Boolean;
var A: TNativeGroupAffinity;
begin
  Result := False;
  Group := 0;
  Mask := 0;
  if Thread = 0 then Exit;
  ResolveScheduler;
  if (SizeOf(A) <> 16) or not Assigned(ThreadGroupPtr) then Exit;
  A := Default(TNativeGroupAffinity);
  if not ThreadGroupPtr(Thread, A) then Exit;
  if (A.Mask = 0) or (A.Group = High(Word)) then Exit;
  Group := A.Group;
  Mask := A.Mask;
  Result := True;
end;


function ValidateProcessGroups(var Values: TArray<Word>; Count: Integer): Boolean;
var I: Integer;
begin
  Result := False;
  if (Count <= 0) or (Count > Length(Values)) then Exit;
  SetLength(Values, Count);
  TArray.Sort<Word>(Values);
  for I := 0 to Count - 1 do
  begin
    if Values[I] = High(Word) then Exit;
    if (I > 0) and (Values[I] = Values[I - 1]) then Exit;
  end;
  Result := True;
end;

function FormatProcessGroups(const Values: TArray<Word>): string;
var I: Integer;
begin
  Result := '';
  for I := 0 to High(Values) do
  begin
    if I > 0 then Result := Result + ',';
    Result := Result + IntToStr(Values[I]);
  end;
end;

function GetNativeProcessGroups(Process: THandle; out Groups: string): Boolean;
const
  MAX_ATTEMPTS = 3;
  INSUFFICIENT_BUFFER = 122;
var
  Values: TArray<Word>;
  CountWord: Word;
  Attempt, Count: Integer;
  ErrorCode: Cardinal;
  Candidate: string;
begin
  Result := False;
  Groups := '';
  if Process = 0 then Exit;
  ResolveScheduler;
  if not Assigned(ProcessGroupsPtr) then Exit;
  SetLength(Values, 128);
  for Attempt := 1 to MAX_ATTEMPTS do
  begin
    FillChar(Values[0], Length(Values) * SizeOf(Word), 0);
    CountWord := Word(Length(Values));
    if not ProcessGroupsPtr(Process, CountWord, @Values[0]) then
    begin
      ErrorCode := WinGetLastError; // capture before any other OS call
      if (ErrorCode <> INSUFFICIENT_BUFFER) or
         (Integer(CountWord) <= Length(Values)) then Exit;
      if Attempt = MAX_ATTEMPTS then Exit;
      // CountWord is the required ELEMENT count, not a byte count.
      SetLength(Values, Integer(CountWord));
      Continue;
    end;
    Count := Integer(CountWord);
    if not ValidateProcessGroups(Values, Count) then Exit;
    Candidate := FormatProcessGroups(Values);
    Groups := Candidate;
    Exit(True);
  end;
end;

function GetNativeProcessBoost(Process: THandle; out Disabled: BOOL): Boolean;
var Candidate: BOOL;
begin
  Result := False;
  Disabled := False;
  if Process = 0 then Exit;
  ResolveScheduler;
  if not Assigned(ProcessBoostPtr) then Exit;
  Candidate := False;
  if not ProcessBoostPtr(Process, Candidate) then Exit;
  Disabled := Candidate;
  Result := True;
end;

function GetNativeThreadBoost(Thread: THandle; out Disabled: BOOL): Boolean;
var Candidate: BOOL;
begin
  Result := False;
  Disabled := False;
  if Thread = 0 then Exit;
  ResolveScheduler;
  if not Assigned(ThreadBoostPtr) then Exit;
  Candidate := False;
  if not ThreadBoostPtr(Thread, Candidate) then Exit;
  Disabled := Candidate;
  Result := True;
end;

function GetNativeThreadPower(Thread: THandle;
  out ControlMask, StateMask: Cardinal): Boolean;
const THREAD_POWER_THROTTLING_CLASS = 3;
var State: TNativePowerThrottling;
begin
  Result := False;
  ControlMask := 0;
  StateMask := 0;
  if Thread = 0 then Exit;
  ResolveScheduler;
  if not Assigned(ThreadInformationPtr) then Exit;
  State := Default(TNativePowerThrottling);
  State.Version := 1;
  if not ThreadInformationPtr(Thread, THREAD_POWER_THROTTLING_CLASS,
    @State, SizeOf(State)) then Exit;
  if State.Version <> 1 then Exit;
  ControlMask := State.ControlMask;
  StateMask := State.StateMask;
  Result := True;
end;

function GetNativeMitigation(Process: THandle; PolicyIndex: Cardinal;
  out Flags: Cardinal): Boolean;
var Candidate: Cardinal;
begin
  // Preserve the existing 32-bit policy reader. No new mitigation is applied.
  Result := False;
  Flags := 0;
  if Process = 0 then Exit;
  ResolveScheduler;
  if not Assigned(MitigationPtr) then Exit;
  Candidate := 0;
  if not MitigationPtr(Process, PolicyIndex, @Candidate, SizeOf(Candidate)) then Exit;
  Flags := Candidate;
  Result := True;
end;

{$IFDEF NHW_NATIVE5C_TESTS}
  {$I Cozy.NHW.Native5C.Scheduler.inc}
{$ENDIF}
initialization
  ResolveLock := TCriticalSection.Create;
finalization
  ResolveLock.Free;
end.
