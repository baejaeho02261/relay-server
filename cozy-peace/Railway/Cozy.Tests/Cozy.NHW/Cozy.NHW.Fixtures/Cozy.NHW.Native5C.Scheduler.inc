var SchedulerTestMode, SchedulerTestCalls: Integer;
function SchedulerTestGroups(Process: THandle; var Count: Word; Groups: PWord): BOOL; stdcall;
var V: array[0..2] of Word;
begin
  Inc(SchedulerTestCalls);
  if SchedulerTestMode = 1 then
  begin SetLastError(5); Exit(False); end;
  if ((SchedulerTestMode = 2) and (SchedulerTestCalls = 1)) or
     (SchedulerTestMode = 3) then
  begin Inc(Count); SetLastError(122); Exit(False); end;
  if SchedulerTestMode = 4 then begin Inc(Count); Exit(True); end;
  if SchedulerTestMode = 6 then begin Count := 0; Exit(True); end;
  Count := 3; V[0] := 7; V[1] := 1; V[2] := 3;
  if SchedulerTestMode = 5 then V[2] := 1;
  if SchedulerTestMode = 7 then V[2] := High(Word);
  Move(V[0], Groups^, SizeOf(V));
  Result := True;
end;
function SchedulerTestPriority(Process: THandle): Cardinal; stdcall;
begin if SchedulerTestMode = 0 then Result := 32 else Result := 0; end;
function SchedulerTestThreadPriority(Thread: THandle): Integer; stdcall;
begin if SchedulerTestMode = 0 then Result := -2 else Result := MaxInt; end;
function SchedulerTestAffinity(Process: THandle; var Mask, SystemMask: NativeUInt): BOOL; stdcall;
begin
  Mask := 3; SystemMask := 15;
  if SchedulerTestMode = 2 then Mask := 0;
  Result := SchedulerTestMode <> 1;
end;
function SchedulerTestGroup(Thread: THandle; var A: TNativeGroupAffinity): BOOL; stdcall;
begin
  A := Default(TNativeGroupAffinity); A.Mask := 3; A.Group := 2;
  if SchedulerTestMode = 2 then A.Mask := 0;
  Result := SchedulerTestMode <> 1;
end;
function SchedulerTestBoost(Handle: THandle; var Disabled: BOOL): BOOL; stdcall;
begin Disabled := True; Result := SchedulerTestMode = 0; end;
function SchedulerTestPower(Thread: THandle; InfoClass: Cardinal; Buffer: Pointer;
  BufferSize: Cardinal): BOOL; stdcall;
var State: TNativePowerThrottling;
begin
  State := Default(TNativePowerThrottling);
  State.Version := 1; State.ControlMask := 1; State.StateMask := 1;
  if SchedulerTestMode = 2 then State.Version := 2;
  Move(State, Buffer^, SizeOf(State));
  Result := SchedulerTestMode <> 1;
end;
function SchedulerTestMitigation(Process: THandle; PolicyIndex: Cardinal;
  Buffer: Pointer; Size: NativeUInt): BOOL; stdcall;
begin PCardinal(Buffer)^ := 17; Result := SchedulerTestMode = 0; end;
function TestSchedulerHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedResolved: Integer;
  SP: TPriorityClass; ST: TThreadPriority; SA: TProcessAffinity; SG: TThreadGroup;
  SGS: TProcessGroups; SB: TProcessBoost; STB: TThreadBoost;
  SI: TThreadInformation; SM: TMitigation;
  Groups: string; C, C2: Cardinal; V: Integer; Mask: NativeUInt;
  Group: Word; Disabled: BOOL; ModeValue: Integer;
  procedure Check(B: Boolean; const Name: string);
  begin Inc(Checks); if not B then raise Exception.Create(Name); end;
  procedure Mode(M: Integer);
  begin SchedulerTestMode := M; SchedulerTestCalls := 0; end;
begin
  Result := False; Failure := ''; Checks := 0;
  SavedResolved := Resolved; SP := PriorityClassPtr; ST := ThreadPriorityPtr;
  SA := ProcessAffinityPtr; SG := ThreadGroupPtr; SGS := ProcessGroupsPtr;
  SB := ProcessBoostPtr; STB := ThreadBoostPtr; SI := ThreadInformationPtr; SM := MitigationPtr;
  try
    try
      Resolved := 1; PriorityClassPtr := SchedulerTestPriority;
      ThreadPriorityPtr := SchedulerTestThreadPriority; ProcessAffinityPtr := SchedulerTestAffinity;
      ThreadGroupPtr := SchedulerTestGroup; ProcessGroupsPtr := SchedulerTestGroups;
      ProcessBoostPtr := SchedulerTestBoost; ThreadBoostPtr := SchedulerTestBoost;
      ThreadInformationPtr := SchedulerTestPower; MitigationPtr := SchedulerTestMitigation;
      Mode(0); Check(GetNativeProcessGroups(1, Groups), 'group list valid');
      Check(Groups = '1,3,7', 'groups canonically sorted');
      Mode(2); Check(GetNativeProcessGroups(1, Groups), 'group growth retried');
      Check((SchedulerTestCalls = 2) and (Groups = '1,3,7'), 'retry uses actual count');
      Mode(3); Check(not GetNativeProcessGroups(1, Groups), 'endless growth bounded');
      Check((SchedulerTestCalls = 3) and (Groups = ''), 'no partial growing output');
      for ModeValue := 4 to 7 do
      begin
        Mode(ModeValue); Groups := 'old';
        Check(not GetNativeProcessGroups(1, Groups), 'bad count or group rejected');
        Check(Groups = '', 'bad group output cleared');
      end;
      Mode(1); Check(not GetNativeProcessGroups(1, Groups), 'access failure not retried');
      Check(SchedulerTestCalls = 1, 'only size error retried');
      Mode(0); Check(not GetNativeProcessGroups(0, Groups), 'zero process no groups');
      Check(SchedulerTestCalls = 0, 'zero process does not call API');
      Check(GetNativePriorityClass(1, C) and (C = 32), 'priority valid');
      Mode(1); Check(not GetNativePriorityClass(1, C) and (C = 0), 'priority failure output');
      Mode(0); Check(GetNativeThreadPriority(1, V) and (V = -2), 'negative priority valid');
      Mode(1); Check(not GetNativeThreadPriority(1, V) and (V = 0), 'thread priority sentinel cleared');
      Check(not GetNativeProcessAffinity(1, Mask) and (Mask = 0), 'affinity partial failure cleared');
      Mode(2); Check(not GetNativeProcessAffinity(1, Mask), 'zero mask unknown');
      Mode(0); Check(GetNativeProcessAffinity(1, Mask) and (Mask = 3), 'affinity valid');
      Mode(1); Check(not GetNativeThreadGroup(1, Group, Mask), 'thread group failure');
      Check((Group = 0) and (Mask = 0), 'group failure outputs clear');
      Mode(2); Check(not GetNativeThreadGroup(1, Group, Mask), 'zero group mask unknown');
      Mode(0); Check(GetNativeThreadGroup(1, Group, Mask), 'thread group valid');
      Check((Group = 2) and (Mask = 3), 'thread group exact values');
      Mode(1); Check(not GetNativeProcessBoost(1, Disabled) and not Disabled, 'boost failure output');
      Check(not GetNativeThreadBoost(1, Disabled) and not Disabled, 'thread boost failure output');
      Check(not GetNativeThreadPower(1, C, C2), 'power failure');
      Check((C = 0) and (C2 = 0), 'power failure outputs');
      Mode(2); Check(not GetNativeThreadPower(1, C, C2), 'power version rejected');
      Mode(0); Check(GetNativeThreadPower(1, C, C2), 'power valid');
      Check((C = 1) and (C2 = 1), 'power values');
      Mode(1); Check(not GetNativeMitigation(1, 0, C) and (C = 0), 'existing policy failure output');
      Mode(0); Check(GetNativeMitigation(1, 0, C) and (C = 17), 'existing policy preserved');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    Resolved := SavedResolved; PriorityClassPtr := SP; ThreadPriorityPtr := ST;
    ProcessAffinityPtr := SA; ThreadGroupPtr := SG; ProcessGroupsPtr := SGS;
    ProcessBoostPtr := SB; ThreadBoostPtr := STB; ThreadInformationPtr := SI; MitigationPtr := SM;
  end;
end;
