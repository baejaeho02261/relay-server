unit Cozy.ProductFaults;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
{$IFNDEF GAME_PRODUCT_FAULT_TESTS}
  {$MESSAGE FATAL 'Product fault controls belong only in isolated test executables.'}
{$ENDIF}
{$IFDEF GAME_APPLICATION_BUILD}
  {$MESSAGE FATAL 'Product fault controls are forbidden in application builds.'}
{$ENDIF}

interface
{ Cozy central text imports. }
uses
  Cozy.Strings.Application;


function ProductFaultRoot: string;
function ProductFaultTriggered(const Stage: string): Boolean;
function ProductFaultArmed(const Stage: string): Boolean;
function ProductFaultHoldLocalStop(DeadlineTick: UInt64): Boolean;
procedure ProductFaultPoint(const Stage: string);
procedure ProductFaultObserved(const Stage: string);
procedure ProductFaultLeaseGranted(RequestStartedTick, LeaseMs, DeadlineTick: UInt64);
procedure ProductFaultParentCleanup(ParentPID: Cardinal);
procedure ProductFaultLateLifecycleReport(ShutdownDeadline: UInt64);
function ProductFaultHandoff(const Stage: string; ChildPID: Cardinal;
  PartialBytes, TotalBytes: Integer): Integer;
{ Result: 0=continue, 1=close this writer, 2=exit this exact test parent.
  Child termination is performed by the test runner's owned process handle. }

implementation

uses Cozy.Clock, Winapi.Windows, System.SysUtils, System.JSON, System.SyncObjs,
  Cozy.Api.Pointer, Cozy.Api.ROR13, Cozy.Platform.ExportResolver;

type
  TEnv = function(Name, Buffer: PWideChar; Size: DWORD): DWORD; stdcall;
  TAttrs = function(Name: PWideChar): DWORD; stdcall;
  TCreate = function(Name: PWideChar; Access, Share: DWORD; Security: Pointer;
    Creation, Flags: DWORD; Template: THandle): THandle; stdcall;
  TInfo = function(Handle: THandle; var Info: TByHandleFileInformation): BOOL; stdcall;
  TRead = function(Handle: THandle; var Buffer; Count: DWORD;
    var Done: DWORD; Overlapped: Pointer): BOOL; stdcall;
  TWrite = function(Handle: THandle; const Buffer; Count: DWORD;
    var Done: DWORD; Overlapped: Pointer): BOOL; stdcall;
  TClose = function(Handle: THandle): BOOL; stdcall;
  TPid = function: DWORD; stdcall;
var
  EnvAPI, AttrAPI, CreateAPI, InfoAPI, ReadAPI, WriteAPI, CloseAPI, PidAPI: TEncodedApiPointer;
  RootPath, RunID, Scenario: string;
  Sequence: Integer;
  LeaseGrantObserved: Boolean;
  AuthorityHoldObserved: Boolean;

procedure Need(Value: Boolean);
begin
  if not Value then raise Exception.Create(CozyText_ProductFaults_PRODUCT_FAULT_CONTEXT_INVALID_118b38a1);
end;

function SafeWord(const Value: string): Boolean;
var C: Char;
begin
  Result := (Length(Value) > 0) and (Length(Value) <= 128);
  if not Result then Exit;
  for C in Value do
    if not CharInSet(C, ['a'..'z', 'A'..'Z', '0'..'9', '-', '_']) then Exit(False);
end;

procedure CheckPath(const Path: string; Directory: Boolean);
var I: Integer; Part: string; Attr: DWORD;
begin
  Need((Length(Path) >= 4) and (Path[2] = ':') and (Path[3] = '\') and
    (Pos(CozyText_ProductFaults_Text_8b5125f8, Path) = 0) and (Pos('/', Path) = 0) and (Pos(':', Copy(Path, 3, MaxInt)) = 0));
  for I := 4 to Length(Path) do
    if (Path[I] = '\') or (I = Length(Path)) then
    begin
      Part := Copy(Path, 1, I);
      Attr := TAttrs(DecodeApiPointer(AttrAPI))(PWideChar(Part));
      Need((Attr <> INVALID_FILE_ATTRIBUTES) and
        ((Attr and FILE_ATTRIBUTE_REPARSE_POINT) = 0));
      if (I < Length(Path)) or Directory then Need((Attr and FILE_ATTRIBUTE_DIRECTORY) <> 0)
      else Need((Attr and FILE_ATTRIBUTE_DIRECTORY) = 0);
    end;
end;

function ReadSmall(const Name: string): string;
var Handle: THandle; Info: TByHandleFileInformation; Bytes: TBytes; Done: DWORD;
begin
  CheckPath(Name, False);
  Handle := TCreate(DecodeApiPointer(CreateAPI))(PWideChar(Name), GENERIC_READ,
    FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, 0);
  Need(Handle <> INVALID_HANDLE_VALUE);
  try
    Need(TInfo(DecodeApiPointer(InfoAPI))(Handle, Info));
    Need((Info.nNumberOfLinks = 1) and (Info.nFileSizeHigh = 0) and
      (Info.nFileSizeLow > 0) and (Info.nFileSizeLow <= 4096) and
      ((Info.dwFileAttributes and (FILE_ATTRIBUTE_REPARSE_POINT or FILE_ATTRIBUTE_DIRECTORY)) = 0));
    SetLength(Bytes, Info.nFileSizeLow);
    Need(TRead(DecodeApiPointer(ReadAPI))(Handle, Bytes[0], Length(Bytes), Done, nil) and
      (Done = DWORD(Length(Bytes))));
    Result := TEncoding.UTF8.GetString(Bytes);
  finally
    TClose(DecodeApiPointer(CloseAPI))(Handle);
  end;
end;

procedure LoadContext;
var Buffer: array[0..32767] of Char; Count: DWORD; Value: TJSONValue; Obj: TJSONObject;
begin
  Count := TEnv(DecodeApiPointer(EnvAPI))(CozyText_ProductFaults_GAME_PRODUCT_FAULT_ROOT_c9a4db1c, @Buffer[0], Length(Buffer));
  Need((Count > 0) and (Count < DWORD(Length(Buffer))));
  SetString(RootPath, PChar(@Buffer[0]), Count);
  RootPath := ExcludeTrailingPathDelimiter(RootPath);
  CheckPath(RootPath, True);
  Need(Trim(ReadSmall(RootPath + CozyText_ProductFaults_test_owned_marker_51c27652)) <> '');
  Need(Trim(ReadSmall(RootPath + CozyText_ProductFaults_product_fault_marker_b3434644)) = CozyText_ProductFaults_GAME_PRODUCT_FAULT_V1_c82b3fc6);
  Value := TJSONObject.ParseJSONValue(ReadSmall(RootPath + CozyText_ProductFaults_product_fault_control_json_5e053f20));
  try
    Need(Value is TJSONObject); Obj := TJSONObject(Value);
    Need((Obj.Count = 3) and (Obj.GetValue(CozyText_ProductFaults_version_6483512e) is TJSONNumber) and
      (Obj.GetValue(CozyText_ProductFaults_version_6483512e).Value = '1') and (Obj.GetValue(CozyText_ProductFaults_runId_51b2a4a8) is TJSONString) and
      (Obj.GetValue(CozyText_ProductFaults_scenario_2c45c112) is TJSONString));
    RunID := Obj.GetValue(CozyText_ProductFaults_runId_51b2a4a8).Value; Scenario := Obj.GetValue(CozyText_ProductFaults_scenario_2c45c112).Value;
    Need(SafeWord(RunID) and SafeWord(Scenario));
  finally
    Value.Free;
  end;
end;

function ProductFaultRoot: string;
begin
  Result := RootPath;
end;

function ProductFaultTriggered(const Stage: string): Boolean;
var Suffix: string;
begin
  Result := Scenario = Stage;
  if (Stage = CozyText_ProductFaults_handoff_body_ab_a855e6a2) or (Stage = CozyText_ProductFaults_handoff_body_bo_4a22135c) then
  begin
    Suffix := Copy(Stage, Length(Stage) - 1, 2);
    Result := (Scenario = CozyText_ProductFaults_handoff_body_interrupt_89f4d982 + Suffix) or
      (Scenario = CozyText_ProductFaults_handoff_parent_exit_eff5ab04 + Suffix) or
      (Scenario = CozyText_ProductFaults_handoff_child_exit_5db8e089 + Suffix);
  end;
end;

procedure Emit(const EventName, Stage: string; ChildPID: Cardinal;
  PartialBytes, TotalBytes: Integer; DeadlineTick: UInt64 = 0;
  RequestStartedTick: UInt64 = 0; LeaseMs: UInt64 = 0);
var Obj: TJSONObject; Bytes: TBytes; Name: string; N: Integer; Handle: THandle; Done: DWORD;
begin
  Need(SafeWord(EventName) and SafeWord(Stage));
  N := TInterlocked.Increment(Sequence); Need((N > 0) and (N <= 1024));
  CheckPath(RootPath, True);
  Obj := TJSONObject.Create;
  try
    Obj.AddPair(CozyText_ProductFaults_version_6483512e, TJSONNumber.Create(1)); Obj.AddPair(CozyText_ProductFaults_runId_51b2a4a8, RunID);
    Obj.AddPair(CozyText_ProductFaults_scenario_2c45c112, Scenario); Obj.AddPair(CozyText_ProductFaults_event_76154367, EventName); Obj.AddPair(CozyText_ProductFaults_stage_e133d3e7, Stage);
    Obj.AddPair(CozyText_ProductFaults_pid_a3caf8d8, TJSONNumber.Create(Int64(TPid(DecodeApiPointer(PidAPI))())));
    Obj.AddPair(CozyText_ProductFaults_observedTick_e4807eb2, TJSONNumber.Create(Int64(CozyTick)));
    if DeadlineTick <> 0 then
    begin
      Obj.AddPair(CozyText_ProductFaults_deadlineTick_c56ba1ee, TJSONNumber.Create(Int64(DeadlineTick)));
      Obj.AddPair(CozyText_ProductFaults_requestStartedTick_5c6f55d4, TJSONNumber.Create(Int64(RequestStartedTick)));
      Obj.AddPair(CozyText_ProductFaults_leaseMs_a70955fa, TJSONNumber.Create(Int64(LeaseMs)));
    end;
    if ChildPID <> 0 then Obj.AddPair(CozyText_ProductFaults_childPid_b3ff47e9, TJSONNumber.Create(Int64(ChildPID)));
    if TotalBytes <> 0 then
    begin
      Obj.AddPair(CozyText_ProductFaults_partialBytes_e55074c0, TJSONNumber.Create(PartialBytes));
      Obj.AddPair(CozyText_ProductFaults_bytesWritten_0623c2f7, TJSONNumber.Create(PartialBytes));
      Obj.AddPair(CozyText_ProductFaults_totalBytes_d6550dcc, TJSONNumber.Create(TotalBytes));
    end;
    Bytes := TEncoding.UTF8.GetBytes(Obj.ToJSON);
  finally Obj.Free; end;
  Name := RootPath + CozyText_ProductFaults_native_ad1901ba + UIntToStr(TPid(DecodeApiPointer(PidAPI))()) + '-' + IntToStr(N) + CozyText_ProductFaults_json_8ad6f71c;
  Handle := TCreate(DecodeApiPointer(CreateAPI))(PWideChar(Name), GENERIC_WRITE, 0,
    nil, CREATE_NEW, FILE_ATTRIBUTE_NORMAL or FILE_FLAG_OPEN_REPARSE_POINT, 0);
  Need(Handle <> INVALID_HANDLE_VALUE);
  try
    Need(TWrite(DecodeApiPointer(WriteAPI))(Handle, Bytes[0], Length(Bytes), Done, nil) and
      (Done = DWORD(Length(Bytes))));
  finally TClose(DecodeApiPointer(CloseAPI))(Handle); end;
end;

procedure ProductFaultPoint(const Stage: string);
begin
  if ProductFaultTriggered(Stage) then Emit(CozyText_ProductFaults_fault_point_c49d2611, Stage, 0, 0, 0);
end;

procedure ProductFaultObserved(const Stage: string);
begin
  if ProductFaultTriggered(Stage) then Emit(CozyText_ProductFaults_fault_observed_de7c89f7, Stage, 0, 0, 0);
end;

procedure ProductFaultLeaseGranted(RequestStartedTick, LeaseMs, DeadlineTick: UInt64);
var At: UInt64;
begin
  if not ((Scenario = CozyText_ProductFaults_overlay_lease_expiry_4d6c66ab) or
    (Scenario = CozyText_ProductFaults_authority_measurement_skipped_e14bb035) or
    (Scenario = CozyText_ProductFaults_authority_report_stopped_0463e4a4) or
    (Scenario = CozyText_ProductFaults_authority_local_stop_held_01c4cd1f)) then Exit;
  if LeaseGrantObserved then Exit;
  At := CozyTick;
  Need((LeaseMs > 0) and (LeaseMs <= 120000) and (RequestStartedTick <= At) and
    (RequestStartedTick <= High(UInt64) - LeaseMs) and
    (RequestStartedTick + LeaseMs = DeadlineTick) and (DeadlineTick > At));
  if Scenario = CozyText_ProductFaults_overlay_lease_expiry_4d6c66ab then
    Emit(CozyText_ProductFaults_fault_observed_de7c89f7, Scenario, 0, 0, 0, DeadlineTick, RequestStartedTick, LeaseMs)
  else
    Emit(CozyText_ProductFaults_authority_grant_d4955e7f, Scenario, 0, 0, 0, DeadlineTick, RequestStartedTick, LeaseMs);
  LeaseGrantObserved := True;
end;

function ProductFaultArmed(const Stage: string): Boolean;
begin
  Result := LeaseGrantObserved and (Scenario = Stage);
end;

function ProductFaultHoldLocalStop(DeadlineTick: UInt64): Boolean;
var At: UInt64; ReleaseName: string;
begin
  Result := False;
  if not ProductFaultArmed(CozyText_ProductFaults_authority_local_stop_held_01c4cd1f) then Exit;
  At := CozyTick;
  { Dedicated, non-publishable O only. Never edit a server lease or touch a
    foreign process. This bounded fault represents a local close not happening. }
  if (DeadlineTick = 0) or (At < DeadlineTick) or
    (At - DeadlineTick >= 30000) then Exit;
  ReleaseName := RootPath + CozyText_ProductFaults_release_authority_0f60987c + UIntToStr(TPid(DecodeApiPointer(PidAPI))());
  if TAttrs(DecodeApiPointer(AttrAPI))(PWideChar(ReleaseName)) <> INVALID_FILE_ATTRIBUTES then
  begin CheckPath(ReleaseName, False); Exit; end;
  if not AuthorityHoldObserved then
  begin
    AuthorityHoldObserved := True;
    Emit(CozyText_ProductFaults_fault_observed_de7c89f7, Scenario, 0, 0, 0, DeadlineTick, 0, 0);
  end;
  Result := True;
end;

procedure ProductFaultParentCleanup(ParentPID: Cardinal);
var Deadline: UInt64; ReleaseName: string;
begin
  if not ((Scenario = CozyText_ProductFaults_lifecycle_cleanup_refused_2fbbf8db) or
    (Scenario = CozyText_ProductFaults_lifecycle_cleanup_scheduled_a46f90f9)) then Exit;
  Need(ParentPID <> 0);
  Emit(CozyText_ProductFaults_lifecycle_cleanup_ready_fb35d6ef, CozyText_ProductFaults_lifecycle_parent_cleanup_7bdb52e7, ParentPID, 0, 0);
  ReleaseName := RootPath + CozyText_ProductFaults_release_5e0d9f6d + UIntToStr(TPid(DecodeApiPointer(PidAPI))());
  Deadline := CozyTick + 8000;
  repeat
    if TAttrs(DecodeApiPointer(AttrAPI))(PWideChar(ReleaseName)) <> INVALID_FILE_ATTRIBUTES then
    begin
      CheckPath(ReleaseName, False);
      Emit(CozyText_ProductFaults_fault_observed_de7c89f7, CozyText_ProductFaults_lifecycle_parent_cleanup_7bdb52e7, ParentPID, 0, 0);
      Exit;
    end;
    CozyPause(10);
  until CozyTick >= Deadline;
  raise Exception.Create(CozyText_ProductFaults_PRODUCT_FAULT_RUNNER_RELEASE_TIMEOUT_532b07a9);
end;

procedure ProductFaultLateLifecycleReport(ShutdownDeadline: UInt64);
var At, Deadline: UInt64; ReleaseName: string;
begin
  if not LeaseGrantObserved or (Scenario <> CozyText_ProductFaults_overlay_lease_expiry_4d6c66ab) then Exit;
  At := CozyTick;
  { Spend only existing shutdown time and reserve the diagnostic transport
    budget. This hook never changes the business or shutdown deadline. }
  if (ShutdownDeadline <= At) or (ShutdownDeadline - At <= 1000) then Exit;
  Deadline := At + 1500;
  if Deadline > ShutdownDeadline - 1000 then Deadline := ShutdownDeadline - 1000;
  Emit(CozyText_ProductFaults_lifecycle_late_report_ready_53f9d4e8, CozyText_ProductFaults_overlay_lease_expiry_4d6c66ab, 0, 0, 0);
  ReleaseName := RootPath + CozyText_ProductFaults_release_late_6d420d9d + UIntToStr(TPid(DecodeApiPointer(PidAPI))());
  repeat
    if TAttrs(DecodeApiPointer(AttrAPI))(PWideChar(ReleaseName)) <> INVALID_FILE_ATTRIBUTES then
    begin
      CheckPath(ReleaseName, False);
      Emit(CozyText_ProductFaults_lifecycle_late_report_released_d0e8616b, CozyText_ProductFaults_overlay_lease_expiry_4d6c66ab, 0, 0, 0);
      Exit;
    end;
    CozyPause(10);
  until CozyTick >= Deadline;
  { Missing observer evidence remains a failed test; normal cleanup continues. }
end;

function ProductFaultHandoff(const Stage: string; ChildPID: Cardinal;
  PartialBytes, TotalBytes: Integer): Integer;
var Deadline: UInt64; ReleaseName: string;
begin
  Result := 0;
  if not ProductFaultTriggered(Stage) then Exit;
  Need((ChildPID <> 0) and (PartialBytes > 4) and (PartialBytes < TotalBytes));
  Emit(CozyText_ProductFaults_handoff_body_written_0298159f, Stage, ChildPID, PartialBytes, TotalBytes);
  if Pos(CozyText_ProductFaults_handoff_parent_exit_eff5ab04, Scenario) = 1 then
  begin Emit(CozyText_ProductFaults_fault_observed_de7c89f7, Stage, ChildPID, PartialBytes, TotalBytes); Exit(2); end;
  if Pos(CozyText_ProductFaults_handoff_child_exit_5db8e089, Scenario) = 1 then
  begin
    ReleaseName := RootPath + CozyText_ProductFaults_release_5e0d9f6d + UIntToStr(TPid(DecodeApiPointer(PidAPI))());
    Deadline := CozyTick + 8000;
    repeat
      if TAttrs(DecodeApiPointer(AttrAPI))(PWideChar(ReleaseName)) <> INVALID_FILE_ATTRIBUTES then
      begin
        CheckPath(ReleaseName, False);
        Emit(CozyText_ProductFaults_fault_observed_de7c89f7, Stage, ChildPID, PartialBytes, TotalBytes);
        Exit(0);
      end;
      CozyPause(10);
    until CozyTick >= Deadline;
    raise Exception.Create(CozyText_ProductFaults_PRODUCT_FAULT_RUNNER_RELEASE_TIMEOUT_532b07a9);
  end;
  Emit(CozyText_ProductFaults_fault_observed_de7c89f7, Stage, ChildPID, PartialBytes, TotalBytes);
  Result := 1;
end;

initialization
  BindApiPointer(EnvAPI, RequireProcAddressHash64(CozyText_ProductFaults_kernel32_dll_5e654f00, HASH_GetEnvironmentVariableW));
  BindApiPointer(AttrAPI, RequireProcAddressHash64(CozyText_ProductFaults_kernel32_dll_5e654f00, HASH_GetFileAttributesW));
  BindApiPointer(CreateAPI, RequireProcAddressHash64(CozyText_ProductFaults_kernel32_dll_5e654f00, HASH_CreateFileW));
  BindApiPointer(InfoAPI, RequireProcAddressHash64(CozyText_ProductFaults_kernel32_dll_5e654f00, HASH_GetFileInformationByHandle));
  BindApiPointer(ReadAPI, RequireProcAddressHash64(CozyText_ProductFaults_kernel32_dll_5e654f00, HASH_ReadFile));
  BindApiPointer(WriteAPI, RequireProcAddressHash64(CozyText_ProductFaults_kernel32_dll_5e654f00, HASH_WriteFile));
  BindApiPointer(CloseAPI, RequireProcAddressHash64(CozyText_ProductFaults_kernel32_dll_5e654f00, HASH_CloseHandle));
  BindApiPointer(PidAPI, RequireProcAddressHash64(CozyText_ProductFaults_kernel32_dll_5e654f00, HASH_GetCurrentProcessId));

  LoadContext;
end.
