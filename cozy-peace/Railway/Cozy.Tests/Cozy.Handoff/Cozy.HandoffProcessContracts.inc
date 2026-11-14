{ Test-only process harness. All terminated processes were created by this
  probe. Uses the production restricted handle-list, environment and pipe I/O
  primitives; no production authorization bypass or arbitrary PID lookup. }
procedure StopHandoffProbeProcess(var Process: TProcessInformation);
begin
  try
    if Process.hProcess <> 0 then
    begin
      if WaitForSingleObject(Process.hProcess, 0) = WAIT_TIMEOUT then
        TerminateProcess(Process.hProcess, 83);
      Check(WaitForSingleObject(Process.hProcess, 3000) = WAIT_OBJECT_0,
        CozyText_HandoffProcessContracts_PROBE_CHILD_DID_NOT_EXIT_e1945a63);
    end;
  finally
    Close(Process.hThread);
    Close(Process.hProcess);
  end;
end;

procedure StartHandoffProbeProcess(const Mode: string;
  const Handles: array of THandle; out Process: TProcessInformation;
  Restricted: Boolean = False);
var
  Startup: TStartupInfoExLocal;
  AttributeBytes: NativeUInt;
  Initialized: Boolean;
  I: Integer;
  Executable, CommandLine, Environment, WorkingDirectory: string;
begin
  FillChar(Process, SizeOf(Process), 0);
  FillChar(Startup, SizeOf(Startup), 0);
  Initialized := False;
  try
    Check(Length(Handles) > 0, CozyText_HandoffProcessContracts_PROBE_HANDLES_REQUIRED_93a74f53);
    Executable := ImagePath(GetCurrentProcess);
    CommandLine := '"' + Executable + CozyText_HandoffProcessContracts_Text_7078d421 + Mode;
    for I := 0 to High(Handles) do
    begin
      Check(Handles[I] <> 0, CozyText_HandoffProcessContracts_PROBE_HANDLE_INVALID_3e127347);
      CommandLine := CommandLine + ' ' + UIntToStr(UInt64(Handles[I]));
    end;
    AttributeBytes := 0;
    InitializeAttributeList(nil, 1, 0, AttributeBytes);
    Check((AttributeBytes > 0) and (AttributeBytes <= 65536), CozyText_HandoffProcessContracts_PROBE_ATTRIBUTE_SIZE_35483083);
    GetMem(Startup.AttributeList, AttributeBytes);
    Check(InitializeAttributeList(Startup.AttributeList, 1, 0, AttributeBytes),
      CozyText_HandoffProcessContracts_PROBE_ATTRIBUTE_INIT_5a574058);
    Initialized := True;
    Check(UpdateAttribute(Startup.AttributeList, 0, AttributeHandleList,
      @Handles[0], NativeUInt(Length(Handles)) * SizeOf(THandle), nil, nil),
      CozyText_HandoffProcessContracts_PROBE_ATTRIBUTE_HANDLES_4ff9db6b);
    Startup.StartupInfo.cb := SizeOf(Startup);
    Environment := ChildEnvironment;
    WorkingDirectory := ExtractFilePath(Executable);
    UniqueString(CommandLine);
    RequireProcessCommand(TApiBuffer.Borrow(PWideChar(CommandLine),
      (Length(CommandLine) + 1) * SizeOf(Char), True), Length(CommandLine) + 1);
    if Restricted then
      CreateOverlayRestrictedProcess(Executable, CommandLine, Environment,
        WorkingDirectory, Startup.StartupInfo, Process)
    else
      Check(CreateProcessW(PWideChar(Executable), PWideChar(CommandLine), nil, nil,
        True, ExtendedStartupInfoPresent or UnicodeEnvironmentFlag,
        PWideChar(Environment), PWideChar(WorkingDirectory), Startup.StartupInfo,
        Process), CozyText_HandoffProcessContracts_PROBE_PROCESS_CREATE_a2e16ab8);
    Close(Process.hThread);
  finally
    if Initialized then DeleteAttributeList(Startup.AttributeList);
    if Startup.AttributeList <> nil then FreeMem(Startup.AttributeList);
    WipeText(CommandLine); WipeText(Environment);
  end;
end;

function HandoffProbeArgument(Index: Integer): THandle;
var Value: UInt64;
begin
  Check(TryStrToUInt64(ParamStr(Index), Value) and (Value <> 0),
    CozyText_HandoffProcessContracts_PROBE_ARGUMENT_INVALID_f03f2651);
  Result := THandle(Value);
end;

function TryRunHandoffProcessChild: Boolean;
var
  Mode: string;
  H: array[0..5] of THandle;
  ReadPipe, WritePipe, RemoteChild: THandle;
  Child: TProcessInformation;
  Attributes: TSecurityAttributes;
  Bytes: TBytes;
  I: Integer;
  Rejected: Boolean;
  FrameSize, Error: DWORD;
  Offset: Integer;
  FixturePath, Signature: string;
  Device: TDeviceSecurity;
  ReadOnlyFile: THandle;
begin
  Result := False;
  if ParamCount = 0 then Exit;
  Mode := ParamStr(1);
  if (Mode <> CozyText_HandoffProcessContracts_handoff_probe_dying_child_755c5973) and
    (Mode <> CozyText_HandoffProcessContracts_handoff_probe_writer_parent_1271ea3f) and
    (Mode <> CozyText_HandoffProcessContracts_handoff_probe_orphan_reader_7455d879) and
    (Mode <> CozyText_HandoffProcessContracts_handoff_probe_restricted_overlay_2043f006) then Exit;
  Result := True;
  FillChar(H, SizeOf(H), 0);
  FillChar(Child, SizeOf(Child), 0);
  ReadPipe := 0; WritePipe := 0; RemoteChild := 0;
  Device := nil; ReadOnlyFile := 0;
  try
    if Mode = CozyText_HandoffProcessContracts_handoff_probe_restricted_overlay_2043f006 then
    begin
      Check(ParamCount = 4, CozyText_HandoffProcessContracts_PROBE_RESTRICTED_ARGUMENT_COUNT_c0d99d75);
      for I := 0 to 2 do H[I] := HandoffProbeArgument(I + 2);
      RequireOverlayRestrictedProcess(GetCurrentProcess);
      SetLength(Bytes, SizeOf(FrameSize));
      ReadExact(H[0], Bytes, 0, Length(Bytes), CozyTick + 3000);
      Move(Bytes[0], FrameSize, SizeOf(FrameSize));
      Check((FrameSize > 0) and (FrameSize <= 4096), CozyText_HandoffProcessContracts_PROBE_RESTRICTED_PATH_SIZE_795ca715);
      SetLength(Bytes, Integer(FrameSize));
      ReadExact(H[0], Bytes, 0, Length(Bytes), CozyTick + 3000);
      Offset := 0; FixturePath := DecodeField(Bytes, Offset, FrameSize);
      RequirePipeEnd(H[0], CozyTick + 3000);
      ReadOnlyFile := CreateFileW(PWideChar(FixturePath), GENERIC_READ,
        FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil,
        OPEN_EXISTING, OpenReparsePointFlag, 0);
      Check(ReadOnlyFile <> INVALID_HANDLE_VALUE, CozyText_HandoffProcessContracts_PROBE_RESTRICTED_FIXTURE_READ_7517469c);
      Close(ReadOnlyFile);
      ReadOnlyFile := CreateFileW(PWideChar(FixturePath), GENERIC_WRITE,
        FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil,
        OPEN_EXISTING, OpenReparsePointFlag, 0);
      Error := GetLastError;
      Check((ReadOnlyFile = INVALID_HANDLE_VALUE) and (Error = ERROR_ACCESS_DENIED),
        CozyText_HandoffProcessContracts_PROBE_RESTRICTED_ADMIN_WRITE_ALLOWED_de744350);
      ReadOnlyFile := 0;
      Device := TDeviceSecurity.Create;
      Signature := Device.Sign(CozyText_HandoffProcessContracts_Cozy_restricted_overlay_native_compatibility_pro_2054f203);
      Check((Length(Device.DeviceID) = 64) and (Length(Signature) = 344),
        CozyText_HandoffProcessContracts_PROBE_RESTRICTED_CNG_SIGN_b6bf2e93);
      FreeAndNil(Device); WipeText(Signature);
      WipeBytes(Bytes); SetLength(Bytes, 1); Bytes[0] := 1;
      WritePublicFrame(H[1], Bytes); Close(H[1]);
      Check(WaitForSingleObject(H[2], 5000) = WAIT_OBJECT_0, CozyText_HandoffProcessContracts_PROBE_RESTRICTED_RELEASE_4cdbf7f0);
      Exit;
    end;
    if Mode = CozyText_HandoffProcessContracts_handoff_probe_dying_child_755c5973 then
    begin
      Check(ParamCount = 4, CozyText_HandoffProcessContracts_PROBE_ARGUMENT_COUNT_9cb4e081);
      for I := 0 to 2 do H[I] := HandoffProbeArgument(I + 2);
      Check(SetEvent(H[1]), CozyText_HandoffProcessContracts_PROBE_CHILD_READY_f3ab716a);
      Check(WaitForSingleObject(H[2], 10000) = WAIT_OBJECT_0,
        CozyText_HandoffProcessContracts_PROBE_CHILD_NOT_TERMINATED_31d5683c);
      Exit;
    end;
    if Mode = CozyText_HandoffProcessContracts_handoff_probe_orphan_reader_7455d879 then
    begin
      Check(ParamCount = 5, CozyText_HandoffProcessContracts_PROBE_ARGUMENT_COUNT_9cb4e081);
      for I := 0 to 3 do H[I] := HandoffProbeArgument(I + 2);
      Check(SetEvent(H[2]), CozyText_HandoffProcessContracts_PROBE_READER_READY_6683a3b6);
      Check(WaitForSingleObject(H[3], 5000) = WAIT_OBJECT_0, CozyText_HandoffProcessContracts_PROBE_READER_GATE_ebf25a3a);
      SetLength(Bytes, 16); Rejected := False;
      try
        ReadExact(H[0], Bytes, 0, 16, CozyTick + 2000);
        RequirePipeEnd(H[0], CozyTick + 2000);
      except on EHandoff do Rejected := True; end;
      Check(Rejected, CozyText_HandoffProcessContracts_PROBE_DEAD_PARENT_ACCEPTED_75daf0ef);
      { The first half was actually read before the broken-pipe rejection. }
      for I := 0 to 7 do Check(Bytes[I] = Byte(I + 1), CozyText_HandoffProcessContracts_PROBE_PARTIAL_BODY_MISSING_f60a24bc);
      WipeBytes(Bytes); SetLength(Bytes, 1); Bytes[0] := 1;
      WritePublicFrame(H[1], Bytes);
      Exit;
    end;

    Check(ParamCount = 7, CozyText_HandoffProcessContracts_PROBE_ARGUMENT_COUNT_9cb4e081);
    for I := 0 to 5 do H[I] := HandoffProbeArgument(I + 2);
    FillChar(Attributes, SizeOf(Attributes), 0);
    Attributes.nLength := SizeOf(Attributes); Attributes.bInheritHandle := True;
    Check(CreatePipe(ReadPipe, WritePipe, @Attributes, MaxHandoffBytes), CozyText_HandoffProcessContracts_PROBE_PARENT_PIPE_4aa15372);
    Check(SetHandleInformation(WritePipe, HANDLE_FLAG_INHERIT, 0), CozyText_HandoffProcessContracts_PROBE_PARENT_WRITE_PRIVATE_df93bff8);
    StartHandoffProbeProcess(CozyText_HandoffProcessContracts_handoff_probe_orphan_reader_7455d879,
      [ReadPipe, H[2], H[3], H[5]], Child);
    Close(ReadPipe);
    { H[0] is a restricted duplicate of the controller's process handle. The
      controller receives an actual handle to this specific child for cleanup. }
    Check(DuplicateHandle(GetCurrentProcess, Child.hProcess, H[0], @RemoteChild,
      SYNCHRONIZE or PROCESS_TERMINATE, False, 0), CozyText_HandoffProcessContracts_PROBE_CHILD_HANDLE_TRANSFER_371d77cb);
    SetLength(Bytes, SizeOf(UInt64));
    Move(RemoteChild, Bytes[0], SizeOf(UInt64));
    WritePublicFrame(H[1], Bytes); Close(H[1]);
    WipeBytes(Bytes); SetLength(Bytes, 8);
    for I := 0 to 7 do Bytes[I] := Byte(I + 1);
    WritePublicFrame(WritePipe, Bytes);
    Check(SetEvent(H[4]), CozyText_HandoffProcessContracts_PROBE_PARENT_PARTIAL_READY_28cb1a40);
    { Intentionally retain only this writer until the controller kills this
      process. No child has inherited a second writer for the input pipe. }
    WaitForSingleObject(GetCurrentProcess, 10000);
    raise EHandoff.Create(CozyText_HandoffProcessContracts_PROBE_PARENT_NOT_TERMINATED_a20d81b9);
  finally
    Device.Free;
    if ReadOnlyFile <> INVALID_HANDLE_VALUE then Close(ReadOnlyFile);
    WipeText(FixturePath); WipeText(Signature);
    StopHandoffProbeProcess(Child);
    Close(ReadPipe); Close(WritePipe);
    for I := 0 to High(H) do Close(H[I]);
    WipeBytes(Bytes);
  end;
end;

{ Real file objects are deliberately plain fixtures, never executables. Each
  path is created under a fresh private probe directory and only those exact
  fixture names are deleted by the probe owner. }
procedure WriteHandoffProbeFixture(const Path: string);
var FileHandle: THandle; Bytes: TBytes; Written: DWORD; I: Integer;
begin
  FileHandle := 0;
  SetLength(Bytes, 16);
  for I := 0 to High(Bytes) do Bytes[I] := Byte(I + 1);
  try
    FileHandle := CreateFileW(PWideChar(Path), GENERIC_READ or GENERIC_WRITE,
      FILE_SHARE_READ, nil, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
    Check(FileHandle <> INVALID_HANDLE_VALUE, CozyText_HandoffProcessContracts_PROBE_FIXTURE_CREATE_9da80410);
    Check(WriteFile(FileHandle, Bytes[0], Length(Bytes), Written, nil) and
      (Written = DWORD(Length(Bytes))), CozyText_HandoffProcessContracts_PROBE_FIXTURE_WRITE_5607daa3);
  finally
    if FileHandle <> INVALID_HANDLE_VALUE then Close(FileHandle);
    WipeBytes(Bytes);
  end;
end;

function RunHandoffRestrictedChildContract(const FixturePath: string): Integer;
var
  OriginalSecurity, PathBytes, Frame: TBytes;
  Needed, FrameSize, ExitCode, SIDSize: DWORD;
  Descriptor: TSecurityDescriptor;
  ACL: array[0..255] of Byte;
  AdminSID, WorldSID: array[0..67] of Byte;
  SecurityChanged: Boolean;
  Attributes: TSecurityAttributes;
  ReadPipe, WritePipe, ReplyRead, ReplyWrite, ReleaseEvent: THandle;
  Child: TProcessInformation;
begin
  Result := 0; SecurityChanged := False;
  ReadPipe := 0; WritePipe := 0; ReplyRead := 0; ReplyWrite := 0; ReleaseEvent := 0;
  FillChar(Child, SizeOf(Child), 0);
  FillChar(Attributes, SizeOf(Attributes), 0);
  Attributes.nLength := SizeOf(Attributes); Attributes.bInheritHandle := True;
  try
    Needed := 0;
    Winapi.Windows.GetFileSecurityW(PWideChar(FixturePath), DACL_SECURITY_INFORMATION,
      nil, 0, Needed);
    Check((Needed > 0) and (Needed <= 65536), CozyText_HandoffProcessContracts_PROBE_ORIGINAL_DACL_SIZE_b2220336);
    SetLength(OriginalSecurity, Needed);
    Check(Winapi.Windows.GetFileSecurityW(PWideChar(FixturePath),
      DACL_SECURITY_INFORMATION, @OriginalSecurity[0], Needed, Needed), CozyText_HandoffProcessContracts_PROBE_ORIGINAL_DACL_c2011c85);
    Check(Winapi.Windows.InitializeSecurityDescriptor(@Descriptor,
      SECURITY_DESCRIPTOR_REVISION), CozyText_HandoffProcessContracts_PROBE_DESCRIPTOR_INIT_b2e4f4de);
    SIDSize := SizeOf(AdminSID);
    Check(Winapi.Windows.CreateWellKnownSid(WinBuiltinAdministratorsSid, nil,
      @AdminSID[0], SIDSize), CozyText_HandoffProcessContracts_PROBE_ADMIN_SID_c697e89a);
    SIDSize := SizeOf(WorldSID);
    Check(Winapi.Windows.CreateWellKnownSid(WinWorldSid, nil,
      @WorldSID[0], SIDSize), CozyText_HandoffProcessContracts_PROBE_WORLD_SID_976a7a39);
    Check(Winapi.Windows.InitializeAcl(@ACL[0], SizeOf(ACL), ACL_REVISION), CozyText_HandoffProcessContracts_PROBE_ACL_INIT_9c520d75);
    Check(Winapi.Windows.AddAccessAllowedAce(@ACL[0], ACL_REVISION,
      GENERIC_READ, @WorldSID[0]), CozyText_HandoffProcessContracts_PROBE_READ_ACE_ad03f429);
    Check(Winapi.Windows.AddAccessAllowedAce(@ACL[0], ACL_REVISION,
      GENERIC_ALL, @AdminSID[0]), CozyText_HandoffProcessContracts_PROBE_ADMIN_ACE_f42d750b);
    Check(Winapi.Windows.SetSecurityDescriptorDacl(@Descriptor, True,
      @ACL[0], False), CozyText_HandoffProcessContracts_PROBE_DESCRIPTOR_DACL_fc651190);
    Check(Winapi.Windows.SetFileSecurityW(PWideChar(FixturePath),
      DACL_SECURITY_INFORMATION or PROTECTED_DACL_SECURITY_INFORMATION,
      @Descriptor), CozyText_HandoffProcessContracts_PROBE_FIXTURE_DACL_bff2f51e);
    SecurityChanged := True;
    Check(CreatePipe(ReadPipe, WritePipe, @Attributes, MaxHandoffBytes), CozyText_HandoffProcessContracts_PROBE_RESTRICTED_INPUT_1efb35ee);
    Check(SetHandleInformation(WritePipe, HANDLE_FLAG_INHERIT, 0), CozyText_HandoffProcessContracts_PROBE_RESTRICTED_INPUT_PRIVATE_4f1cafea);
    Check(CreatePipe(ReplyRead, ReplyWrite, @Attributes, MaxHandoffBytes), CozyText_HandoffProcessContracts_PROBE_RESTRICTED_REPLY_6f58e255);
    Check(SetHandleInformation(ReplyRead, HANDLE_FLAG_INHERIT, 0), CozyText_HandoffProcessContracts_PROBE_RESTRICTED_REPLY_PRIVATE_e0985e34);
    ReleaseEvent := CreateEventW(@Attributes, True, False, nil);
    Check(ReleaseEvent <> 0, CozyText_HandoffProcessContracts_PROBE_RESTRICTED_EVENT_9276b5c9);
    StartHandoffProbeProcess(CozyText_HandoffProcessContracts_handoff_probe_restricted_overlay_2043f006,
      [ReadPipe, ReplyWrite, ReleaseEvent], Child, True);
    Close(ReadPipe); Close(ReplyWrite);
    PathBytes := TEncoding.UTF8.GetBytes(FixturePath);
    FrameSize := Length(PathBytes); SetLength(Frame, SizeOf(FrameSize));
    Move(FrameSize, Frame[0], SizeOf(FrameSize));
    WritePublicFrame(WritePipe, Frame); WritePublicFrame(WritePipe, PathBytes); Close(WritePipe);
    SetLength(Frame, 1);
    ReadExact(ReplyRead, Frame, 0, 1, CozyTick + 30000);
    Check(Frame[0] = 1, CozyText_HandoffProcessContracts_PROBE_RESTRICTED_CHILD_REJECTED_5c6643a8);
    Check(WaitForSingleObject(Child.hProcess, 0) = WAIT_TIMEOUT,
      CozyText_HandoffProcessContracts_PROBE_RESTRICTED_CHILD_PREMATURE_EXIT_1b2d8744);
    Check(SetEvent(ReleaseEvent), CozyText_HandoffProcessContracts_PROBE_RESTRICTED_RELEASE_EVENT_186c5c45);
    Check(WaitForSingleObject(Child.hProcess, 3000) = WAIT_OBJECT_0,
      CozyText_HandoffProcessContracts_PROBE_RESTRICTED_CHILD_REMAINS_21b9c0f6);
    Check(Winapi.Windows.GetExitCodeProcess(Child.hProcess, ExitCode) and
      (ExitCode = 0), CozyText_HandoffProcessContracts_PROBE_RESTRICTED_CHILD_EXIT_CODE_25bc2020);
    Result := 1;
  finally
    try
      StopHandoffProbeProcess(Child);
    finally
      Close(ReadPipe); Close(WritePipe); Close(ReplyRead); Close(ReplyWrite); Close(ReleaseEvent);
      try
        if SecurityChanged then
          Check(Winapi.Windows.SetFileSecurityW(PWideChar(FixturePath),
            DACL_SECURITY_INFORMATION or UNPROTECTED_DACL_SECURITY_INFORMATION,
            @OriginalSecurity[0]), CozyText_HandoffProcessContracts_PROBE_FIXTURE_DACL_RESTORE_747990cc);
      finally
        WipeBytes(OriginalSecurity); WipeBytes(PathBytes); WipeBytes(Frame);
      end;
    end;
  end;
end;

function RunHandoffReadinessAndIdentityContracts: Integer;
var
  Attributes: TSecurityAttributes;
  Child: TProcessInformation;
  ReadyEvent, ReleaseEvent, CancelEvent, SpareEvent, HeldFile, WriteAttempt: THandle;
  Context: THandoffContext;
  OriginalInfo, ReplacementInfo: TByHandleFileInformation;
  Observation: THandoffCleanupObservation;
  TempBuffer: array[0..32767] of WideChar;
  TempLength: DWORD;
  ProbeID: TGUID;
  Directory, OriginalPath, ReplacementPath, ExpectedHash: string;
  Rejected: Boolean;
  PumpCount: Integer;
  PumpDeadline: UInt64;
begin
  Result := 0;
  FillChar(Child, SizeOf(Child), 0);
  ReadyEvent := 0; ReleaseEvent := 0; CancelEvent := 0; SpareEvent := 0;
  HeldFile := 0; WriteAttempt := 0; Context := nil;
  Directory := ''; OriginalPath := ''; ReplacementPath := '';
  FillChar(Attributes, SizeOf(Attributes), 0);
  Attributes.nLength := SizeOf(Attributes); Attributes.bInheritHandle := True;
  try
    ReadyEvent := CreateEventW(@Attributes, True, False, nil);
    ReleaseEvent := CreateEventW(@Attributes, True, False, nil);
    SpareEvent := CreateEventW(@Attributes, True, False, nil);
    CancelEvent := CreateEventW(nil, True, False, nil);
    Check((ReadyEvent <> 0) and (ReleaseEvent <> 0) and (CancelEvent <> 0) and
      (SpareEvent <> 0), CozyText_HandoffProcessContracts_PROBE_RACE_EVENTS_38d0f68d);
    StartHandoffProbeProcess(CozyText_HandoffProcessContracts_handoff_probe_dying_child_755c5973,
      [SpareEvent, ReadyEvent, ReleaseEvent], Child);
    Check(WaitForSingleObject(ReadyEvent, 3000) = WAIT_OBJECT_0, CozyText_HandoffProcessContracts_PROBE_RACE_CHILD_READY_517c8251);
    { Cancellation and readiness are both already observable. A ready event
      is never sufficient authority once cancellation has won. }
    Check(SetEvent(CancelEvent), CozyText_HandoffProcessContracts_PROBE_RACE_CANCEL_7958a8f1);
    Rejected := False;
    try WaitHandoffReadiness(ReadyEvent, Child.hProcess, CancelEvent, CozyTick + 1000);
    except on EHandoff do Rejected := True; end;
    Check(Rejected, CozyText_HandoffProcessContracts_PROBE_READY_CANCEL_ACCEPTED_6e84bb52); Inc(Result);
    Check(WaitForSingleObject(Child.hProcess, 0) = WAIT_TIMEOUT,
      CozyText_HandoffProcessContracts_PROBE_WAIT_CHANGED_CHILD_STATE_65adf972);
    Check(Winapi.Windows.ResetEvent(CancelEvent), CozyText_HandoffProcessContracts_PROBE_CANCEL_RESET_3d75925a);
    WaitHandoffReadiness(ReadyEvent, Child.hProcess, CancelEvent, CozyTick + 1000);
    Rejected := False;
    try WaitHandoffReadiness(ReadyEvent, Child.hProcess, CancelEvent, CozyTick);
    except on EHandoff do Rejected := True; end;
    Check(Rejected, CozyText_HandoffProcessContracts_PROBE_EXPIRED_READY_ACCEPTED_694c24c7);
    Inc(Result);

    { A ready child must not cause a fresh parent renewal. The callback runs
      synchronously only while readiness is still pending. }
    PumpCount := 0;
    WaitHandoffReadiness(ReadyEvent, Child.hProcess, CancelEvent,
      CozyTick + 200,
      procedure
      begin
        Inc(PumpCount);
      end);
    Check(PumpCount = 0, CozyText_HandoffProcessContracts_PROBE_READY_CALLED_PARENT_PUMP_d3916805); Inc(Result);

    Check(Winapi.Windows.ResetEvent(ReadyEvent), CozyText_HandoffProcessContracts_PROBE_PUMP_READY_RESET_96b0d0dc);
    PumpCount := 0;
    WaitHandoffReadiness(ReadyEvent, Child.hProcess, CancelEvent,
      CozyTick + 200,
      procedure
      begin
        Inc(PumpCount);
        Check(SetEvent(ReadyEvent), CozyText_HandoffProcessContracts_PROBE_PUMP_SET_READY_1505cbd0);
      end);
    Check((PumpCount = 1) and
      (WaitForSingleObject(ReadyEvent, 0) = WAIT_OBJECT_0) and
      (WaitForSingleObject(Child.hProcess, 0) = WAIT_TIMEOUT),
      CozyText_HandoffProcessContracts_PROBE_IDLE_PARENT_PUMP_NOT_ACCEPTED_b4891be2); Inc(Result);

    Check(Winapi.Windows.ResetEvent(ReadyEvent), CozyText_HandoffProcessContracts_PROBE_PUMP_FAILURE_RESET_cf426c27);
    PumpCount := 0; Rejected := False;
    try
      WaitHandoffReadiness(ReadyEvent, Child.hProcess, CancelEvent,
        CozyTick + 200,
        procedure
        begin
          Inc(PumpCount);
          raise EAbort.Create(CozyText_HandoffProcessContracts_PROBE_PARENT_RENEWAL_REJECTED_cb61e7f6);
        end);
    except
      on E: EAbort do Rejected := E.Message = CozyText_HandoffProcessContracts_PROBE_PARENT_RENEWAL_REJECTED_cb61e7f6;
    end;
    Check(Rejected and (PumpCount = 1) and
      (WaitForSingleObject(ReadyEvent, 0) = WAIT_TIMEOUT) and
      (WaitForSingleObject(Child.hProcess, 0) = WAIT_TIMEOUT),
      CozyText_HandoffProcessContracts_PROBE_PARENT_PUMP_FAILURE_SWALLOWED_3fc41166); Inc(Result);

    PumpCount := 0; Rejected := False;
    try
      WaitHandoffReadiness(ReadyEvent, Child.hProcess, CancelEvent,
        CozyTick + 200,
        procedure
        begin
          Inc(PumpCount);
          Check(SetEvent(ReadyEvent), CozyText_HandoffProcessContracts_PROBE_PUMP_CANCEL_READY_ba1a2792);
          Check(SetEvent(CancelEvent), CozyText_HandoffProcessContracts_PROBE_PUMP_CANCEL_EVENT_c01f3b73);
        end);
    except on EHandoff do Rejected := True; end;
    Check(Rejected and (PumpCount = 1) and
      (WaitForSingleObject(ReadyEvent, 0) = WAIT_OBJECT_0) and
      (WaitForSingleObject(CancelEvent, 0) = WAIT_OBJECT_0) and
      (WaitForSingleObject(Child.hProcess, 0) = WAIT_TIMEOUT),
      CozyText_HandoffProcessContracts_PROBE_PUMP_CANCEL_READY_ACCEPTED_b239cc01); Inc(Result);
    Check(Winapi.Windows.ResetEvent(CancelEvent), CozyText_HandoffProcessContracts_PROBE_PUMP_CANCEL_RESET_87e65830);
    Check(Winapi.Windows.ResetEvent(ReadyEvent), CozyText_HandoffProcessContracts_PROBE_PUMP_DEADLINE_READY_RESET_eca01cf2);

    PumpCount := 0; Rejected := False;
    PumpDeadline := CozyTick + 50;
    try
      WaitHandoffReadiness(ReadyEvent, Child.hProcess, CancelEvent, PumpDeadline,
        procedure
        begin
          Inc(PumpCount);
          Winapi.Windows.Sleep(75);
          Check(SetEvent(ReadyEvent), CozyText_HandoffProcessContracts_PROBE_PUMP_LATE_READY_cd5f9933);
        end);
    except on EHandoff do Rejected := True; end;
    Check(Rejected and (PumpCount = 1) and (CozyTick >= PumpDeadline) and
      (WaitForSingleObject(ReadyEvent, 0) = WAIT_OBJECT_0) and
      (WaitForSingleObject(Child.hProcess, 0) = WAIT_TIMEOUT),
      CozyText_HandoffProcessContracts_PROBE_PARENT_PUMP_RESTARTED_DEADLINE_5223cb1a); Inc(Result);

    { Let the exact child exit normally after announcing readiness. The
      production waiter must reject even when Windows would return the ready
      event's lower array index for two simultaneously signalled objects. }
    Check(SetEvent(ReleaseEvent), CozyText_HandoffProcessContracts_PROBE_RACE_RELEASE_0e99db10);
    Check(WaitForSingleObject(Child.hProcess, 3000) = WAIT_OBJECT_0, CozyText_HandoffProcessContracts_PROBE_RACE_CHILD_EXIT_4cf03e12);
    Rejected := False;
    try WaitHandoffReadiness(ReadyEvent, Child.hProcess, CancelEvent, CozyTick + 1000);
    except on EHandoff do Rejected := True; end;
    Check(Rejected, CozyText_HandoffProcessContracts_PROBE_READY_DEAD_CHILD_ACCEPTED_612ef97f); Inc(Result);
    Check(WaitForSingleObject(SpareEvent, 0) = WAIT_TIMEOUT,
      CozyText_HandoffProcessContracts_PROBE_READY_CHANGED_UNRELATED_EVENT_ba9bd581);

    { Incomplete contexts cannot mark readiness or clean any file. A genuine
      inherited handle to an exited probe child is used; no PID is looked up. }
    Context := THandoffContext.Create;
    Context.FOverlay := True;
    Context.FCompleted := False;
    Check(DuplicateHandle(GetCurrentProcess, Child.hProcess, GetCurrentProcess,
      @Context.FParentProcess, SYNCHRONIZE or ProcessQueryLimitedInformation,
      False, 0), CozyText_HandoffProcessContracts_PROBE_CONTEXT_PARENT_HANDLE_f16f9fe9);
    Context.FParentID := Child.dwProcessId;
    Check(DuplicateHandle(GetCurrentProcess, ReadyEvent, GetCurrentProcess,
      @Context.FReadyEvent, 0, False, DUPLICATE_SAME_ACCESS), CozyText_HandoffProcessContracts_PROBE_CONTEXT_READY_HANDLE_71fd2bb8);
    Rejected := False;
    try Context.ConfirmOverlayReadyCore;
    except on EHandoff do Rejected := True; end;
    Check(Rejected, CozyText_HandoffProcessContracts_PROBE_UNCLAIMED_CONFIRM_ACCEPTED_96947323);
    Context.CleanupOwnImageForShutdown;
    Observation := Context.OwnCleanupObservation;
    Check(not Observation.CleanupAttempted and not Observation.DispositionAccepted and
      not Observation.FileRemoved, CozyText_HandoffProcessContracts_PROBE_UNCLAIMED_SELF_CLEANUP_5fe8252e);
    Rejected := False;
    try Context.CleanupTransferredParentCore;
    except on EHandoff do Rejected := True; end;
    Check(Rejected, CozyText_HandoffProcessContracts_PROBE_UNCLAIMED_PARENT_CLEANUP_a1da6294);
    Observation := Context.ParentCleanupObservation;
    Check(not Observation.CleanupAttempted and not Observation.DispositionAccepted and
      not Observation.FileRemoved, CozyText_HandoffProcessContracts_PROBE_UNCLAIMED_CLEANUP_REPORTED_9ce96262);
    Check(Winapi.Windows.ResetEvent(ReadyEvent), CozyText_HandoffProcessContracts_PROBE_DEAD_PARENT_READY_RESET_66815242);
    Context.FCompleted := True;
    Rejected := False;
    try Context.ConfirmOverlayReadyCore;
    except on EHandoff do Rejected := True; end;
    Check(Rejected and (WaitForSingleObject(ReadyEvent, 0) = WAIT_TIMEOUT),
      CozyText_HandoffProcessContracts_PROBE_DEAD_PARENT_CONFIRM_ACCEPTED_5348bc04);
    FreeAndNil(Context); Inc(Result);

    TempLength := Winapi.Windows.GetTempPathW(Length(TempBuffer), @TempBuffer[0]);
    Check((TempLength > 0) and (TempLength < DWORD(Length(TempBuffer))), CozyText_HandoffProcessContracts_PROBE_TEMP_PATH_def6f461);
    Check(CreateGUID(ProbeID) = 0, CozyText_HandoffProcessContracts_PROBE_TEMP_ID_bcaf1b9e);
    Directory := IncludeTrailingPathDelimiter(string(PWideChar(@TempBuffer[0]))) +
      CozyText_HandoffProcessContracts_Cozy_Handoff_Ownership_4784cef0 + GUIDToString(ProbeID);
    Check(Winapi.Windows.CreateDirectoryW(PWideChar(Directory), nil), CozyText_HandoffProcessContracts_PROBE_TEMP_DIRECTORY_6f5193f3);
    OriginalPath := IncludeTrailingPathDelimiter(Directory) + CozyText_HandoffProcessContracts_owned_fixture_91790b18;
    ReplacementPath := IncludeTrailingPathDelimiter(Directory) + CozyText_HandoffProcessContracts_replacement_fixture_584c1be3;
    WriteHandoffProbeFixture(OriginalPath);
    WriteHandoffProbeFixture(ReplacementPath);
    HeldFile := OpenSafeImage(OriginalPath, False, OriginalInfo);
    ExpectedHash := HashHandle(HeldFile);
    { The production deny-write/delete pin must block both content changes
      and same-path replacement while handoff validation is in flight. }
    WriteAttempt := CreateFileW(PWideChar(OriginalPath), GENERIC_WRITE,
      FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    Check(WriteAttempt = INVALID_HANDLE_VALUE, CozyText_HandoffProcessContracts_PROBE_PIN_ALLOWS_WRITE_16609791);
    WriteAttempt := 0;
    Check(not Winapi.Windows.MoveFileExW(PWideChar(ReplacementPath),
      PWideChar(OriginalPath), MOVEFILE_REPLACE_EXISTING), CozyText_HandoffProcessContracts_PROBE_PIN_ALLOWS_REPLACE_5d0a5d6d);
    Check(WaitForSingleObject(Child.hProcess, 0) = WAIT_OBJECT_0,
      CozyText_HandoffProcessContracts_PROBE_FILE_TEST_CHANGED_PROCESS_STATE_f81ac955);
    Inc(Result);
    Close(HeldFile);

    { After releasing the pin, replace the directory entry with another
      same-byte file. Hash equality alone must not grant deletion authority. }
    Check(Winapi.Windows.MoveFileExW(PWideChar(ReplacementPath),
      PWideChar(OriginalPath), MOVEFILE_REPLACE_EXISTING), CozyText_HandoffProcessContracts_PROBE_REPLACE_AFTER_RELEASE_e22e68c5);
    Context := THandoffContext.Create;
    Context.FOverlay := True; Context.FCompleted := True;
    Context.FLauncherPath := OriginalPath;
    Context.LauncherSHA512 := ExpectedHash;
    Context.FLauncherVolume := OriginalInfo.dwVolumeSerialNumber;
    Context.FLauncherIndexHigh := OriginalInfo.nFileIndexHigh;
    Context.FLauncherIndexLow := OriginalInfo.nFileIndexLow;
    Context.FParentImage := OpenSafeImage(OriginalPath, False, ReplacementInfo);
    Check(not SameIdentity(OriginalInfo, ReplacementInfo) and
      SameText(HashHandle(Context.FParentImage), ExpectedHash), CozyText_HandoffProcessContracts_PROBE_REPLACEMENT_IDENTITY_cb22c61e);
    Check(DuplicateHandle(GetCurrentProcess, Child.hProcess, GetCurrentProcess,
      @Context.FParentProcess, SYNCHRONIZE or ProcessQueryLimitedInformation,
      False, 0), CozyText_HandoffProcessContracts_PROBE_STALE_PARENT_HANDLE_68df01f4);
    Context.FParentID := Child.dwProcessId;
    Rejected := False;
    try Context.CleanupTransferredParentCore;
    except on EHandoff do Rejected := True; end;
    Check(Rejected, CozyText_HandoffProcessContracts_PROBE_REPLACEMENT_CLEANUP_ACCEPTED_2f2ef5a1);
    Observation := Context.ParentCleanupObservation;
    Check(Observation.ExitObserved and not Observation.CleanupAttempted and
      not Observation.DispositionAccepted and not Observation.FileRemoved,
      CozyText_HandoffProcessContracts_PROBE_REPLACEMENT_OBSERVATION_cbb89e3c);
    Check(GetFileAttributesW(PWideChar(OriginalPath)) <> INVALID_FILE_ATTRIBUTES,
      CozyText_HandoffProcessContracts_PROBE_REPLACEMENT_REMOVED_6c2525fc);
    FreeAndNil(Context); Inc(Result);
    Inc(Result, RunHandoffRestrictedChildContract(OriginalPath));
  finally
    Context.Free;
    Close(HeldFile);
    if WriteAttempt <> INVALID_HANDLE_VALUE then Close(WriteAttempt);
    StopHandoffProbeProcess(Child);
    Close(ReadyEvent); Close(ReleaseEvent); Close(CancelEvent); Close(SpareEvent);
    if OriginalPath <> '' then Winapi.Windows.DeleteFileW(PWideChar(OriginalPath));
    if ReplacementPath <> '' then Winapi.Windows.DeleteFileW(PWideChar(ReplacementPath));
    if Directory <> '' then Winapi.Windows.RemoveDirectoryW(PWideChar(Directory));
    WipeText(ExpectedHash);
  end;
end;

function RunHandoffProcessContracts: Integer;
var
  Attributes: TSecurityAttributes;
  Child, Parent, Reader: TProcessInformation;
  Handles: array[0..9] of THandle;
  Bytes, Wrapping: TBytes;
  ChildID, Nonce: string;
  Rejected: Boolean;
  I: Integer;
begin
  Result := 0;
  FillChar(Handles, SizeOf(Handles), 0);
  FillChar(Child, SizeOf(Child), 0);
  FillChar(Parent, SizeOf(Parent), 0);
  FillChar(Reader, SizeOf(Reader), 0);
  FillChar(Attributes, SizeOf(Attributes), 0);
  Attributes.nLength := SizeOf(Attributes); Attributes.bInheritHandle := True;
  try
    { A child exits before sending its public hello. The parent must reject
      without inventing a hello or waiting indefinitely on the pipe. }
    Check(CreatePipe(Handles[0], Handles[1], @Attributes, MaxHandoffBytes), CozyText_HandoffProcessContracts_PROBE_HELLO_PIPE_236c0da4);
    Check(SetHandleInformation(Handles[0], HANDLE_FLAG_INHERIT, 0), CozyText_HandoffProcessContracts_PROBE_HELLO_READ_PRIVATE_fe4f91dc);
    Handles[2] := CreateEventW(@Attributes, True, False, nil);
    Handles[3] := CreateEventW(@Attributes, True, False, nil);
    StartHandoffProbeProcess(CozyText_HandoffProcessContracts_handoff_probe_dying_child_755c5973,
      [Handles[1], Handles[2], Handles[3]], Child);
    Close(Handles[1]);
    Check(WaitForSingleObject(Handles[2], 3000) = WAIT_OBJECT_0, CozyText_HandoffProcessContracts_PROBE_CHILD_START_5ae7ed87);
    StopHandoffProbeProcess(Child);
    Rejected := False;
    try Bytes := ReadHello(Handles[0], 0, CozyTick + 2000, ChildID, Nonce, Wrapping);
    except on EHandoff do Rejected := True; end;
    Check(Rejected, CozyText_HandoffProcessContracts_PROBE_DEAD_CHILD_HELLO_ACCEPTED_aba0435c);
    Check(WaitForSingleObject(Handles[3], 0) = WAIT_TIMEOUT, CozyText_HandoffProcessContracts_PROBE_UNRELATED_EVENT_CHANGED_282883a5);
    for I := 0 to 3 do Close(Handles[I]);
    Inc(Result);

    { Real three-process topology: controller -> writer parent -> reader child.
      Kill the writer after half a frame, then let the child consume the pipe. }
    Check(DuplicateHandle(GetCurrentProcess, GetCurrentProcess, GetCurrentProcess,
      @Handles[0], PROCESS_DUP_HANDLE, True, 0), CozyText_HandoffProcessContracts_PROBE_CONTROLLER_HANDLE_6210592a);
    Check(CreatePipe(Handles[1], Handles[2], @Attributes, MaxHandoffBytes), CozyText_HandoffProcessContracts_PROBE_CONTROL_PIPE_bce1a9c6);
    Check(SetHandleInformation(Handles[1], HANDLE_FLAG_INHERIT, 0), CozyText_HandoffProcessContracts_PROBE_CONTROL_PRIVATE_58008935);
    Check(CreatePipe(Handles[3], Handles[4], @Attributes, MaxHandoffBytes), CozyText_HandoffProcessContracts_PROBE_RESULT_PIPE_dcc403f4);
    Check(SetHandleInformation(Handles[3], HANDLE_FLAG_INHERIT, 0), CozyText_HandoffProcessContracts_PROBE_RESULT_PRIVATE_36f1f9b1);
    Handles[5] := CreateEventW(@Attributes, True, False, nil);
    Handles[6] := CreateEventW(@Attributes, True, False, nil);
    Handles[7] := CreateEventW(@Attributes, True, False, nil);
    Handles[8] := CreateEventW(nil, True, False, nil); // unrelated, not inherited
    Check(Handles[8] <> 0, CozyText_HandoffProcessContracts_PROBE_UNRELATED_EVENT_718e2948);
    StartHandoffProbeProcess(CozyText_HandoffProcessContracts_handoff_probe_writer_parent_1271ea3f,
      [Handles[0], Handles[2], Handles[4], Handles[5], Handles[6], Handles[7]], Parent);
    Close(Handles[0]); Close(Handles[2]); Close(Handles[4]);
    SetLength(Bytes, SizeOf(UInt64));
    ReadExact(Handles[1], Bytes, 0, Length(Bytes), CozyTick + 5000);
    Move(Bytes[0], Reader.hProcess, SizeOf(UInt64));
    Check(Reader.hProcess <> 0, CozyText_HandoffProcessContracts_PROBE_READER_HANDLE_f06f5060);
    Check(WaitForSingleObject(Handles[5], 3000) = WAIT_OBJECT_0, CozyText_HandoffProcessContracts_PROBE_READER_START_0e8e5e15);
    Check(WaitForSingleObject(Handles[6], 3000) = WAIT_OBJECT_0, CozyText_HandoffProcessContracts_PROBE_PARENT_BODY_READY_e54ed6cc);
    StopHandoffProbeProcess(Parent);
    Check(SetEvent(Handles[7]), CozyText_HandoffProcessContracts_PROBE_READER_RELEASE_18107680);
    SetLength(Bytes, 1);
    ReadExact(Handles[3], Bytes, 0, 1, CozyTick + 3000);
    Check(Bytes[0] = 1, CozyText_HandoffProcessContracts_PROBE_READER_FAILURE_REPORT_b1552566);
    Check(WaitForSingleObject(Reader.hProcess, 3000) = WAIT_OBJECT_0, CozyText_HandoffProcessContracts_PROBE_ORPHAN_REMAINS_dc4f615c);
    Check(WaitForSingleObject(Handles[8], 0) = WAIT_TIMEOUT, CozyText_HandoffProcessContracts_PROBE_UNRELATED_STATE_CHANGED_64547e53);
    Check(SetEvent(Handles[8]), CozyText_HandoffProcessContracts_PROBE_UNRELATED_HANDLE_CLOSED_d9d05279);
    Inc(Result);
    Inc(Result, RunHandoffReadinessAndIdentityContracts);
  finally
    StopHandoffProbeProcess(Child);
    StopHandoffProbeProcess(Parent);
    StopHandoffProbeProcess(Reader);
    for I := 0 to High(Handles) do Close(Handles[I]);
    WipeBytes(Bytes); WipeBytes(Wrapping); WipeText(ChildID); WipeText(Nonce);
  end;
end;
