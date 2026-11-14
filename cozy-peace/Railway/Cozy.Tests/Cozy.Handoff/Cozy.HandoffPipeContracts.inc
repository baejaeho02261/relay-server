{ Test-only writer: no anonymous-method capture and no external process.
  Payloads are <= 4096 bytes, below the 65536-byte anonymous-pipe buffer,
  so writes cannot wait for a reader to make buffer space. }
type
  THandoffProbeFragmentWriter = class
  public
    Pipe, CancelEvent, FirstWriteEvent, ContinueEvent: THandle;
    Bytes: TBytes;
    Fragments: TArray<Integer>;
    GapMs, HoldOpenMs: DWORD;
    BytesWritten: Integer;
    PipeClosed: Boolean;
    destructor Destroy; override;
  end;

destructor THandoffProbeFragmentWriter.Destroy;
begin
  WipeBytes(Bytes); Fragments := nil;
  Close(Pipe); Close(CancelEvent); Close(FirstWriteEvent); Close(ContinueEvent);
  inherited;
end;

function WriteHandoffProbeFragments(Parameter: Pointer): Integer;
var Writer: THandoffProbeFragmentWriter; I, At: Integer;
  Written, Status: DWORD; StartHandles: array[0..1] of THandle;
begin
  Result := 1;
  Writer := THandoffProbeFragmentWriter(Parameter);
  try
    try
      At := 0;
      for I := 0 to High(Writer.Fragments) do
      begin
        if I = 0 then Status := WaitForSingleObject(Writer.CancelEvent, 0)
        else Status := WaitForSingleObject(Writer.CancelEvent, Writer.GapMs);
        if Status = WAIT_OBJECT_0 then Exit(0);
        Check(Status = WAIT_TIMEOUT, CozyText_HandoffPipeContracts_PROBE_FRAGMENT_CANCEL_WAIT_f0fb35e9);
        Check((Writer.Fragments[I] > 0) and
          (Writer.Fragments[I] <= Length(Writer.Bytes) - At), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_RANGE_2d36354a);
        Check(WriteFile(Writer.Pipe, Writer.Bytes[At], Writer.Fragments[I], Written, nil) and
          (Written = DWORD(Writer.Fragments[I])), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_WRITE_2c156584);
        Inc(At, Integer(Written)); Writer.BytesWritten := At;
        if I = 0 then
        begin
          Check(SetEvent(Writer.FirstWriteEvent), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_FIRST_WRITE_2246c1ff);
          StartHandles[0] := Writer.CancelEvent; StartHandles[1] := Writer.ContinueEvent;
          Status := WaitForMultipleObjects(2, @StartHandles[0], False, 3000);
          if Status = WAIT_OBJECT_0 then Exit(0);
          Check(Status = WAIT_OBJECT_0 + 1, CozyText_HandoffPipeContracts_PROBE_FRAGMENT_START_GATE_e1d74120);
        end;
      end;
      Check(At = Length(Writer.Bytes), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_PLAN_INCOMPLETE_1c6415cc);
      Status := WaitForSingleObject(Writer.CancelEvent, Writer.HoldOpenMs);
      Check((Status = WAIT_TIMEOUT) or (Status = WAIT_OBJECT_0), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_CLOSE_WAIT_5adcfd8f);
      Result := 0;
    except
      Result := 1;
    end;
  finally
    Writer.PipeClosed := (Writer.Pipe <> 0) and CloseHandle(Writer.Pipe);
    if Writer.PipeClosed then Writer.Pipe := 0 else Result := 1;
  end;
end;

function HandoffProbeByteFragments(Count: Integer): TArray<Integer>;
var I: Integer;
begin
  SetLength(Result, Count);
  for I := 0 to Count - 1 do Result[I] := 1;
end;

function HandoffProbeSplitFragments(Count, Cut: Integer): TArray<Integer>;
begin
  Check((Cut > 0) and (Cut < Count), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_CUT_af09d4ae);
  SetLength(Result, 2); Result[0] := Cut; Result[1] := Count - Cut;
end;

procedure CloseHandoffProbeHandle(var Handle: THandle);
begin
  if Handle = 0 then Exit;
  Check(CloseHandle(Handle), CozyText_HandoffPipeContracts_PROBE_OWNED_HANDLE_CLOSE_7ff7b371);
  Handle := 0;
end;

function ReadHandoffProbeFrame(Pipe: THandle; Count: Integer;
  Deadline: UInt64): TBytes;
var Candidate: TBytes; I: Integer;
begin
  Result := nil; Candidate := nil;
  Check((Count >= 4) and (Count <= 4096), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_FRAME_SIZE_ca4edec6);
  try
    try
      SetLength(Candidate, Count + 8);
      FillChar(Candidate[0], Length(Candidate), $A5);
      { Header and body consume ONE original deadline; neither phase restarts it. }
      ReadExact(Pipe, Candidate, 4, 4, Deadline);
      ReadExact(Pipe, Candidate, 8, Count - 4, Deadline);
      RequirePipeEnd(Pipe, Deadline);
      for I := 0 to 3 do
        Check((Candidate[I] = $A5) and (Candidate[Count + 4 + I] = $A5),
          CozyText_HandoffPipeContracts_PROBE_FRAGMENT_GUARD_CHANGED_b5c72177);
      SetLength(Result, Count); Move(Candidate[4], Result[0], Count);
    except
      WipeBytes(Result);
      raise;
    end;
  finally
    WipeBytes(Candidate);
  end;
end;

procedure RunHandoffFragmentCase(const Wire, Expected: TBytes;
  const Fragments: TArray<Integer>; GapMs, HoldOpenMs, BudgetMs: DWORD;
  ReadAsHello, MustReject: Boolean; const ExpectedKeyID, ExpectedNonce: string;
  MinimumWritten, MaximumWritten: Integer);
var Writer: THandoffProbeFragmentWriter; ReadPipe, WritePipe, WriterThread: THandle;
  Output, Wrapping: TBytes; KeyID, Nonce: string;
  Deadline, StartedAt, Elapsed: UInt64; ExitStatus, ThreadID: DWORD;
  Rejected, Joined: Boolean; I, Planned: Integer;
begin
  Writer := nil; ReadPipe := 0; WritePipe := 0; WriterThread := 0;
  Output := nil; Wrapping := nil; Joined := False;
  try
    Check((Length(Wire) > 0) and (Length(Wire) <= 4096) and
      (Length(Fragments) > 0) and (BudgetMs > 0), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_INPUT_a9089f07);
    Planned := 0;
    for I := 0 to High(Fragments) do
    begin
      Check((Fragments[I] > 0) and (Fragments[I] <= Length(Wire) - Planned),
        CozyText_HandoffPipeContracts_PROBE_FRAGMENT_PLAN_2a2e2fce);
      Inc(Planned, Fragments[I]);
    end;
    Check(Planned = Length(Wire), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_PLAN_SIZE_8b10bbbb);
    Check(CreatePipe(ReadPipe, WritePipe, nil, MaxHandoffBytes), CozyText_HandoffPipeContracts_PROBE_PIPE_CREATE_e80a470b);
    Writer := THandoffProbeFragmentWriter.Create;
    Writer.Bytes := Copy(Wire); Writer.Fragments := Copy(Fragments);
    Writer.GapMs := GapMs; Writer.HoldOpenMs := HoldOpenMs;
    Writer.CancelEvent := CreateEventW(nil, True, False, nil);
    Writer.FirstWriteEvent := CreateEventW(nil, True, False, nil);
    Writer.ContinueEvent := CreateEventW(nil, True, False, nil);
    Check((Writer.CancelEvent <> 0) and (Writer.FirstWriteEvent <> 0) and
      (Writer.ContinueEvent <> 0), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_EVENTS_54984a84);
    Writer.Pipe := WritePipe; WritePipe := 0;
    WriterThread := BeginThread(nil, 0, WriteHandoffProbeFragments, Writer, 0, ThreadID);
    Check(WriterThread <> 0, CozyText_HandoffPipeContracts_PROBE_FRAGMENT_THREAD_7af2793f);
    try
      { Prove actual input was written, so timeout cases cannot pass merely
        because the OS did not schedule the writer before the test started. }
      Check(WaitForSingleObject(Writer.FirstWriteEvent, 2000) = WAIT_OBJECT_0,
        CozyText_HandoffPipeContracts_PROBE_FRAGMENT_WRITER_NOT_STARTED_c542a2bb);
      StartedAt := CozyTick; Deadline := StartedAt + BudgetMs;
      Check(SetEvent(Writer.ContinueEvent), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_ARM_READER_f7cbb31a);
      Rejected := False;
      try
        if ReadAsHello then Output := ReadHello(ReadPipe, 0, Deadline, KeyID, Nonce, Wrapping)
        else Output := ReadHandoffProbeFrame(ReadPipe, Length(Expected), Deadline);
      except
        on EHandoff do Rejected := True;
      end;
      Elapsed := CozyTick - StartedAt;
      Check(Rejected = MustReject, CozyText_HandoffPipeContracts_PROBE_FRAGMENT_WRONG_OUTCOME_0175d4b6);
      Check(Elapsed <= UInt64(BudgetMs) + 1500, CozyText_HandoffPipeContracts_PROBE_FRAGMENT_DEADLINE_RESTARTED_f75beb8e);
      if MustReject then
        Check((Length(Output) = 0) and (Length(Wrapping) = 0) and
          (KeyID = '') and (Nonce = ''), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_PARTIAL_OUTPUT_db845b2c)
      else
      begin
        Check((Length(Output) = Length(Expected)) and
          CompareMem(@Output[0], @Expected[0], Length(Expected)), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_BYTES_a16b0a97);
        if ReadAsHello then
          Check((KeyID = ExpectedKeyID) and (Nonce = ExpectedNonce) and
            (Length(Wrapping) >= 281) and (Length(Wrapping) <= 288), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_HELLO_8a7446d3);
      end;
    finally
      { Cancel every delay, then join BEFORE touching the shared context or
        closing its event/pipe handles, including an assertion exception. }
      SetEvent(Writer.CancelEvent);
      Joined := WaitForSingleObject(WriterThread, 2000) = WAIT_OBJECT_0;
      { A probe cannot safely free a context still owned by a stalled thread.
        Fail the isolated test process; Windows reclaims its owned resources. }
      if not Joined then Halt(86);
    end;
    Check(GetExitCodeThread(WriterThread, ExitStatus) and (ExitStatus = 0),
      CozyText_HandoffPipeContracts_PROBE_FRAGMENT_WRITER_FAILED_f90a56f2);
    Check(Writer.PipeClosed and (Writer.Pipe = 0), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_WRITER_HANDLE_22ea3b58);
    Check((Writer.BytesWritten >= MinimumWritten) and
      (Writer.BytesWritten <= MaximumWritten), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_PROGRESS_4b68b201);
    CloseHandoffProbeHandle(WriterThread);
    CloseHandoffProbeHandle(Writer.CancelEvent);
    CloseHandoffProbeHandle(Writer.FirstWriteEvent);
    CloseHandoffProbeHandle(Writer.ContinueEvent);
    CloseHandoffProbeHandle(ReadPipe);
    WipeBytes(Writer.Bytes);
    Check((WriterThread = 0) and (ReadPipe = 0) and (WritePipe = 0) and
      (Writer.CancelEvent = 0) and (Writer.FirstWriteEvent = 0) and
      (Writer.ContinueEvent = 0) and
      (Length(Writer.Bytes) = 0), CozyText_HandoffPipeContracts_PROBE_FRAGMENT_REMAINDER_2190e36f);
  finally
    { If BeginThread itself failed, no worker ever borrowed this context. }
    if (WriterThread <> 0) and not Joined then
    begin
      SetEvent(Writer.CancelEvent);
      if WaitForSingleObject(WriterThread, 2000) <> WAIT_OBJECT_0 then Halt(86);
    end;
    Close(WriterThread); Writer.Free;
    Close(ReadPipe); Close(WritePipe);
    WipeBytes(Output); WipeBytes(Wrapping); WipeText(KeyID); WipeText(Nonce);
  end;
end;

function RunFragmentedHandoffPipeContracts: Integer;
var Input, Hello, Changed: TBytes; Fragments: TArray<Integer>;
  Device: TDeviceSecurity; Cipher: THandoffCipher; Nonce: string;
  I, Cut: Integer; ReadPipe, WritePipe: THandle; Rejected: Boolean;
  Header: TChildHelloHeader;
begin
  Result := 0; Input := nil; Hello := nil; Changed := nil;
  Device := nil; Cipher := nil; ReadPipe := 0; WritePipe := 0;
  try
    SetLength(Input, 24);
    for I := 0 to High(Input) do Input[I] := Byte(I + 1);
    { All two-fragment cut positions of a complete two-phase frame. }
    for Cut := 1 to Length(Input) - 1 do
    begin
      RunHandoffFragmentCase(Input, Input, HandoffProbeSplitFragments(Length(Input), Cut),
        2, 0, 3000, False, False, '', '', Length(Input), Length(Input));
      Inc(Result);
    end;
    RunHandoffFragmentCase(Input, Input, HandoffProbeByteFragments(Length(Input)),
      2, 0, 3000, False, False, '', '', Length(Input), Length(Input)); Inc(Result);
    { Progress cannot restart the deadline; first byte is actually present. }
    RunHandoffFragmentCase(Input, Input, HandoffProbeByteFragments(Length(Input)),
      25, 0, 80, False, True, '', '', 1, Length(Input)); Inc(Result);
    { End-of-pipe is part of the same budget, even after every byte arrived. }
    SetLength(Fragments, 1); Fragments[0] := Length(Input);
    RunHandoffFragmentCase(Input, Input, Fragments,
      0, 500, 80, False, True, '', '', Length(Input), Length(Input)); Inc(Result);
    SetLength(Changed, Length(Input) + 1); Move(Input[0], Changed[0], Length(Input));
    Changed[High(Changed)] := $EE;
    RunHandoffFragmentCase(Changed, Input, HandoffProbeSplitFragments(Length(Changed), Length(Input)),
      30, 0, 3000, False, True, '', '', Length(Changed), Length(Changed)); Inc(Result);
    { A closed pipe at an already expired deadline must also be rejected. }
    Check(CreatePipe(ReadPipe, WritePipe, nil, MaxHandoffBytes), CozyText_HandoffPipeContracts_PROBE_PIPE_CREATE_e80a470b);
    CloseHandoffProbeHandle(WritePipe); Rejected := False;
    try RequirePipeEnd(ReadPipe, CozyTick);
    except on EHandoff do Rejected := True; end;
    Check(Rejected, CozyText_HandoffPipeContracts_PROBE_EXPIRED_EOF_ACCEPTED_678694a6); Inc(Result);
    CloseHandoffProbeHandle(ReadPipe);

    { Maximum public frame size, including every one-byte boundary. }
    SetLength(Changed, 4096);
    for I := 0 to High(Changed) do Changed[I] := Byte(I and $FF);
    RunHandoffFragmentCase(Changed, Changed, HandoffProbeByteFragments(Length(Changed)),
      0, 0, 3000, False, False, '', '', Length(Changed), Length(Changed)); Inc(Result);

    Device := TDeviceSecurity.Create; Cipher := THandoffCipher.Create;
    Hello := BuildHello(0, Device, Cipher, Nonce);
    { Actual valid public hello: every header/key/nonce boundary is fragmented. }
    RunHandoffFragmentCase(Hello, Hello, HandoffProbeByteFragments(Length(Hello)),
      1, 0, 30000, True, False, Device.DeviceID, Nonce, Length(Hello), Length(Hello)); Inc(Result);
    for Cut := SizeOf(TChildHelloHeader) - 1 to SizeOf(TChildHelloHeader) + 1 do
    begin
      RunHandoffFragmentCase(Hello, Hello, HandoffProbeSplitFragments(Length(Hello), Cut),
        5, 0, 3000, True, False, Device.DeviceID, Nonce, Length(Hello), Length(Hello));
      Inc(Result);
    end;
    for Cut := 0 to 1 do
    begin
      if Cut = 0 then Changed := Copy(Hello, 0, SizeOf(TChildHelloHeader) - 1)
      else Changed := Copy(Hello, 0, Length(Hello) - 1);
      RunHandoffFragmentCase(Changed, Hello, HandoffProbeByteFragments(Length(Changed)),
        0, 0, 3000, True, True, '', '', Length(Changed), Length(Changed)); Inc(Result);
    end;
    SetLength(Fragments, 3); Fragments[0] := SizeOf(TChildHelloHeader);
    Fragments[1] := 1; Fragments[2] := Length(Hello) - Fragments[0] - 1;
    RunHandoffFragmentCase(Hello, Hello, Fragments,
      60, 0, 80, True, True, '', '', SizeOf(TChildHelloHeader), Length(Hello)); Inc(Result);
    Changed := Copy(Hello); Move(Changed[0], Header, SizeOf(Header));
    Header.Nonce[63] := Ord('G'); Move(Header, Changed[0], SizeOf(Header));
    SetLength(Fragments, 1); Fragments[0] := Length(Changed);
    RunHandoffFragmentCase(Changed, Hello, Fragments,
      0, 0, 3000, True, True, '', '', Length(Changed), Length(Changed)); Inc(Result);
  finally
    Close(ReadPipe); Close(WritePipe); Cipher.Free; Device.Free;
    WipeBytes(Input); WipeBytes(Hello); WipeBytes(Changed); WipeText(Nonce);
    FillChar(Header, SizeOf(Header), 0); Fragments := nil;
  end;
end;

{ Windows-only: exercises actual production pipe I/O helpers and malformed
  frames. It creates only anonymous pipes, never a server or child process. }
function RunHandoffPipeContracts: Integer;
var
  ReadPipe, WritePipe: THandle;
  Input, Output, Hello, Wrapping: TBytes;
  Header: TChildHelloHeader;
  ChildID, Nonce, Text: string;
  I, Mode, Offset: Integer;
  Rejected: Boolean;
  procedure NewPipe;
  begin
    Check(CreatePipe(ReadPipe, WritePipe, nil, MaxHandoffBytes), CozyText_HandoffPipeContracts_PROBE_PIPE_CREATE_e80a470b);
  end;
begin
  Result := 0; ReadPipe := 0; WritePipe := 0;
  try
    CheckABI;
    SetLength(Input, 16);
    for I := 0 to High(Input) do Input[I] := Byte(I + 1);
    for Mode := 0 to 3 do
    begin
      NewPipe;
      try
        SetLength(Output, 16); FillChar(Output[0], Length(Output), 0);
        case Mode of
          0: begin WritePublicFrame(WritePipe, Input); Close(WritePipe); end;
          1: begin SetLength(Input, 8); WritePublicFrame(WritePipe, Input); Close(WritePipe); end;
          2: begin SetLength(Input, 16); WritePublicFrame(WritePipe, Input); Close(WritePipe); end;
          3: ; // no bytes; an already elapsed monotonic budget must reject.
        end;
        Rejected := False;
        try
          if Mode = 3 then ReadExact(ReadPipe, Output, 0, 16, CozyTick)
          else if Mode = 2 then
          begin
            ReadExact(ReadPipe, Output, 0, 8, CozyTick + 1000);
            RequirePipeEnd(ReadPipe, CozyTick + 1000);
          end
          else
          begin
            ReadExact(ReadPipe, Output, 0, 16, CozyTick + 1000);
            RequirePipeEnd(ReadPipe, CozyTick + 1000);
          end;
        except on EHandoff do Rejected := True; end;
        if Mode = 0 then Check(not Rejected and CompareMem(@Input[0], @Output[0], 16), CozyText_HandoffPipeContracts_PROBE_PIPE_ROUNDTRIP_49763021)
        else Check(Rejected, CozyText_HandoffPipeContracts_PROBE_PIPE_FAILURE_ACCEPTED_234352a8);
        Inc(Result);
      finally Close(ReadPipe); Close(WritePipe); end;
    end;

    { Malformed public hello is rejected before allocating variable payload. }
    for Mode := 0 to 3 do
    begin
      FillChar(Header, SizeOf(Header), 0);
      Header.Magic := HelloMagic; Header.Version := HandoffVersion;
      Header.ComponentRole := 0; Header.SigningBytes := 376; Header.WrappingBytes := 281;
      case Mode of
        0: Header.Version := 2;
        1: Header.ComponentRole := 1;
        2: Header.SigningBytes := High(DWORD);
        3: Header.WrappingBytes := 0;
      end;
      SetLength(Hello, SizeOf(Header)); Move(Header, Hello[0], SizeOf(Header));
      NewPipe;
      try
        WritePublicFrame(WritePipe, Hello); Close(WritePipe);
        Rejected := False;
        try Output := ReadHello(ReadPipe, 0, CozyTick + 1000, ChildID, Nonce, Wrapping);
        except on EHandoff do Rejected := True; end;
        Check(Rejected, CozyText_HandoffPipeContracts_PROBE_HELLO_FAILURE_ACCEPTED_e63cd9d4); Inc(Result);
      finally Close(ReadPipe); Close(WritePipe); end;
    end;

    Rejected := False;
    try ReadExact(0, Output, -1, 1, CozyTick + 1000);
    except on EHandoff do Rejected := True; end;
    Check(Rejected, CozyText_HandoffPipeContracts_PROBE_NEGATIVE_READ_ACCEPTED_dcb294b6); Inc(Result);
    Offset := Length(Input) + 1; Rejected := False;
    try Text := DecodeField(Input, Offset, 1);
    except on EHandoff do Rejected := True; end;
    Check(Rejected, CozyText_HandoffPipeContracts_PROBE_FIELD_OVERFLOW_ACCEPTED_f12b9b94); Inc(Result);
    SetLength(Input, 4097); Rejected := False;
    try WritePublicFrame(0, Input);
    except on EHandoff do Rejected := True; end;
    Check(Rejected, CozyText_HandoffPipeContracts_PROBE_PUBLIC_FRAME_OVERSIZE_ACCEPTED_245a3f79); Inc(Result);
    Inc(Result, RunFragmentedHandoffPipeContracts);
  finally
    Close(ReadPipe); Close(WritePipe);
    WipeBytes(Input); WipeBytes(Output); WipeBytes(Hello); WipeBytes(Wrapping);
    WipeText(ChildID); WipeText(Nonce); WipeText(Text);
  end;
end;
