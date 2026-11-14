{ Included only in the dedicated probe. Never enabled in A/B/O builds. }
function SocketTestResolve(var Addresses: PRelayAddrInfoEx): Integer;
begin
  case SocketTestResolveMode of
    1: begin
      SetEvent(SocketTestEntered);
      if WaitForSingleObject(SocketTestRelease, 5000) <> WAIT_OBJECT_0 then Exit(WSAETIMEDOUT);
      Addresses := SocketTestResult; Exit(0);
    end;
    2: begin Addresses := SocketTestResult; Exit(0); end;
    3: begin
      Addresses := SocketTestResult;
      SocketTestOwner.Cancel; { Completion and cancellation race. }
      Exit(0);
    end;
  else raise EInvalidOpException.Create(CozyText_RelaySocketContracts_SOCKET_TEST_MODE_398c27a7);
  end;
end;

procedure RunRelaySocketContractTests;
var
  Nodes: array[0..9] of TRelayAddrInfoEx;
  SockBytes: array[0..9, 0..27] of Byte;
  Addresses: TRelayAddresses;
  State: IHostResolution;
  Held: array[0..3] of IHostResolution;
  Client: TRelaySocketClient;
  Worker: TResolverThread;
  I, J, Baseline: Integer;
  Started: UInt64;
  Rejected, CancelValue: Boolean;
  procedure Check(Value: Boolean; const Name: string);
  begin
    if not Value then raise EInvalidOpException.Create(CozyText_RelaySocketContracts_RELAY_SOCKET_CONTRACT_c5049655 + Name);
  end;
begin
  Baseline := TInterlocked.CompareExchange(ResolverCount, 0, 0);
  Check(Baseline = 0, CozyText_RelaySocketContracts_ISOLATED_PROCESS_REQUIRED_f4b5244c);
  Check(SizeOf(TRelayAddrInfoEx) = 72, CozyText_RelaySocketContracts_ADDRINFOEX_WIN64_ABI_ead90f4f);
  FillChar(Nodes, SizeOf(Nodes), 0); FillChar(SockBytes, SizeOf(SockBytes), 0);
  for I := 0 to High(Nodes) do
  begin
    Nodes[I].Family := AF_INET6; Nodes[I].SocketType := SOCK_STREAM;
    Nodes[I].Protocol := IPPROTO_TCP; Nodes[I].AddressLength := 28;
    Nodes[I].Address := @SockBytes[I, 0];
    PWord(@SockBytes[I, 0])^ := AF_INET6; SockBytes[I, 23] := Byte(I + 1);
    if I < High(Nodes) then Nodes[I].Next := @Nodes[I + 1];
  end;
  Addresses := CopyResolvedAddresses(@Nodes[0]);
  Check(Length(Addresses) = MaxResolvedCandidates, CozyText_RelaySocketContracts_CANDIDATE_BOUND_c24d7984);
  Check(Addresses[0].Bytes[23] = 1, CozyText_RelaySocketContracts_IPV6_COPY_aa3eb8be);
  Nodes[0].Family := AF_INET; Nodes[0].AddressLength := 16;
  PWord(@SockBytes[0, 0])^ := AF_INET;
  Addresses := CopyResolvedAddresses(@Nodes[0]);
  Check((Addresses[0].Family = AF_INET) and (Addresses[0].Length = 16), CozyText_RelaySocketContracts_IPV4_COPY_0b11fc97);
  Nodes[0].AddressLength := 15;
  Addresses := CopyResolvedAddresses(@Nodes[0]);
  Check(Addresses[0].Family = AF_INET6, CozyText_RelaySocketContracts_MALFORMED_LENGTH_REJECTED_90754c44);
  Nodes[0].AddressLength := 16;
  Nodes[0].Next := @Nodes[0];
  Addresses := CopyResolvedAddresses(@Nodes[0]);
  Check(Length(Addresses) = 1, CozyText_RelaySocketContracts_PROVIDER_CYCLE_SCAN_BOUND_AND_DEDUP_7ea22404);
  Nodes[0].Next := nil;
  SocketTestResult := @Nodes[0];
  try
    SocketTestResolveMode := 2;
    State := THostResolution.Create(CozyText_RelaySocketContracts_unit_invalid_d07ebcc0, 443, CozyTick + 500);
    State.Resolve;
    Check(State.Wait(0) and (Length(State.Addresses) = 1), CozyText_RelaySocketContracts_SUCCESS_OWNED_COPY_4b1b377a);
    Check(SocketTestFreeCalls = 1, CozyText_RelaySocketContracts_RESULT_FREED_ONCE_2fb297f7);
    State := nil;

    SocketTestResolveMode := 3;
    State := THostResolution.Create(CozyText_RelaySocketContracts_unit_invalid_d07ebcc0, 443, CozyTick + 500);
    SocketTestOwner := State;
    State.Resolve;
    Check(State.Done and not State.Wait(0), CozyText_RelaySocketContracts_CANCEL_BEATS_READY_196a79ba);
    SocketTestOwner := nil; State := nil;
    Check(SocketTestFreeCalls = 2, CozyText_RelaySocketContracts_CANCEL_RESULT_FREED_b0b1df0c);

    SocketTestResolveMode := 1;
    SocketTestEntered := CreateEvent(nil, True, False, nil);
    SocketTestRelease := CreateEvent(nil, True, False, nil);
    Check((SocketTestEntered <> 0) and (SocketTestRelease <> 0), CozyText_RelaySocketContracts_TEST_EVENTS_71ef9e22);
    Started := CozyTick;
    State := THostResolution.Create(CozyText_RelaySocketContracts_unit_invalid_d07ebcc0, 443, Started + 5000);
    Worker := TResolverThread.Create(State); Worker.FreeOnTerminate := False;
    try
      Worker.Start;
      Check(WaitForSingleObject(SocketTestEntered, 1000) = WAIT_OBJECT_0, CozyText_RelaySocketContracts_DNS_ENTERED_1bf17d1f);
      State.Cancel;
      Check(not State.Wait(25) and not State.Done, CozyText_RelaySocketContracts_CANCEL_RETURNS_WITHOUT_FREEING_PROVIDER_abe57e87);
      Check(TInterlocked.CompareExchange(ResolverCount, 0, 0) = Baseline + 1,
        CozyText_RelaySocketContracts_DNS_ADMISSION_RETAINED_WHILE_PROVIDER_PENDING_6c2c60fd);
      SetEvent(SocketTestRelease);
      State.Wait(1000);
      Check(State.Done, CozyText_RelaySocketContracts_DNS_COMPLETION_DRAINED_d31324b3);
      Check(not State.Wait(0), CozyText_RelaySocketContracts_LATE_CANCELLED_RESULT_REJECTED_92653872);
      Worker.WaitFor;
    finally
      SetEvent(SocketTestRelease); Worker.WaitFor; Worker.Free; State := nil;
    end;
    Check(CozyTick - Started < 1500, CozyText_RelaySocketContracts_CONTROLLED_DNS_DRAIN_BOUND_1d42beda);
    CloseHandle(SocketTestEntered); SocketTestEntered := 0;
    CloseHandle(SocketTestRelease); SocketTestRelease := 0;
    Check(TInterlocked.CompareExchange(ResolverCount, 0, 0) = Baseline, CozyText_RelaySocketContracts_DNS_OWNERS_DRAINED_64bf216c);

    SocketTestResolveMode := 2;
    for J := 1 to 24 do
    begin
      State := THostResolution.Create(CozyText_RelaySocketContracts_unit_invalid_d07ebcc0, 443, CozyTick);
      State.Resolve; Check(not State.Wait(0), CozyText_RelaySocketContracts_EXPIRED_DNS_NOT_STARTED_776e684b); State := nil;
    end;
    Check(TInterlocked.CompareExchange(ResolverCount, 0, 0) = Baseline, CozyText_RelaySocketContracts_REPEATED_FAILURE_NO_OWNER_LEAK_15ed93a4);
    for I := 0 to High(Held) do
      Held[I] := THostResolution.Create(CozyText_RelaySocketContracts_unit_invalid_d07ebcc0, 443, CozyTick + 500);
    Rejected := False;
    try State := THostResolution.Create(CozyText_RelaySocketContracts_unit_invalid_d07ebcc0, 443, CozyTick + 500);
    except on E: EInvalidOpException do Rejected := E.Message = CozyText_RelaySocketContracts_DNS_RESOLVER_CAPACITY_2f22d45e; end;
    Check(Rejected, CozyText_RelaySocketContracts_RESOLVER_ADMISSION_CAP_7c262d13);
    for I := 0 to High(Held) do Held[I] := nil;
  finally
    SocketTestOwner := nil; State := nil;
    for I := 0 to High(Held) do Held[I] := nil;
    SocketTestResolveMode := 0; SocketTestResult := nil;
    if SocketTestEntered <> 0 then CloseHandle(SocketTestEntered);
    if SocketTestRelease <> 0 then CloseHandle(SocketTestRelease);
    SocketTestEntered := 0; SocketTestRelease := 0;
  end;
  Check(TInterlocked.CompareExchange(ResolverCount, 0, 0) = Baseline, CozyText_RelaySocketContracts_FINAL_DNS_OWNER_COUNT_b1657e8d);

  CancelValue := False;
  Client := TRelaySocketClient.Create(50, 256,
    function: Boolean begin Result := CancelValue; end);
  try
    Client.FDeadline := CozyTick + 50;
    Check(Client.RemainingTimeout(100) <= 50, CozyText_RelaySocketContracts_ONE_DEADLINE_bbea7924);
    CancelValue := True;
    Check(Client.RemainingTimeout(100) = 0, CozyText_RelaySocketContracts_CALLER_CANCEL_57fce8da);
    CancelValue := False; Client.Close;
    Check(Client.RemainingTimeout(100) = 0, CozyText_RelaySocketContracts_CLOSE_LATCH_e8fa7716);
    Check(not Client.ConnectTLS(CozyText_RelaySocketContracts_unit_invalid_d07ebcc0, 443, CozyText_RelaySocketContracts_unit_invalid_d07ebcc0, StringOfChar('0', 64)),
      CozyText_RelaySocketContracts_NO_PHASE_AFTER_CLOSE_4cee4879);
    Check(not Client.IsConnected, CozyText_RelaySocketContracts_CLOSED_RESOURCE_STATE_957f20c2);
  finally Client.Free; end;
end;
