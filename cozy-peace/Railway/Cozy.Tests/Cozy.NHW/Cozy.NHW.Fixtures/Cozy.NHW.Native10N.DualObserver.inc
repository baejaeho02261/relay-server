function TestDualObserver10N(out Failure: string; out Checks: Integer): Boolean;
var
  G: TDualObserver; Shared: TObserverShared;
  E, ReadBack: TObserverSessionEvidence; D: TDetectionKinds; I: Integer;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;
  procedure Publish(Sequence, WhenTick: UInt64; State: Cardinal; Created: UInt64);
  begin
    E := Default(TObserverSessionEvidence); E.Sequence := Sequence;
    E.OwnerPID := G.FExpectedOwnerPID; E.OwnerCreated := G.FExpectedOwnerCreated;
    E.ObserverPID := G.FChildPID; E.ObservedTick := WhenTick;
    E.ObservedCreation := Created; E.State := State;
    ObserverStore64(Shared.ProofRevision, Sequence-1);
    Shared.ProofEvidence := E;
    if not NHWSessionMAC(G.FSessionKey, E, Shared.ProofMAC) then
      raise Exception.Create('Windows BCrypt HMAC unavailable');
    ObserverStore64(Shared.ProofRevision, Sequence);
  end;
begin
  Result := False; Failure := ''; Checks := 0; G := nil;
  Shared := Default(TObserverShared);
  try
    try
      G := TDualObserver.Create; G.FView := @Shared;
      G.FChildProcess := Winapi.Windows.GetCurrentProcess;
      G.FChildPID := Winapi.Windows.GetCurrentProcessId;
      G.FExpectedOwnerPID := G.FChildPID; G.FExpectedOwnerCreated := 100;
      for I := 0 to High(G.FSessionKey) do G.FSessionKey[I] := Byte(I);
      Shared.Magic := OBSERVER_MAGIC; Shared.Version := OBSERVER_VERSION;
      Check((NativeUInt(@Shared.ProofRevision) and 7) = 0, 'shared revision aligned for interlocked access');
      Check((NativeUInt(@Shared.OwnerTick) and 7) = 0, 'owner heartbeat aligned');
      Publish(2, 10000, 1, 100);
      Check(G.ReadProof(10001, ReadBack), 'consistent authenticated healthy proof accepted');
      Check(G.AuthenticatedReport(10001), 'healthy polling preserved');
      Shared.State := 2; Shared.ObserverTick := 999999;
      Check(G.ReadProof(10001, ReadBack) and (ReadBack.State = 1), 'unsigned legacy fields never decide proof state');
      ObserverStore64(Shared.ProofRevision, 3);
      Check(not G.ReadProof(10001, ReadBack), 'in-progress odd revision rejected');
      ObserverStore64(Shared.ProofRevision, 2);
      Shared.ProofMAC[0] := Shared.ProofMAC[0] xor 1;
      Check(not G.ReadProof(10001, ReadBack), 'altered MAC rejected');
      Publish(2, 10000, 1, 100);
      Check(not G.ReadProof(13001, ReadBack), 'stale proof rejected');
      Check(not G.ReadProof(9999, ReadBack), 'future timestamp rejected');
      Publish(4, 10700, 2, 200); D := [];
      Check(G.Examine(True, 10701, D) and (G.FAnomalyConfirm = 1), 'first fresh mismatch counted');
      G.Examine(True, 10702, D); G.Examine(True, 10703, D);
      Check((G.FAnomalyConfirm = 1) and not (dkObserverMismatch in D), 'same response never becomes three confirmations');
      Publish(6, 11400, 2, 200); G.Examine(True, 11401, D);
      Check(G.FAnomalyConfirm = 2, 'second distinct response counted');
      Publish(8, 12100, 2, 200); G.Examine(True, 12101, D);
      Check(dkObserverMismatch in D, 'three distinct authenticated mismatches with evidence still report');
      Publish(10, 12800, 1, 100); D := []; G.Examine(True, 12801, D);
      Check((G.FAnomalyConfirm = 0) and (D = []), 'healthy proof breaks anomaly sequence');
      Publish(12, 13500, 2, 200); G.Examine(False, 13501, D);
      Check(G.FAnomalyConfirm = 0, 'independent evidence still required');
      G.Examine(True, 13502, D); Check(G.FAnomalyConfirm = 0, 'cannot reuse a consumed uncorrelated response');
      Publish(14, 14200, 2, 200); G.Examine(True, 14201, D);
      Check(G.FAnomalyConfirm = 1, 'new mismatch starts fresh sequence');
      Publish(16, 14200, 2, 200); G.Examine(True, 14202, D);
      Check(G.FAnomalyConfirm = 0, 'new sequence with repeated observation timestamp does not extend confirmation');
      Publish(18, 14900, 1, 200);
      Check(not G.ReadProof(14901, ReadBack), 'healthy state with mismatching identity rejected');
      Publish(20, 15600, 2, 200); G.Examine(True, 15601, D);
      G.Examine(True, 19001, D);
      Check(G.FAnomalyConfirm = 0, 'stale coverage breaks pending confirmations');
      Result := True;
    except
      on Ex: Exception do Failure := Ex.Message;
    end;
  finally
    if G <> nil then
    begin
      // These are borrowed test resources, not a mapped view or child process.
      G.FView := nil; G.FChildProcess := 0; G.FChildPID := 0;
    end;
    G.Free;
  end;
end;
