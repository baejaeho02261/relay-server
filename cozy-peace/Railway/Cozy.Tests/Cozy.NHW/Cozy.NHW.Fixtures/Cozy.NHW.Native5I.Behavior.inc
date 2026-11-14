function TestBehavior5I(out Failure: string; out Checks: Integer): Boolean;
var
  M: TBehaviorFingerprint;
  I, N, BeforeScore: Integer;
  Before: TActorBehaviorFrame;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  function ActorIndex(A: UInt64): Integer;
  var J: Integer;
  begin
    Result := -1;
    for J := Low(M.FFrames) to High(M.FFrames) do
      if M.FFrames[J].AliasId = A then Exit(J);
  end;
  function CountActor(A: UInt64): Integer;
  var J: Integer;
  begin
    Result := 0;
    for J := Low(M.FFrames) to High(M.FFrames) do
      if M.FFrames[J].AliasId = A then Inc(Result);
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := TBehaviorFingerprint.Create;
  try
    try
      M.Observe(1, ACCESS_QUERY_INFORMATION, False, True, 1000);
      M.Observe(2, ACCESS_VM_READ, False, True, 50000);
      M.Observe(2, ACCESS_VM_WRITE, False, True, 62000);
      Check(CountActor(2) = 1, 'existing actor wins over expired earlier slot');
      Check(M.FFrames[ActorIndex(2)].Escalations = 1, 'previous process rights kept');
      Check(M.FFrames[0].AliasId = 1, 'expired slot not overwritten when actor exists');
      M.FFrames[0] := Default(TActorBehaviorFrame);
      M.Observe(2, ACCESS_VM_READ, False, True, 63000);
      Check(CountActor(2) = 1, 'existing actor wins over empty earlier slot');
      M.Observe(2, ACCESS_VM_WRITE, False, True, 124001);
      Check(M.FFrames[ActorIndex(2)].FirstTick = 124001, 'same expired actor starts new frame');
      Check(M.FFrames[ActorIndex(2)].Escalations = 0, 'expired escalation cleared');
      Check(M.FFrames[ActorIndex(2)].WriteEdges = 1, 'expired counts do not carry');
      Before := M.FFrames[ActorIndex(2)];
      M.Observe(2, ACCESS_QUERY_INFORMATION, False, True, 124000);
      Check(M.FFrames[ActorIndex(2)].LastTick = Before.LastTick, 'late event ignored');
      Check(M.FFrames[ActorIndex(2)].LastRights = Before.LastRights, 'late rights ignored');
      M.Reset;
      M.Observe(7, ACCESS_VM_READ, False, True, 1000); // same bit as THREAD_SET_CONTEXT
      M.Observe(7, THREAD_SET_CONTEXT_RIGHT, True, True, 1100);
      Check(M.FFrames[0].Escalations = 0, 'first thread observation is not process escalation');
      M.Observe(7, THREAD_QUERY_INFORMATION_RIGHT, True, True, 1200);
      M.Observe(7, ACCESS_VM_READ, False, True, 1300);
      M.Observe(7, THREAD_SET_CONTEXT_RIGHT, True, True, 1400);
      Check(M.FFrames[0].Escalations = 1, 'thread escalation uses thread lane despite process interleave');
      M.Observe(7, ACCESS_VM_WRITE, False, True, 1500);
      Check(M.FFrames[0].Escalations = 2, 'process escalation uses process lane');
      Check((M.FFrames[0].LastProcessRights = ACCESS_VM_WRITE) and
        (M.FFrames[0].LastThreadRights = THREAD_SET_CONTEXT_RIGHT), 'lanes stored separately');
      M.Reset;
      M.Observe(8, THREAD_QUERY_INFORMATION_RIGHT, True, True, 1000);
      M.Observe(8, ACCESS_VM_READ, False, True, 50000);
      M.Observe(8, THREAD_SET_CONTEXT_RIGHT, True, True, 62001);
      Check(M.FFrames[0].Escalations = 0, 'active process lane cannot refresh expired thread lane');
      M.Reset;
      for I := 1 to 128 do M.Observe(UInt64(I), ACCESS_QUERY_INFORMATION, False, True, UInt64(I));
      M.Observe(129, ACCESS_VM_WRITE, False, True, 200);
      Check(ActorIndex(1) = -1, 'full table replaces oldest');
      Check((CountActor(129) = 1) and (ActorIndex(128) >= 0), 'full table admits new actor without harming newest');
      N := 0; for I := 0 to 127 do if M.FFrames[I].AliasId <> 0 then Inc(N);
      Check(N = 128, 'capacity remains bounded');
      M.Reset;
      M.Observe(55, ACCESS_VM_READ, False, True, 1000);
      M.Observe(55, ACCESS_VM_READ, False, True, 1100);
      Check(M.Score(55, 1100) = 18, 'existing score rule retained');
      Check(M.Score(55, 16100) = 18, 'score boundary inclusive');
      Check(M.Score(55, 16101) = 0, 'stale score not exposed');
      Check(M.Score(55, 900) = 0, 'future observation not exposed');
      BeforeScore := M.Score(55, 1100);
      M.Observe(0, ACCESS_VM_WRITE, False, True, 1200);
      M.Observe(55, 0, False, True, 1200);
      M.Observe(55, ACCESS_VM_WRITE, False, False, 1200);
      Check(M.Score(55, 1100) = BeforeScore, 'invalid/non-new observations do not mutate score');
      M.FFrames[0].ReadEdges := High(Word); M.FFrames[0].WriteEdges := High(Word);
      M.FFrames[0].ThreadEdges := High(Word); M.FFrames[0].Escalations := High(Word);
      M.Observe(55, ACCESS_VM_READ or ACCESS_VM_WRITE, False, True, 1300);
      M.Observe(55, THREAD_SET_CONTEXT_RIGHT, True, True, 1400);
      Check((M.FFrames[0].ReadEdges = High(Word)) and (M.FFrames[0].ThreadEdges = High(Word)), 'edge counters saturate');
      Check(M.Score(55, 1400) = 100, 'score upper bound retained');
      M.Reset;
      Check(M.Score(55, 1400) = 0, 'reset clears actors');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally M.Free; end;
end;
