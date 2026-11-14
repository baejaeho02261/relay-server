var
  Proof10Q: TObserverSessionEvidence;
  ProofValid10Q, ProofAvailable10Q: Boolean;
  ProofCalls10Q: Integer;
function ReadProof10Q(Tick: UInt64; out Evidence: TObserverSessionEvidence;
  out Available: Boolean): Boolean;
begin
  Inc(ProofCalls10Q);
  Evidence := Proof10Q; Available := ProofAvailable10Q;
  Result := ProofValid10Q and (Tick >= Proof10Q.ObservedTick);
end;
function TestObserverAttestation10Q(out Failure: string; out Checks: Integer): Boolean;
var
  A: TObserverAttestation; O: TDualObserver;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  A := nil; O := nil;
  try
    try
      A := TObserverAttestation.Create; O := TDualObserver.Create;
      AttestationRead10Q := ReadProof10Q;
      Proof10Q := Default(TObserverSessionEvidence);
      Proof10Q.ObserverPID := 400; Proof10Q.OwnerPID := 500; Proof10Q.OwnerCreated := 999;
      Proof10Q.State := 1; Proof10Q.Sequence := 2; Proof10Q.ObservedTick := 1000;
      ProofValid10Q := True; ProofAvailable10Q := True; ProofCalls10Q := 0;
      A.Examine(O, True, True, 1100);
      Check(ProofCalls10Q = 1, 'one verified payload read');
      Check(A.Grade = oagAuthenticated, 'valid proof grade');
      Check(A.LastAuthenticated = 1000, 'proof time not polling time');
      Check(A.LastSequence = 2, 'same proof sequence recorded');
      A.Examine(O, True, True, 1200);
      Check(ProofCalls10Q = 2, 'one read on next poll');
      Check((A.LastAuthenticated = 1000) and (A.LastSequence = 2), 'duplicate not fresh attestation');
      Proof10Q.Sequence := 4; Proof10Q.ObservedTick := 1300;
      A.Examine(O, True, True, 1400);
      Check((A.LastSequence = 4) and (A.LastAuthenticated = 1300), 'fresh proof advances');
      Proof10Q.Sequence := 2; Proof10Q.ObservedTick := 1000;
      A.Examine(O, True, True, 1500);
      Check((A.Grade = oagStale) and (A.LastSequence = 4), 'replayed older sequence rejected');
      Proof10Q.Sequence := 4; Proof10Q.ObservedTick := 1400;
      A.Examine(O, True, True, 1500); Check(A.Grade = oagStale, 'same sequence cannot change proof time');
      Proof10Q.Sequence := 6; Proof10Q.ObservedTick := 1300;
      A.Examine(O, True, True, 1500); Check(A.Grade = oagStale, 'new sequence with old time rejected');
      ProofAvailable10Q := False;
      A.Examine(O, True, True, 1500); Check(A.Grade = oagUnavailable, 'availability from same acquisition');
      ProofAvailable10Q := True; ProofValid10Q := False;
      A.Examine(O, True, True, 1500); Check(A.Grade = oagStale, 'invalid MAC copy not authenticated');
      ProofValid10Q := True; Proof10Q.ObserverPID := 401;
      Proof10Q.Sequence := 2; Proof10Q.ObservedTick := 1600;
      A.Examine(O, True, True, 1700);
      Check((A.Grade = oagAuthenticated) and (A.LastSequence = 2), 'new observer session starts a new proof run');
      A.Examine(O, True, False, 1800);
      Check((A.Grade = oagUnknown) and (A.LastAuthenticated = 0), 'unstable target resets attestation');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    AttestationRead10Q := nil; A.Free; O.Free;
  end;
end;
