var
  Self5KStamp: UInt64;
  Self5KIdentityOK, Self5KPrivate: Boolean;

function MockSelfIdentity5K(ID: Cardinal; Start: NativeUInt;
  out Created: UInt64): Boolean;
begin
  Created := 0;
  Result := Self5KIdentityOK and (ID <> 0) and (Start <> 0);
  if Result then Created := Self5KStamp;
end;
function MockSelfPrivate5K(Address: NativeUInt): Boolean;
begin Result := Self5KPrivate and (Address <> 0); end;

function TestSelfGuard5K(out Failure: string; out Checks: Integer): Boolean;
var M: TSelfGuardMonitor; Threads: TThreadSampleMap; S: TThreadSample;
    K: TDetectionKinds; P: TSelfThreadPending;
  procedure Check(C: Boolean; const Name: string);
  begin Inc(Checks); if not C then raise Exception.Create(Name); end;
  procedure Observe(Valid, Base: Boolean; Tick: UInt64; Worker: Cardinal = 0);
  begin K := []; M.CheckThreads(Threads, Valid, Base, Worker, Tick, K); end;
  procedure AddSample(ID: Cardinal; Start: NativeUInt);
  begin
    S := Default(TThreadSample); S.ThreadID := ID; S.StartAddress := Start;
    Threads.AddOrSetValue(ID, S);
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil; Threads := nil;
  SelfIdentity5KHook := MockSelfIdentity5K;
  SelfPrivate5KHook := MockSelfPrivate5K;
  Self5KStamp := 100; Self5KIdentityOK := True; Self5KPrivate := True;
  try
    try
      M := TSelfGuardMonitor.Create; Threads := TThreadSampleMap.Create;
      AddSample(11, $100000);
      Observe(True, True, 1000);
      Check(M.FKnownThreads[11] = 100, 'baseline stores birth, not TID alone');
      Check(not M.FThreadPrimed, 'quiet baseline remains quiet');
      Observe(True, False, 2000);
      Check(M.FThreadPrimed and (K = []), 'first complete active frame primes');
      Self5KStamp := 200; M.FLastExternalHighTick := 3000;
      Observe(True, False, 4000);
      Check(not M.FKnownThreads.ContainsKey(11), 'reused TID no longer inherits known stamp');
      P := M.FThreadPending[11];
      Check((P.Created = 200) and (P.Count = 1), 'new lifetime starts at one');
      Observe(True, False, 4000);
      Check(M.FThreadPending[11].Count = 1, 'same timestamp cannot confirm twice');
      Observe(True, False, 5000);
      Check(dkThreadProvenance in K, 'two fresh suspicious observations preserved');
      Check(M.FKnownThreads[11] = 200, 'reported lifetime becomes known');
      Observe(True, False, 6000); Check(K = [], 'same lifetime does not repeat');
      Threads.Clear; Observe(True, False, 6100);
      Check(M.FKnownThreads.Count = 0, 'complete departure prunes known identity');
      AddSample(11, $100000); Self5KStamp := 300; M.FLastExternalHighTick := 6200;
      Observe(True, False, 6300); Check(M.FThreadPending[11].Count = 1, 'new observed identity candidate');
      Observe(False, False, 6400);
      Check(M.FThreadPending.Count = 0, 'snapshot gap drops confirmations');
      Observe(True, False, 6500); Check(K = [], 'recovery starts a new candidate');
      Self5KIdentityOK := False; Observe(True, False, 6600);
      Check(M.FThreadPending.Count = 0, 'unknown birth cannot confirm');
      Self5KIdentityOK := True; Observe(True, False, 6700);
      Check(M.FThreadPending[11].Count = 1, 'identity query recovery starts at one');
      AddSample(11, $200000); Observe(True, False, 6800);
      Check((M.FThreadPending[11].Count = 1) and
        (M.FThreadPending[11].StartAddress = $200000), 'changed start separates candidates');
      Observe(True, False, 6900);
      Check(dkThreadProvenance in K, 'new start needs two matching observations');
      Threads.Clear; Observe(False, False, 7000);
      Check(M.FKnownThreads.ContainsKey(11), 'incomplete absence does not prune');
      Observe(True, False, 7100);
      Check(not M.FKnownThreads.ContainsKey(11), 'complete absence prunes');
      AddSample(12, $300000); Self5KStamp := 400;
      Observe(True, False, 7200, 12);
      Check((K = []) and (M.FKnownThreads[12] = 400), 'expected new worker exception preserved');
      Self5KStamp := 500; M.FLastExternalHighTick := 7300;
      Observe(True, False, 7400, 12);
      Check(M.FThreadPending.ContainsKey(12), 'reused known worker ID is not blindly exempt');
      Observe(True, False, 7450, 12);
      Check(dkThreadProvenance in K, 'reused worker does not become exempt on second sample');
      Self5KStamp := 550; Observe(True, False, 7470, 12);
      Check(M.FThreadPending.ContainsKey(12), 'later worker reuse stays pending');
      S := Threads[12]; S.ThreadID := 99; Threads[12] := S;
      Observe(True, False, 7500);
      Check(M.FThreadPending.Count = 0, 'malformed map invalidates pending');
      AddSample(12, $300000); Self5KStamp := 0;
      Observe(True, False, 7600);
      Check(M.FThreadPending.Count = 0, 'zero birth rejected');
      K := []; M.CheckThreads(nil, True, False, 0, 7700, K);
      Check(K = [], 'nil snapshot is unknown');
      Self5KStamp := 600; Observe(True, True, 7800);
      Check(M.FThreadPending.Count = 0, 'baseline transition clears candidates');
      Check(M.FKnownThreads[12] = 600, 'verified baseline captures lifetime');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    Threads.Free; M.Free; SelfIdentity5KHook := nil; SelfPrivate5KHook := nil;
  end;
end;
