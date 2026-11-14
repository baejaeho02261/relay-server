var
  IdentityTestPID, IdentityTestSecondPID: Cardinal;
  IdentityTestPIDCalls: Integer;
  IdentityTestCreated: UInt64;
  IdentityTestTimesOK: Boolean;
function StableTestPID(Handle: THandle): Cardinal; stdcall;
begin
  Inc(IdentityTestPIDCalls);
  if (IdentityTestPIDCalls > 1) and (IdentityTestSecondPID <> 0) then
    Result := IdentityTestSecondPID
  else Result := IdentityTestPID;
end;
function StableTestTimes(Handle: THandle; out C, E, K, U: TFileTime): BOOL;
begin
  C.dwLowDateTime := Cardinal(IdentityTestCreated and $FFFFFFFF);
  C.dwHighDateTime := Cardinal(IdentityTestCreated shr 32);
  E := Default(TFileTime); K := E; U := E;
  Result := IdentityTestTimesOK;
end;
function TestStableIdentityHardening(out Failure: string; out Checks: Integer): Boolean;
var
  SavedPID: TIdentityGetPID; SavedTimes: TIdentityTestTimes;
  M: TStableObjectIdentity; H: TTargetHolder;
  Created: UInt64; I: Integer;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Fake(PID: Cardinal; Creation: UInt64);
  begin
    IdentityTestPID := PID; IdentityTestSecondPID := 0; IdentityTestPIDCalls := 0;
    IdentityTestCreated := Creation; IdentityTestTimesOK := True;
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil;
  SavedPID := IdentityGetPID; SavedTimes := IdentityTestTimes;
  try
    try
      IdentityGetPID := StableTestPID; IdentityTestTimes := StableTestTimes;
      M := TStableObjectIdentity.Create;
      Fake(42, 100);
      Check(not M.ObserveTarget(0, 42), 'null target rejected');
      Check(not M.ObserveTarget(1, 0), 'zero PID rejected');
      Check(M.FTargetPID = 0, 'invalid input cannot establish baseline');
      Fake(43, 100);
      Check(not M.ObserveTarget(1, 42), 'wrong handle PID rejected');
      Check(not M.TargetValidated and (M.TargetCreation = 0), 'wrong PID not bound');
      Fake(42, 100); IdentityTestSecondPID := 43;
      Check(not M.ObserveTarget(1, 42), 'changed handle PID rejected');
      Check(M.FTargetPID = 0, 'changed handle does not bind baseline');
      Fake(42, 100);
      Check(M.ObserveTarget(1, 42), 'matching handle and creation binds target');
      Check(M.TargetValidated and (M.TargetCreation = 100), 'bound target fields');
      Fake(42, 101);
      Check(not M.ObserveTarget(1, 42), 'PID reuse rejected');
      Check(M.TargetCreation = 100, 'rejected reuse does not rewrite baseline');
      Fake(42, 100);
      Check(M.ObserveTarget(THandle(High(NativeUInt)), 42), 'current process pseudo handle accepted');
      IdentityTestTimesOK := False; Created := 999;
      Check(not QueryCreationIdentity(1, Created), 'times failure rejected');
      Check(Created = 0, 'times failure does not leak partial creation');
      Fake(42, 0);
      Check(not QueryCreationIdentity(1, Created) and (Created = 0), 'zero creation unknown');
      Check(not SameProcessIdentity(42, 0, 42, 0), 'unknown epochs never equal');
      Check(SameProcessIdentity(42, 100, 42, 100), 'known identity equality');
      Check(not SameProcessIdentity(41, 100, 42, 100), 'PID equality required');
      M.Reset;
      H := Default(TTargetHolder);
      for I := 0 to MAX_STABLE_ACTORS - 1 do
      begin
        H.PID := Cardinal(100 + I); H.CreateTime := UInt64(I + 1);
        M.ObserveHolder(H, UInt64(I + 1));
      end;
      Check(M.FActors.Count = MAX_STABLE_ACTORS, 'bounded cache full');
      H.PID := 100; H.CreateTime := 1; M.ObserveHolder(H, 3000);
      H.PID := 99999; H.CreateTime := 7000; M.ObserveHolder(H, 3001);
      Check(M.FActors.Count = MAX_STABLE_ACTORS, 'eviction keeps bound');
      Check(M.FActors.ContainsKey(99999), 'new identity tracked after saturation');
      Check(M.FActors.ContainsKey(100), 'recently touched identity retained');
      Check(not M.FActors.ContainsKey(101), 'oldest observed identity evicted');
      Check(M.LastActorReuse = 0, 'eviction itself is not PID reuse');
      H.CreateTime := 8000; M.ObserveHolder(H, 3002);
      Check(M.LastActorReuse = 3002, 'newly admitted actor reuse detected');
      H.CreateTime := 7000; M.ObserveHolder(H, 2000);
      Check(M.FActors[99999].Created = 8000, 'out of order actor does not overwrite');
      Check(M.LastActorReuse = 3002, 'late record not reuse evidence');
      H.PID := 50000; H.CreateTime := 0; M.ObserveHolder(H, 4000);
      Check(not M.FActors.ContainsKey(50000), 'unknown creation not cached');
      H.PID := 4; H.CreateTime := 1; M.ObserveHolder(H, 4000);
      Check(not M.FActors.ContainsKey(4), 'system PID policy unchanged');
      M.Reset;
      Check((M.FActors.Count = 0) and not M.TargetValidated and
        (M.LastActorReuse = 0), 'reset clears per-instance state');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    M.Free; IdentityGetPID := SavedPID; IdentityTestTimes := SavedTimes;
  end;
end;
