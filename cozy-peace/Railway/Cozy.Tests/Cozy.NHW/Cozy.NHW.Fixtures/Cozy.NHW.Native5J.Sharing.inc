function TestSharing5J(out Failure: string; out Checks: Integer): Boolean;
var
  M: THandleSharingEvidence;
  L: TList<TObservedHandle>;
  Ages: TDictionary<Cardinal, UInt64>;
  H: TObservedHandle;
  D: TDetectionKinds;
  I, BeforeLive: Integer;
  Raised: Boolean;
  A, B: TSharingHandle;
  procedure Check(Value: Boolean; const Name: string);
  begin Inc(Checks); if not Value then raise Exception.Create(Name); end;
  procedure Add(PID: Cardinal; Handle: NativeUInt; Rights: Cardinal;
    ThreadObject: Boolean = False);
  begin
    H := Default(TObservedHandle); H.OwnerPID := PID;
    H.HandleValue := Handle; H.ObjectIdentity := $CAFE;
    H.GrantedAccess := Rights; H.IsThread := ThreadObject; L.Add(H);
  end;
  procedure Scan(Tick: UInt64; Baseline: Boolean = False; ThreadOK: Boolean = True);
  begin D := []; M.Examine(L, Ages, ThreadOK, Baseline, Baseline, Tick, D); end;
  procedure Prime;
  begin
    SharingFailStage := 0; M.Reset; L.Clear; Ages.Clear;
    Ages.Add(101, 1000); Ages.Add(102, 2000);
    Add(101, $11, ACCESS_VM_WRITE); Scan(100, True);
    Add(102, $22, ACCESS_VM_WRITE); Scan(150);
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil; L := nil; Ages := nil;
  SharingFailStage := 0;
  try
    try
      M := THandleSharingEvidence.Create;
      L := TList<TObservedHandle>.Create;
      Ages := TDictionary<Cardinal, UInt64>.Create;
      Prime; Check((D = []) and (M.FPending.Count = 1), 'first shared appearance is a candidate');
      Scan(200); Check(dkHandleSharingEvidence in D, 'second fresh observation confirms');
      Scan(250); Check(D = [], 'unchanged handles do not repeat report');
      Check(M.FPrevious.Count = 2, 'complete map committed');
      Prime; Scan(150); Check(D = [], 'same-tick duplicate is not confirmation');
      Scan(151); Check(dkHandleSharingEvidence in D, 'next fresh tick still confirms');
      Prime; D := [dkProcess]; M.Examine(nil, Ages, True, False, False, 200, D);
      Check(D = [dkProcess], 'nil input preserves other findings');
      Check((M.FPrevious.Count = 0) and (M.FPending.Count = 0), 'nil snapshot breaks continuity');
      Scan(250); Scan(300); Check(D = [], 'old candidate not resurrected after nil');
      Prime; D := []; M.Examine(L, nil, True, False, False, 200, D);
      Check((D = []) and not M.FHasSnapshot, 'nil creation map safely rejected');
      Prime; Ages.Clear; Scan(200);
      Check((M.FPrevious.Count = 0) and (D = []), 'unknown process creation excluded');
      Prime; Ages.AddOrSetValue(102, 3000); Scan(200);
      Check(D = [], 'reused PID starts fresh');
      Prime; Scan(50); Check(D = [], 'clock rollback breaks pending confirmation');
      Prime; Scan(16000); Check(D = [], 'excessive observation gap rebases');
      Prime; Add(102, $22, ACCESS_VM_OPERATION); Scan(200);
      Check((D = []) and not M.FHasSnapshot, 'contradictory duplicate key rejected');
      Prime; Add(102, $22, ACCESS_VM_WRITE); Scan(200);
      Check(dkHandleSharingEvidence in D, 'identical duplicate does not add confirmation');
      Prime; L.Clear; Add(101, $11, ACCESS_VM_WRITE); Add(102, 0, ACCESS_VM_WRITE); Scan(200);
      Check((D = []) and (M.FPrevious.Count = 1), 'zero handle excluded');
      Prime; L.Clear; Add(101, $11, ACCESS_VM_WRITE); Add(102, $22, ACCESS_QUERY_LIMITED); Scan(200);
      Check(D = [], 'query-only rights cannot confirm');
      Prime; H := Default(TObservedHandle);
      for I := L.Count to MAX_SHARING_ENTRIES do L.Add(H);
      Scan(200); Check((D = []) and not M.FHasSnapshot, 'oversized snapshot invalidated');
      Prime; L.Clear; Add(101, $11, THREAD_SET_CONTEXT_RIGHT, True); Scan(300, True);
      Add(102, $22, THREAD_SET_CONTEXT_RIGHT, True); Scan(350);
      Scan(400, False, False);
      Check((D = []) and (M.FPending.Count = 0), 'incomplete thread data breaks thread candidates');
      Scan(450); Check(D = [], 'recovered thread data does not reuse earlier confirmation');
      for I := 1 to 6 do
      begin
        Prime; BeforeLive := SharingTestLive;
        SharingFailStage := I; D := [dkProcess]; Raised := False;
        try M.Examine(L, Ages, True, False, False, 200, D);
        except on E: EOutOfMemory do Raised := True; end;
        SharingFailStage := 0;
        Check(Raised, 'allocation failure propagated: ' + IntToStr(I));
        Check(SharingTestLive = BeforeLive, 'temporary maps released: ' + IntToStr(I));
        Check(D = [dkProcess], 'no partial finding published: ' + IntToStr(I));
        Check((M.FPending.Count = 0) and (M.FPrevious.Count = 0),
          'failure cannot preserve a partial epoch: ' + IntToStr(I));
      end;
      A := Default(TSharingHandle); A.PID := 101; A.Created := 1;
      A.ObjectIdentity := $99; A.AccessMask := ACCESS_VM_WRITE;
      B := A; B.PID := 102; B.Created := 2;
      Check(NHWPotentialSharedHandle(A, B, True), 'helper accepts bounded shared capability');
      Check(not NHWPotentialSharedHandle(A, B, False), 'prior owner must remain present');
      B.PID := 0; Check(not NHWPotentialSharedHandle(A, B, True), 'invalid actor rejected');
      B.PID := 102; B.Created := 0;
      Check(not NHWPotentialSharedHandle(A, B, True), 'missing identity rejected');
      M.Free; M := nil;
      Check(SharingTestLive = 0, 'all tracked map instances destroyed');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally
    SharingFailStage := 0; Ages.Free; L.Free; M.Free;
  end;
end;
