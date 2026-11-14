function TestNetworkGuard5L(out Failure: string; out Checks: Integer): Boolean;
var M: TNetworkGuard; K: TDetectionKinds; I: Integer;
    Raised: Boolean; L: TStringList;
  procedure Check(C: Boolean; const Msg: string);
  begin Inc(Checks); if not C then raise Exception.Create(Msg); end;
  procedure Fresh;
  begin
    M.Reset; K := []; Network5LAllocations := 0; Network5LCalls := 0;
    Network5LFailAllocation := 0; Network5LFailProbe := 0; Network5LRound := 1;
  end;
begin
  Result := False; Failure := ''; Checks := 0; M := nil; L := nil;
  Network5LAlive := 0;
  try
    try
      M := TNetworkGuard.Create;
      for I := 1 to 5 do
      begin
        Fresh; Network5LFailAllocation := I; Raised := False;
        try M.Examine(1000, K); except on E: EOutOfMemory do Raised := True; end;
        Check(Raised, 'injected list allocation failure propagated');
        Check(Network5LAlive = 0, 'all earlier temporary lists released');
        Check(Network5LCalls = 0, 'no probe before all five lists exist');
        Check(K = [], 'allocation failure is not a detection');
      end;
      Fresh; L := NewKeyList;
      Check(L.Sorted and L.CaseSensitive and (L.Duplicates = dupIgnore), 'key-list policy retained');
      L.Free; L := nil; Check(Network5LAlive = 0, 'key-list ownership released');
      Fresh; M.Examine(1000, K);
      Check((K = []) and (Network5LCalls = 3), 'first complete snapshots establish quiet baselines');
      Check(Network5LAlive = 0, 'success releases five temporaries');
      Network5LRound := 2; M.Examine(13000, K);
      Check(K = [], 'first network change candidate remains quiet');
      M.Examine(25000, K);
      Check([dkNetworkFilter, dkWFPCallout, dkWFPProvider, dkRouteChange,
        dkProxyChange, dkNetworkCorrelation] <= K, 'second complete change retains all six signals');
      K := []; M.Examine(37000, K); Check(K = [], 'same accepted snapshots do not repeat');
      Check(Network5LAlive = 0, 'repeated success releases lists');
      for I := 1 to 3 do
      begin
        Fresh; Network5LFailProbe := I; Raised := False; K := [dkHeapState];
        try M.Examine(1000, K); except on E: Exception do Raised := True; end;
        Check(Raised, 'native probe exception propagated');
        Check(Network5LAlive = 0, 'probe exception frees all temporary lists');
        Check(K = [dkHeapState], 'native exception preserves other sensor output');
      end;
      Fresh; M.Examine(1000, K); Network5LCalls := 0; M.Examine(2000, K);
      Check((Network5LCalls = 0) and (Network5LAlive = 0), 'poll throttling retained');
      Result := True;
    except on E: Exception do Failure := E.Message; end;
  finally L.Free; M.Free; end;
end;
