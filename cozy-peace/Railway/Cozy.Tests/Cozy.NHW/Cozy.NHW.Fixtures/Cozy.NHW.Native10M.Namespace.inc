function TestNamespace10M(out Failure: string; out Checks: Integer): Boolean;
var W: TNamespaceWatch; OldRef: TNamespaceEntries;
    D: TDetectionKinds; Changes, NHWChanges: Integer; Raised: Boolean; Entry: TNamespaceEntry;
  procedure Check(Condition: Boolean; const Msg: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Msg);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  W := nil;
  try
    try
      W := TNamespaceWatch.Create('test-only', True, True);
      Namespace10MMode := 0; Namespace10MDacl := 1;
      Namespace10MEntry := Default(TNamespaceEntry);
      Namespace10MEntry.Name := 'NHW.TEST'; Namespace10MEntry.TypeName := 'SymbolicLink';
      Namespace10MEntry.TargetKnown := True; Namespace10MEntry.Target := 'A';
      D := W.Examine(Changes, NHWChanges);
      Check((D = []) and W.FPrimed and (W.FEntries.Count = 1), 'first complete collection primes');
      OldRef := W.FEntries; Namespace10MEntry.Target := 'B'; Namespace10MDacl := 2;
      Namespace10MMode := 1; D := W.Examine(Changes, NHWChanges);
      Check((W.FEntries = OldRef) and (D = []), 'failed enumeration preserves original dictionary');
      Check(W.FDaclSignature = 1, 'failed enumeration preserves DACL');
      Namespace10MMode := 2; Raised := False;
      try W.Examine(Changes, NHWChanges); except on E: EOutOfMemory do Raised := True; end;
      Check(Raised and (W.FEntries = OldRef), 'exception before commit preserves reference');
      Entry := W.FEntries['NHW.TEST'];
      Check((Entry.Target = 'A') and (W.FDaclSignature = 1), 'exception leaves complete old data');
      Namespace10MMode := 0; D := W.Examine(Changes, NHWChanges);
      Check(W.FEntries <> OldRef, 'commit swaps a fully built map');
      Check((dkSymbolicLink in D) and (dkObjectSecurity in D), 'existing changes still detected');
      Check((Changes = 2) and (NHWChanges = 1), 'DACL excluded from NHW burst count');
      Namespace10MEntry.TargetKnown := False; Namespace10MMode := 3;
      D := W.Examine(Changes, NHWChanges); Entry := W.FEntries['NHW.TEST'];
      Check(Entry.TargetKnown and (Entry.Target = 'B'), 'unreadable link retains last known target');
      Check((D = []) and (W.FDaclSignature = 2), 'unknown target/DACL not a fabricated change');
      Namespace10MMode := 4; D := W.Examine(Changes, NHWChanges);
      Check((W.FEntries.Count = 0) and (dkNamespace in D), 'complete empty enumeration still detects removal');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    Namespace10MMode := 0; W.Free;
  end;
end;
