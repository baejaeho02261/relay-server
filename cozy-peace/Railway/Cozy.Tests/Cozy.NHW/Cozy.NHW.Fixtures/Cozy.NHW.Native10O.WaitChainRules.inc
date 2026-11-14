function TestWaitChainRules10O(out Failure: string; out Checks: Integer): Boolean;
var
  Nodes: array[0..4] of TWaitChainNode;
  Facts, Zero: TWaitFacts;
  Owner: PWaitThreadNode;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;
  procedure InitChain;
  begin
    FillChar(Nodes, SizeOf(Nodes), 0);
    Nodes[0].ObjectType := WCT_OBJECT_THREAD; Nodes[0].ObjectStatus := WCT_STATUS_BLOCKED;
    Owner := PWaitThreadNode(@Nodes[0].Payload[0]); Owner^.ProcessId := 123; Owner^.ThreadId := 111;
    Nodes[1].ObjectType := WCT_OBJECT_CRITICAL_SECTION; Nodes[1].ObjectStatus := 6;
    Nodes[2].ObjectType := WCT_OBJECT_THREAD; Nodes[2].ObjectStatus := 2;
    Owner := PWaitThreadNode(@Nodes[2].Payload[0]); Owner^.ProcessId := 123; Owner^.ThreadId := 456;
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  Zero := Default(TWaitFacts);
  try
    try
      InitChain;
      Check(ClassifyWait(@Nodes[0], 3, 123, 111, False, Facts) and Facts.SameProcessOwner, 'matching root and local owner');
      Check(Facts.Blocked and Facts.CriticalSection and not Facts.ExternalOwner, 'complete local facts');
      Owner := PWaitThreadNode(@Nodes[2].Payload[0]); Owner^.ProcessId := 987;
      Check(ClassifyWait(@Nodes[0], 3, 123, 111, False, Facts) and Facts.ExternalOwner, 'external owner retained');
      Check(not ClassifyWait(@Nodes[0], 3, 124, 111, False, Facts), 'wrong target PID rejected');
      Check(CompareMem(@Facts, @Zero, SizeOf(Facts)), 'wrong target publishes no partial facts');
      Check(not ClassifyWait(@Nodes[0], 3, 123, 112, False, Facts), 'wrong root TID rejected');
      Check(not ClassifyWait(@Nodes[0], 3, 0, 111, False, Facts), 'zero target rejected');
      Check(not ClassifyWait(@Nodes[0], 3, 123, 0, False, Facts), 'zero root rejected');
      Nodes[1].ObjectStatus := WCT_STATUS_NO_ACCESS;
      Check(not ClassifyWait(@Nodes[0], 3, 123, 111, False, Facts), 'inaccessible link rejected');
      Check(CompareMem(@Facts, @Zero, SizeOf(Facts)), 'partial chain clears facts');
      InitChain; Nodes[1].ObjectType := WCT_OBJECT_THREAD;
      Check(not ClassifyWait(@Nodes[0], 3, 123, 111, False, Facts), 'adjacent thread nodes rejected');
      InitChain; Nodes[2].ObjectType := WCT_OBJECT_MUTEX;
      Check(not ClassifyWait(@Nodes[0], 3, 123, 111, False, Facts), 'missing owner thread rejected');
      InitChain; Nodes[1].ObjectStatus := 7;
      Check(not ClassifyWait(@Nodes[0], 3, 123, 111, False, Facts), 'not-owned lock cannot claim following owner');
      InitChain; Owner := PWaitThreadNode(@Nodes[2].Payload[0]); Owner^.ThreadId := 0;
      Check(not ClassifyWait(@Nodes[0], 3, 123, 111, False, Facts), 'partial COM/ALPC identity treated as unknown');
      Check(not ClassifyWait(nil, 3, 123, 111, False, Facts), 'null nodes rejected');
      Check(not ClassifyWait(@Nodes[0], 17, 123, 111, False, Facts), 'capacity checked before read');
      InitChain;
      Check(ClassifyWait(@Nodes[0], 2, 123, 111, False, Facts) and not Facts.HasOwner, 'terminal lock does not invent an owner');
      Nodes[2].ObjectStatus := WCT_STATUS_BLOCKED;
      Nodes[3].ObjectType := WCT_OBJECT_MUTEX; Nodes[3].ObjectStatus := 6;
      Nodes[4] := Nodes[0];
      Check(ClassifyWait(@Nodes[0], 5, 123, 111, True, Facts) and Facts.Cycle, 'valid cycle indicator retained');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    // No owned resources.
  end;
end;
