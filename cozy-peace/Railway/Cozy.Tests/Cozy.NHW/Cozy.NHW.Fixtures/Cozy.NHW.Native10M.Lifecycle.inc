function TestLifecycle10M(out Failure: string; out Checks: Integer): Boolean;
var Parents: TProcessParentMap; Threads: TThreadSampleMap; Data: TBytes;
    P, Tail: PProcessInfoX64; T1, T2: PThreadInfoX64; Raised: Boolean;
  procedure Check(Condition: Boolean; const Msg: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Msg);
  end;
  procedure Build;
  begin
    SetLength(Data, SizeOf(TProcessInfoX64) + 2 * SizeOf(TThreadInfoX64));
    FillChar(Data[0], Length(Data), 0);
    P := Pointer(@Data[0]); P^.UniqueProcessId := 42;
    P^.InheritedFromUniqueProcessId := 1; P^.NumberOfThreads := 2;
    T1 := Pointer(NativeUInt(P) + SizeOf(TProcessInfoX64));
    T2 := Pointer(NativeUInt(T1) + SizeOf(TThreadInfoX64));
    T1^.ClientProcessId := 42; T1^.ClientThreadId := 11; T1^.StartAddress := Pointer($10000);
    T2^.ClientProcessId := 42; T2^.ClientThreadId := 12; T2^.StartAddress := Pointer($20000);
  end;
  procedure EmptyOutputs;
  begin Check((Parents.Count = 0) and (Threads.Count = 0), 'failed collection leaves no partial result'); end;
begin
  Result := False; Failure := ''; Checks := 0;
  Parents := nil; Threads := nil; Lifecycle10MFailInsert := False;
  try
    try
      Parents := TProcessParentMap.Create; Threads := TThreadSampleMap.Create;
      Build;
      Check(ParseSystemThreadSnapshot(Data, 42, Parents, Threads), 'valid native layout');
      Check((Parents.Count = 1) and (Threads.Count = 2), 'complete outputs');
      Check(Threads[11].StartAddress = $10000, 'thread data copied');
      T2^.ClientThreadId := 0;
      Check(not ParseSystemThreadSnapshot(Data, 42, Parents, Threads), 'invalid second TID rejected');
      EmptyOutputs;
      Build; T2^.ClientThreadId := 11;
      Check(not ParseSystemThreadSnapshot(Data, 42, Parents, Threads), 'duplicate thread rejected');
      EmptyOutputs;
      Build; T2^.ClientProcessId := 43;
      Check(not ParseSystemThreadSnapshot(Data, 42, Parents, Threads), 'wrong thread owner rejected');
      EmptyOutputs;
      Build; SetLength(Data, Length(Data) - 1);
      Check(not ParseSystemThreadSnapshot(Data, 42, Parents, Threads), 'truncated thread array');
      EmptyOutputs;
      Build; P^.NumberOfThreads := MAX_TARGET_THREADS + 1;
      Check(not ParseSystemThreadSnapshot(Data, 42, Parents, Threads), 'oversized thread count');
      EmptyOutputs;
      Build;
      Check(not ParseSystemThreadSnapshot(Data, 99, Parents, Threads), 'missing target');
      EmptyOutputs;
      Build; SetLength(Data, Length(Data) + SizeOf(TProcessInfoX64));
      P := Pointer(@Data[0]); P^.NextEntryOffset := 416;
      Tail := Pointer(NativeUInt(@Data[0]) + 416); FillChar(Tail^, SizeOf(Tail^), 0);
      Tail^.NextEntryOffset := 1;
      Check(not ParseSystemThreadSnapshot(Data, 42, Parents, Threads), 'bad tail after populated target');
      EmptyOutputs;
      Tail^.NextEntryOffset := 0; Tail^.UniqueProcessId := 42;
      Check(not ParseSystemThreadSnapshot(Data, 42, Parents, Threads), 'duplicate target record');
      EmptyOutputs;
      Build; Lifecycle10MFailInsert := True; Raised := False;
      try ParseSystemThreadSnapshot(Data, 42, Parents, Threads);
      except on E: EOutOfMemory do Raised := True; end;
      Check(Raised, 'allocation exception propagates'); EmptyOutputs;
      Lifecycle10MFailInsert := False;
      Build; Check(not ParseSystemThreadSnapshot(Data, 0, Parents, Threads), 'zero target rejected');
      Check(not ParseSystemThreadSnapshot(Data, 42, nil, Threads), 'nil parent output rejected');
      Check(not ReadSystemThreadSnapshot(0, Parents, Threads), 'public invalid input does not fetch');
      EmptyOutputs;
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    Lifecycle10MFailInsert := False; Threads.Free; Parents.Free;
  end;
end;
