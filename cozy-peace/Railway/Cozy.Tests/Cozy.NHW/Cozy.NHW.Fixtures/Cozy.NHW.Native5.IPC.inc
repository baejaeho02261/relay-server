// Compiled only by NHW.Native5.Tests.dproj; no production test hooks.
function TestIPCNativeHardening(out Failure: string; out Checks: Integer): Boolean;
var
  Data: TBytes;
  Probes: TList<TIPCTypeProbe>;
  Probe: TIPCTypeProbe;
  Observed: TList<TIPCObservation>;
  Cache: TDictionary<Word, TIPCObjectKind>;
  Entry: PNativeHandleEntry;
  N: NativeUInt;
  procedure Check(Value: Boolean; const Name: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Name);
  end;
  procedure Snapshot(Count: NativeUInt);
  begin
    SetLength(Data, IPC_HEADER_BYTES + Integer(Count) * SizeOf(TNativeHandleEntry));
    FillChar(Data[0], Length(Data), 0);
    Move(Count, Data[0], SizeOf(Count));
  end;
begin
  Checks := 0; Failure := ''; Result := False;
  Probes := nil; Observed := nil; Cache := nil;
  try
    try
      Probes := TList<TIPCTypeProbe>.Create;
      Observed := TList<TIPCObservation>.Create;
      Cache := TDictionary<Word, TIPCObjectKind>.Create;
      Check(not IPCSnapshotShape(Data, 0), 'missing header');
      Snapshot(0);
      Check(IPCSnapshotShape(Data, 0), 'empty snapshot shape');
      Observed.Add(Default(TIPCObservation));
      Check(CaptureIPCObjects(Data, 0, 123, Cache, Observed), 'empty snapshot succeeds');
      Check(Observed.Count = 0, 'stale observations cleared');
      Check(not CaptureIPCObjects(Data, 0, 0, Cache, Observed), 'zero target rejected');
      Check(not CaptureIPCObjects(Data, 0, 123, nil, Observed), 'nil cache rejected');
      Check(not CaptureIPCObjects(Data, 0, 123, Cache, nil), 'nil output rejected');
      Check(not IPCSnapshotShape(Data, High(NativeUInt)), 'huge count rejected');
      N := 1; Move(N, Data[0], SizeOf(N));
      Check(not IPCSnapshotShape(Data, 1), 'truncated array rejected');
      Snapshot(1);
      Check(not IPCSnapshotShape(Data, 0), 'header count mismatch');
      Check(IPCSnapshotShape(Data, 1), 'one entry shape');
      Probe := Default(TIPCTypeProbe);
      Probe.Handle := 44; Probe.Identity := $ABC000; Probe.TypeIndex := 9; Probe.Kind := ikEvent;
      Probes.Add(Probe);
      Entry := PNativeHandleEntry(@Data[IPC_HEADER_BYTES]);
      Entry^.OwnerPID := 123; Entry^.HandleValue := 44;
      Entry^.ObjectPointer := Pointer(NativeUInt($ABC000)); Entry^.ObjectTypeIndex := 9;
      Check(ConfirmIPCProbes(Data, 123, Probes), 'matching owned duplicate');
      Entry^.ObjectPointer := Pointer(NativeUInt($DEF000));
      Check(not ConfirmIPCProbes(Data, 123, Probes), 'reused handle object rejected');
      Entry^.ObjectPointer := Pointer(NativeUInt($ABC000)); Entry^.ObjectTypeIndex := 10;
      Check(not ConfirmIPCProbes(Data, 123, Probes), 'changed object type rejected');
      Entry^.ObjectTypeIndex := 9; Entry^.OwnerPID := 124;
      Check(not ConfirmIPCProbes(Data, 123, Probes), 'other process handle rejected');
      Entry^.OwnerPID := 123;
      Check(not ConfirmIPCProbes(Data, 0, Probes), 'zero observer PID rejected');
      Probes.Add(Probe);
      Check(not ConfirmIPCProbes(Data, 123, Probes), 'duplicate proof handle rejected');
      Probes.Delete(1);
      Snapshot(2);
      Entry := PNativeHandleEntry(@Data[IPC_HEADER_BYTES]);
      Entry^.OwnerPID := 123; Entry^.HandleValue := 44;
      Entry^.ObjectPointer := Pointer(NativeUInt($ABC000)); Entry^.ObjectTypeIndex := 9;
      Move(Entry^, Data[IPC_HEADER_BYTES + SizeOf(TNativeHandleEntry)], SizeOf(TNativeHandleEntry));
      Check(not ConfirmIPCProbes(Data, 123, Probes), 'duplicate snapshot handle rejected');
      Check(ClassifyNativeType('Event') = ikEvent, 'Event');
      Check(ClassifyNativeType('Mutant') = ikMutex, 'Mutant');
      Check(ClassifyNativeType('Semaphore') = ikSemaphore, 'Semaphore');
      Check(ClassifyNativeType('Section') = ikSection, 'Section');
      Check(ClassifyNativeType('File') = ikNone, 'unrelated type');
      Check(OpaqueKey(1, 20) <> OpaqueKey(2, 20), 'type included in identity key');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    Cache.Free; Observed.Free; Probes.Free;
  end;
end;
