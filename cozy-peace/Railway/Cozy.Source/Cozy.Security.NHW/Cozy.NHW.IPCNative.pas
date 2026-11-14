unit Cozy.NHW.IPCNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Types;

function CaptureIPCObjects(const Data: TBytes; Count: NativeUInt;
  TargetPID: Cardinal;
  TypeCache: TDictionary<Word, TIPCObjectKind>;
  Observed: TList<TIPCObservation>): Boolean;

{$IFDEF NHW_NATIVE5_TESTS}
function TestIPCNativeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  Cozy.NHW.Native,
  Cozy.NHW.WinPointers,
  Cozy.NHW.IPCSnapshot.Decoder;

const
  PROCESS_DUP_HANDLE_RIGHT = $0040;
  IPC_MAX_TYPE_PROBES = 128;

function CaptureIPCObjects(const Data: TBytes; Count: NativeUInt;
  TargetPID: Cardinal;
  TypeCache: TDictionary<Word, TIPCObjectKind>;
  Observed: TList<TIPCObservation>): Boolean;
var
  SourceProcess, ProbeHandle: THandle;
  OwnSource: Boolean;
  IdentityKinds: TDictionary<string, TIPCObjectKind>;
  ProbeTypes: TDictionary<Word, Byte>;
  Probes: TList<TIPCTypeProbe>;
  Probe: TIPCTypeProbe;
  Entry: PNativeHandleEntry;
  I: NativeUInt;
  J, Attempts: Integer;
  Name, Key: string;
  Kind: TIPCObjectKind;
  Obs: TIPCObservation;
  CurrentPID: Cardinal;
  VerifyData: TBytes;
  Status: TNTStatus;
begin
  Result := False;
  if Observed = nil then Exit;
  Observed.Clear;
  if (TypeCache = nil) or (TargetPID = 0) then Exit;
  if not IPCSnapshotShape(Data, Count) then Exit;
  // Avoid NativeUInt underflow in "Count - 1" on an empty snapshot.
  if Count = 0 then Exit(True);
  if not IPCNativeAvailable then Exit;
  CurrentPID := WinCurrentProcessId;
  if CurrentPID = 0 then Exit;
  SourceProcess := 0;
  OwnSource := False;
  IdentityKinds := nil;
  ProbeTypes := nil;
  Probes := nil;
  try
    IdentityKinds := TDictionary<string, TIPCObjectKind>.Create;
    ProbeTypes := TDictionary<Word, Byte>.Create;
    Probes := TList<TIPCTypeProbe>.Create;
    Attempts := 0;
    Entry := PNativeHandleEntry(@Data[IPC_HEADER_BYTES]);
    for I := 0 to Count - 1 do
    begin
      if Entry^.OwnerPID = NativeUInt(TargetPID) then
      begin
        // Redacted/malformed target identities are unknown, not absence.
        if (Entry^.ObjectPointer = nil) or (Entry^.ObjectTypeIndex = 0) or
           (Entry^.HandleValue = 0) then Exit;
        if not TypeCache.ContainsKey(Entry^.ObjectTypeIndex) and
           not ProbeTypes.ContainsKey(Entry^.ObjectTypeIndex) then
        begin
          if Attempts >= IPC_MAX_TYPE_PROBES then Exit;
          Inc(Attempts);
          if SourceProcess = 0 then
          begin
            if TargetPID = CurrentPID then
              SourceProcess := WinCurrentProcess
            else
            begin
              SourceProcess := OpenNativeProcess(TargetPID, PROCESS_DUP_HANDLE_RIGHT);
              OwnSource := SourceProcess <> 0;
            end;
            if SourceProcess = 0 then Exit;
          end;
          // Duplicate even self handles. Never query/close a borrowed live
          // handle that another target thread can close and reuse.
          ProbeHandle := 0;
          try
            if not DuplicateNativeHandle(SourceProcess,
              THandle(Entry^.HandleValue), ProbeHandle) then Exit;
            if not QueryNativeObjectType(ProbeHandle, Name) then Exit;
            Probe := Default(TIPCTypeProbe);
            Probe.Handle := ProbeHandle;
            Probe.Identity := NativeUInt(Entry^.ObjectPointer);
            Probe.TypeIndex := Entry^.ObjectTypeIndex;
            Probe.Kind := ClassifyNativeType(Name);
            Probes.Add(Probe);
            ProbeHandle := 0; // ownership transferred to Probes
            ProbeTypes.Add(Probe.TypeIndex, 1);
          finally
            if ProbeHandle <> 0 then CloseNativeProcess(ProbeHandle);
          end;
        end;
      end;
      Inc(Entry);
    end;
    if Probes.Count <> 0 then
    begin
      // One verification snapshot for all new type probes. The duplicated
      // handles keep the probed objects alive while their identities match.
      if not FetchSnapshot(VerifyData, Status) then Exit;
      if not ConfirmIPCProbes(VerifyData, CurrentPID, Probes) then Exit;
      for J := 0 to Probes.Count - 1 do
      begin
        Probe := Probes[J];
        TypeCache.AddOrSetValue(Probe.TypeIndex, Probe.Kind);
      end;
    end;
    Entry := PNativeHandleEntry(@Data[IPC_HEADER_BYTES]);
    for I := 0 to Count - 1 do
    begin
      if Entry^.OwnerPID = NativeUInt(TargetPID) then
      begin
        if not TypeCache.TryGetValue(Entry^.ObjectTypeIndex, Kind) then Exit;
        if Kind <> ikNone then
        begin
          Key := OpaqueKey(Entry^.ObjectTypeIndex, NativeUInt(Entry^.ObjectPointer));
          IdentityKinds.AddOrSetValue(Key, Kind);
        end;
      end;
      Inc(Entry);
    end;
    Entry := PNativeHandleEntry(@Data[IPC_HEADER_BYTES]);
    for I := 0 to Count - 1 do
    begin
      if (Entry^.OwnerPID <> NativeUInt(TargetPID)) and
         (Entry^.OwnerPID <> NativeUInt(CurrentPID)) and
         (Entry^.OwnerPID > 0) and
         (Entry^.OwnerPID <= NativeUInt(High(Cardinal))) and
         (Entry^.ObjectPointer <> nil) and (Entry^.ObjectTypeIndex <> 0) then
      begin
        Key := OpaqueKey(Entry^.ObjectTypeIndex, NativeUInt(Entry^.ObjectPointer));
        if IdentityKinds.TryGetValue(Key, Kind) then
        begin
          Obs := Default(TIPCObservation);
          Obs.OwnerPID := Cardinal(Entry^.OwnerPID);
          Obs.ObjectIdentity := NativeUInt(Entry^.ObjectPointer);
          Obs.Kind := Kind;
          Obs.GrantedAccess := Entry^.GrantedAccess;
          Observed.Add(Obs);
        end;
      end;
      Inc(Entry);
    end;
    Result := True;
  finally
    if Probes <> nil then
      for J := 0 to Probes.Count - 1 do
      begin
        Probe := Probes[J];
        CloseNativeProcess(Probe.Handle);
      end;
    Probes.Free;
    ProbeTypes.Free;
    IdentityKinds.Free;
    if OwnSource then CloseNativeProcess(SourceProcess);
    if not Result then Observed.Clear;
  end;
end;

{$IFDEF NHW_NATIVE5_TESTS}
  {$I Cozy.NHW.Native5.IPC.inc}
{$ENDIF}
end.
