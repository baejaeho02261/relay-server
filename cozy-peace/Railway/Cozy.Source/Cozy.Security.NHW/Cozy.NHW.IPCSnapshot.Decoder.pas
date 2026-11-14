unit Cozy.NHW.IPCSnapshot.Decoder;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

// Internal read-only decoding layer; callers retain collection/handle ownership.
uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections,
  Cozy.NHW.Types, Cozy.NHW.Native;

const
  IPC_HEADER_BYTES = 16;

type
  TIPCTypeProbe = record
    Handle: THandle;
    Identity: NativeUInt;
    TypeIndex: Word;
    Kind: TIPCObjectKind;
  end;


function ClassifyNativeType(const Name: string): TIPCObjectKind;
function OpaqueKey(TypeIndex: Word; Identity: NativeUInt): string;
function IPCSnapshotShape(const Data: TBytes; Count: NativeUInt): Boolean;
function ConfirmIPCProbes(const Data: TBytes; CurrentPID: Cardinal;
  const Probes: TList<TIPCTypeProbe>): Boolean;

implementation

function ClassifyNativeType(const Name: string): TIPCObjectKind;
begin
  if SameText(Name, 'Event') then Exit(ikEvent);
  if SameText(Name, 'Mutant') then Exit(ikMutex);
  if SameText(Name, 'Semaphore') then Exit(ikSemaphore);
  if SameText(Name, 'Section') then Exit(ikSection);
  Result := ikNone;
end;

function OpaqueKey(TypeIndex: Word; Identity: NativeUInt): string;
begin
  Result := IntToStr(TypeIndex) + ':' + IntToHex(UInt64(Identity), 16);
end;

function IPCSnapshotShape(const Data: TBytes; Count: NativeUInt): Boolean;
var
  HeaderCount: NativeUInt;
begin
  Result := False;
  if (SizeOf(TNativeHandleEntry) <> 40) or
     (Length(Data) < IPC_HEADER_BYTES) then Exit;
  HeaderCount := 0;
  Move(Data[0], HeaderCount, SizeOf(HeaderCount));
  if HeaderCount <> Count then Exit;
  Result := Count <= NativeUInt((Length(Data) - IPC_HEADER_BYTES) div
    SizeOf(TNativeHandleEntry));
end;

function ConfirmIPCProbes(const Data: TBytes; CurrentPID: Cardinal;
  const Probes: TList<TIPCTypeProbe>): Boolean;
var
  Count, I: NativeUInt;
  Entry: PNativeHandleEntry;
  Probe: TIPCTypeProbe;
  ByHandle: TDictionary<NativeUInt, Integer>;
  Seen: TArray<Boolean>;
  Index, Matched: Integer;
begin
  Result := False;
  if (Probes = nil) or (CurrentPID = 0) or
     (Length(Data) < IPC_HEADER_BYTES) then Exit;
  Count := 0;
  Move(Data[0], Count, SizeOf(Count));
  if not IPCSnapshotShape(Data, Count) then Exit;
  if Probes.Count = 0 then Exit(True);
  if Count = 0 then Exit;
  ByHandle := TDictionary<NativeUInt, Integer>.Create;
  try
    SetLength(Seen, Probes.Count);
    for Index := 0 to Probes.Count - 1 do
    begin
      Probe := Probes[Index];
      if (Probe.Handle = 0) or (Probe.Identity = 0) or
         (Probe.TypeIndex = 0) or ByHandle.ContainsKey(NativeUInt(Probe.Handle)) then Exit;
      ByHandle.Add(NativeUInt(Probe.Handle), Index);
    end;
    Matched := 0;
    Entry := PNativeHandleEntry(@Data[IPC_HEADER_BYTES]);
    for I := 0 to Count - 1 do
    begin
      if Entry^.OwnerPID = NativeUInt(CurrentPID) then
        if ByHandle.TryGetValue(Entry^.HandleValue, Index) then
        begin
          Probe := Probes[Index];
          if Seen[Index] or
             (NativeUInt(Entry^.ObjectPointer) <> Probe.Identity) or
             (Entry^.ObjectTypeIndex <> Probe.TypeIndex) then Exit;
          Seen[Index] := True;
          Inc(Matched);
        end;
      Inc(Entry);
    end;
    Result := Matched = Probes.Count;
  finally
    ByHandle.Free;
  end;
end;

end.
