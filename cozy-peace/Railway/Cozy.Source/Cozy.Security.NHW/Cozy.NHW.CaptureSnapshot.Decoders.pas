unit Cozy.NHW.CaptureSnapshot.Decoders;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.SysUtils, System.Generics.Collections;

type
  TCaptureProcessInfo = record
    PID: Cardinal;
    Name: string;
  end;
  TCaptureProcessList = TList<TCaptureProcessInfo>;
  TCapturePIDSet = TDictionary<Cardinal, Byte>;
  PTcpRowNative = ^TTcpRowNative;
  TTcpRowNative = record
    State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwnerPID: Cardinal;
  end;

function ParseCaptureProcesses(const Data: TBytes; List: TCaptureProcessList): Boolean;
function ParseCaptureListeners(const Buffer: TBytes; ActualBytes: Cardinal;
  OutPIDs: TCapturePIDSet): Boolean;

implementation

uses Cozy.NHW.Native, Cozy.NHW.Types;

function ParseCaptureProcesses(const Data: TBytes;
  List: TCaptureProcessList): Boolean;
var
  Offset, NextEntry, DataStart, EntryEnd, TextAddress, Remaining: NativeUInt;
  P: ^TProcessPrefix;
  Info: TCaptureProcessInfo;
begin
  Result := False;
  if List = nil then Exit;
  List.Clear;
  try
    if SizeOf(TProcessPrefix) <> 88 then Exit;
    if Length(Data) < SizeOf(TProcessPrefix) then Exit;
    DataStart := NativeUInt(@Data[0]);
    if NativeUInt(Length(Data)) > High(NativeUInt) - DataStart then Exit;
    Offset := 0;
    repeat
      Remaining := NativeUInt(Length(Data)) - Offset;
      if Remaining < SizeOf(TProcessPrefix) then Exit;
      P := Pointer(DataStart + Offset);
      NextEntry := P^.NextEntryOffset;
      if NextEntry <> 0 then
      begin
        if (NextEntry < SizeOf(TProcessPrefix)) or
           ((NextEntry and 7) <> 0) or (NextEntry > Remaining) then Exit;
        if Remaining - NextEntry < SizeOf(TProcessPrefix) then Exit;
        EntryEnd := DataStart + Offset + NextEntry;
      end
      else EntryEnd := DataStart + NativeUInt(Length(Data));
      if ((P^.ImageName.Length and 1) <> 0) or
         ((P^.ImageName.MaximumLength and 1) <> 0) or
         (P^.ImageName.Length > P^.ImageName.MaximumLength) then Exit;
      if P^.ImageName.Length <> 0 then
      begin
        TextAddress := NativeUInt(P^.ImageName.Buffer);
        if TextAddress < DataStart + Offset + SizeOf(TProcessPrefix) then Exit;
        if TextAddress > EntryEnd then Exit;
        if NativeUInt(P^.ImageName.Length) > EntryEnd - TextAddress then Exit;
        if NativeUInt(P^.UniqueProcessId) > High(Cardinal) then Exit;
        if NativeUInt(P^.UniqueProcessId) > 4 then
        begin
          Info := Default(TCaptureProcessInfo);
          Info.PID := Cardinal(NativeUInt(P^.UniqueProcessId));
          SetString(Info.Name, P^.ImageName.Buffer,
            Integer(P^.ImageName.Length) div SizeOf(WideChar));
          if Pos(#0, Info.Name) <> 0 then Exit;
          List.Add(Info);
        end;
      end;
      if NextEntry = 0 then Exit(True);
      Inc(Offset, NextEntry);
    until False;
  finally
    if not Result then List.Clear;
  end;
end;

function ParseCaptureListeners(const Buffer: TBytes; ActualBytes: Cardinal;
  OutPIDs: TCapturePIDSet): Boolean;
var
  I, Count: Cardinal;
  Row: PTcpRowNative;
begin
  Result := False;
  if OutPIDs = nil then Exit;
  OutPIDs.Clear;
  try
    if (ActualBytes < SizeOf(Cardinal)) or
       (NativeUInt(ActualBytes) > NativeUInt(Length(Buffer))) then Exit;
    Count := PCardinal(@Buffer[0])^;
    if Count > (ActualBytes - SizeOf(Cardinal)) div SizeOf(TTcpRowNative) then Exit;
    if Count <> 0 then
      for I := 0 to Count - 1 do
      begin
        Row := Pointer(NativeUInt(@Buffer[0]) + SizeOf(Cardinal) +
          NativeUInt(I) * SizeOf(TTcpRowNative));
        if Row^.State <> 2 then Exit; // Listener-only table contract.
        if Row^.OwnerPID > 4 then OutPIDs.AddOrSetValue(Row^.OwnerPID, 1);
      end;
    Result := True;
  finally
    if not Result then OutPIDs.Clear;
  end;
end;

end.
