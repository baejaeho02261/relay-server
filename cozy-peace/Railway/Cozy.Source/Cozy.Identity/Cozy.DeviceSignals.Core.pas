unit Cozy.DeviceSignals.Core;
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Identity,
 {$IFDEF FPC}SysUtils{$ELSE}System.SysUtils{$ENDIF};
const MaximumSignalDisks = 8; MaximumSignalNics = 64;
type
  TDeviceSignalItem = record
    Kind: Byte;
    Digest: array[0..31] of Byte;
  end;
  TDeviceSignalSet = record
    Items: array[0..MaximumSignalDisks + MaximumSignalNics - 1] of TDeviceSignalItem;
    Count: Integer;
    DiskCount, NicCount: Cardinal;
  end;
procedure ClearDeviceBytes(var Bytes: TBytes);
function ParseStorageSerial(const Buffer: TBytes; Actual: Cardinal; out Serial: TBytes): Boolean;
function ParsePermanentAddress(const Buffer: TBytes; Actual: Cardinal; out Address: TBytes): Boolean;
procedure AddDeviceSignal(var Signals: TDeviceSignalSet; Kind: Byte;
  const Key, Raw: TBytes);
function FinishDeviceSignals(var Signals: TDeviceSignalSet; const Key: TBytes): string;
implementation
uses Cozy.Hashes;
procedure ClearDeviceBytes(var Bytes: TBytes);
begin
  if Length(Bytes) <> 0 then FillChar(Bytes[0], Length(Bytes), 0);
  Bytes := nil;
end;
function U32(const Buffer: TBytes; Offset: Integer): Cardinal;
begin
  Result := Cardinal(Buffer[Offset]) or (Cardinal(Buffer[Offset+1]) shl 8) or
    (Cardinal(Buffer[Offset+2]) shl 16) or (Cardinal(Buffer[Offset+3]) shl 24);
end;
function ParseStorageSerial(const Buffer: TBytes; Actual: Cardinal; out Serial: TBytes): Boolean;
var Size, Offset, Finish, First, Last, I: Cardinal;
begin
  Serial := nil; Result := False;
  { STORAGE_DEVICE_DESCRIPTOR's fixed fields end at byte 36. All offsets and
    termination must remain inside BOTH returned bytes and the claimed size. }
  if (Actual < 36) or (UInt64(Actual) > UInt64(Length(Buffer))) then Exit;
  Size := U32(Buffer, 4); Offset := U32(Buffer, 24);
  if (U32(Buffer, 0) < 36) or (Size < 36) or (Size > Actual) or
    (Offset < 36) or (Offset >= Size) then Exit;
  Finish := Offset;
  while (Finish < Size) and (Finish - Offset <= 128) and (Buffer[Finish] <> 0) do Inc(Finish);
  if (Finish >= Size) or (Finish - Offset > 128) or (Buffer[Finish] <> 0) then Exit;
  First := Offset; Last := Finish;
  while (First < Last) and (Buffer[First] = 32) do Inc(First);
  while (Last > First) and (Buffer[Last - 1] = 32) do Dec(Last);
  if Last = First then Exit;
  for I := First to Last - 1 do if (Buffer[I] < 32) or (Buffer[I] > 126) then Exit;
  SetLength(Serial, Last - First); Move(Buffer[First], Serial[0], Length(Serial));
  Result := True;
end;
function ParsePermanentAddress(const Buffer: TBytes; Actual: Cardinal; out Address: TBytes): Boolean;
var I: Cardinal; AnyNonzero, AnyNotFF: Boolean;
begin
  Address := nil; Result := False;
  if ((Actual <> 6) and (Actual <> 8)) or (Actual > Cardinal(Length(Buffer))) then Exit;
  if (Buffer[0] and 1) <> 0 then Exit;
  AnyNonzero := False; AnyNotFF := False;
  for I := 0 to Actual - 1 do
  begin AnyNonzero := AnyNonzero or (Buffer[I] <> 0); AnyNotFF := AnyNotFF or (Buffer[I] <> $FF); end;
  if not AnyNonzero or not AnyNotFF then Exit;
  SetLength(Address, Actual); Move(Buffer[0], Address[0], Actual); Result := True;
end;
procedure AddDeviceSignal(var Signals: TDeviceSignalSet; Kind: Byte;
  const Key, Raw: TBytes);
var Hasher: TBlake3Hasher; Digest: TBytes; Item: TDeviceSignalItem; I: Integer;
  Size: Cardinal;
const Domain: AnsiString = CozyText_DeviceSignals_Core_cozy_Client_DeviceSignals_Item_v1_da1a8384;
begin
  if ((Kind <> 1) and (Kind <> 2)) or (Length(Key) <> 32) or
    (Length(Raw) = 0) or (Length(Raw) > 128) then raise EArgumentException.Create(CozyText_DeviceSignals_Core_DEVICE_SIGNAL_INPUT_8f1048a2);
  if (Signals.Count < 0) or (Signals.Count >= Length(Signals.Items)) or
    ((Kind = 1) and (Signals.DiskCount >= MaximumSignalDisks)) or
    ((Kind = 2) and (Signals.NicCount >= MaximumSignalNics)) then Exit;
  Hasher := nil; Item := Default(TDeviceSignalItem);
  try
    Hasher := TBlake3Hasher.CreateKeyed(Key); Hasher.Update(Domain[1], Length(Domain));
    Hasher.Update(Kind, 1); Size := Cardinal(Length(Raw)); Hasher.Update(Size, SizeOf(Size));
    Hasher.Update(Raw[0], Length(Raw)); Digest := Hasher.FinishBytes;
    Item.Kind := Kind; Move(Digest[0], Item.Digest, 32);
    for I := 0 to Signals.Count - 1 do
      if (Signals.Items[I].Kind = Kind) and CompareMem(@Signals.Items[I].Digest, @Item.Digest, 32) then Exit;
    Signals.Items[Signals.Count] := Item; Inc(Signals.Count);
    if Kind = 1 then Inc(Signals.DiskCount) else Inc(Signals.NicCount);
  finally Hasher.Free; ClearDeviceBytes(Digest); FillChar(Item, SizeOf(Item), 0); end;
end;
function CompareItems(const A, B: TDeviceSignalItem): Integer;
var I: Integer;
begin
  Result := Integer(A.Kind) - Integer(B.Kind); if Result <> 0 then Exit;
  for I := 0 to 31 do begin Result := Integer(A.Digest[I]) - Integer(B.Digest[I]); if Result <> 0 then Exit; end;
end;
function FinishDeviceSignals(var Signals: TDeviceSignalSet; const Key: TBytes): string;
var Hasher: TBlake3Hasher; Item: TDeviceSignalItem; I, J: Integer;
const Domain: AnsiString = CozyText_DeviceSignals_Core_cozy_Client_DeviceSignals_Set_v1_22db57cc;
begin
  Result := ''; Hasher := nil; Item := Default(TDeviceSignalItem);
  if (Signals.Count < 0) or (Signals.Count > Length(Signals.Items)) then
    raise EArgumentException.Create(CozyText_DeviceSignals_Core_DEVICE_SIGNAL_COUNT_b06699a1);
  if Signals.Count = 0 then Exit;
  try
    for I := 1 to Signals.Count - 1 do
    begin
      Item := Signals.Items[I]; J := I;
      while (J > 0) and (CompareItems(Signals.Items[J-1], Item) > 0) do
      begin Signals.Items[J] := Signals.Items[J-1]; Dec(J); end;
      Signals.Items[J] := Item;
    end;
    Hasher := TBlake3Hasher.CreateKeyed(Key); Hasher.Update(Domain[1], Length(Domain));
    for I := 0 to Signals.Count - 1 do
    begin Hasher.Update(Signals.Items[I].Kind, 1); Hasher.Update(Signals.Items[I].Digest, 32); end;
    Result := Hasher.FinishHex;
  finally Hasher.Free; FillChar(Item, SizeOf(Item), 0); end;
end;
end.
