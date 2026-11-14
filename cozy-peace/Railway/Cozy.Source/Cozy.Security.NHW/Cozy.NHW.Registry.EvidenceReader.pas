unit Cozy.NHW.Registry.EvidenceReader;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections, Cozy.NHW.RegistryNative;

const
  REG_ENTRY_MAX_BYTES = 131072;
  REG_MAX_ENUM_ITEMS = 512;
  REG_MAX_SECURITY_BYTES = 65536;
  FNV_OFFSET: UInt64 = $CBF29CE484222325;
  FNV_PRIME: UInt64 = $100000001B3;

type
  TRegEnumResult = (reData, reEnd, reFailure);

function HashBuffer(Hash: UInt64; Ptr: PByte; Count: NativeUInt): UInt64;
function HashCardinal(Hash: UInt64; const C: Cardinal): UInt64;
function HashUnicode(Hash: UInt64; const Value: string): UInt64;
function CanonicalHash(Items: TList<string>): UInt64;
function QueryEntry(Key: THandle; Index: Cardinal; IsValue: Boolean;
  out Data: TBytes; out Returned: Cardinal): TRegEnumResult;
function ReadValues(Key: THandle; out Signature: UInt64): Boolean;
function ReadSubkeys(Key: THandle; out Signature: UInt64): Boolean;
function ReadDacl(Key: THandle; out Signature: UInt64): Boolean;

implementation

function HashBuffer(Hash: UInt64; Ptr: PByte; Count: NativeUInt): UInt64;
{$Q-}
var
  I: NativeUInt;
begin
  Result := Hash;
  if (Ptr = nil) or (Count = 0) then Exit;
  for I := 0 to Count - 1 do
  begin
    Result := (Result xor UInt64(Ptr^)) * FNV_PRIME;
    Inc(Ptr);
  end;
end;

function HashCardinal(Hash: UInt64; const C: Cardinal): UInt64;
begin
  Result := HashBuffer(Hash, PByte(@C), SizeOf(C));
end;

function HashUnicode(Hash: UInt64; const Value: string): UInt64;
begin
  Result := HashCardinal(Hash, Cardinal(Length(Value)));
  if Value <> '' then
    Result := HashBuffer(Result, PByte(PWideChar(Value)),
      NativeUInt(Length(Value)) * SizeOf(WideChar));
end;

function CanonicalHash(Items: TList<string>): UInt64;
var
  Item: string;
begin
  Items.Sort;
  Result := HashCardinal(FNV_OFFSET, Cardinal(Items.Count));
  for Item in Items do
    Result := HashUnicode(Result, Item);
end;

function QueryEntry(Key: THandle; Index: Cardinal; IsValue: Boolean;
  out Data: TBytes; out Returned: Cardinal): TRegEnumResult;
var
  Status: TRegNtStatus;
  Capacity, Wanted: Cardinal;
begin
  Returned := 0;
  Capacity := 4096;
  repeat
    SetLength(Data, Capacity);
    if IsValue then
      Status := NativeEnumerateRegistryValue(Key, Index,
        @Data[0], Capacity, Wanted)
    else
      Status := NativeEnumerateRegistryKey(Key, Index,
        @Data[0], Capacity, Wanted);
    if Cardinal(Status) = REG_STATUS_NO_MORE_ENTRIES then
      Exit(reEnd);
    if Status >= 0 then
    begin
      if (Wanted = 0) or (Wanted > Capacity) then Exit(reFailure);
      Returned := Wanted;
      Exit(reData);
    end;
    if (Cardinal(Status) <> REG_STATUS_BUFFER_OVERFLOW) and
       (Cardinal(Status) <> REG_STATUS_BUFFER_TOO_SMALL) then Exit(reFailure);
    if Wanted > REG_ENTRY_MAX_BYTES then Exit(reFailure);
    if Wanted > Capacity then Capacity := Wanted
    else if Capacity <= REG_ENTRY_MAX_BYTES div 2 then
      Capacity := Capacity * 2
    else Exit(reFailure);
  until False;
end;

function ReadValues(Key: THandle; out Signature: UInt64): Boolean;
var
  Index, Returned: Cardinal;
  Data: TBytes;
  Q: TRegEnumResult;
  Info: ^TRegValueFull;
  ValueName: string;
  ItemDigest: UInt64;
  Items: TList<string>;
begin
  Result := False;
  Signature := 0;
  Items := TList<string>.Create;
  try
    for Index := 0 to REG_MAX_ENUM_ITEMS do
    begin
      Q := QueryEntry(Key, Index, True, Data, Returned);
      if Q = reEnd then
      begin
        Signature := CanonicalHash(Items);
        Exit(True);
      end;
      if Q <> reData then Exit;
      if Returned < SizeOf(TRegValueFull) then Exit;
      Info := Pointer(@Data[0]);
      if ((Info^.NameLength and 1) <> 0) or
         (Info^.NameLength > Returned - SizeOf(TRegValueFull)) then Exit;
      if Info^.DataLength > 0 then
      begin
        if (Info^.DataOffset < SizeOf(TRegValueFull)) or
           (Info^.DataOffset > Returned) then Exit;
        if Info^.DataLength > Returned - Info^.DataOffset then Exit;
      end;
      SetString(ValueName, PWideChar(@Data[SizeOf(TRegValueFull)]),
        Integer(Info^.NameLength) div SizeOf(WideChar));
      ValueName := UpperCase(ValueName);
      ItemDigest := HashCardinal(FNV_OFFSET, Info^.DataType);
      ItemDigest := HashCardinal(ItemDigest, Info^.DataLength);
      if Info^.DataLength > 0 then
        ItemDigest := HashBuffer(ItemDigest,
          PByte(NativeUInt(@Data[0]) + Info^.DataOffset), Info^.DataLength);
      Items.Add(ValueName + ':' + IntToHex(ItemDigest, 16));
    end;
  finally
    Items.Free;
  end;
end;

function ReadSubkeys(Key: THandle; out Signature: UInt64): Boolean;
var
  Index, Returned: Cardinal;
  Data: TBytes;
  Q: TRegEnumResult;
  Info: ^TRegKeyBasic;
  KeyName: string;
  Items: TList<string>;
begin
  Result := False;
  Signature := 0;
  Items := TList<string>.Create;
  try
    for Index := 0 to REG_MAX_ENUM_ITEMS do
    begin
      Q := QueryEntry(Key, Index, False, Data, Returned);
      if Q = reEnd then
      begin
        Signature := CanonicalHash(Items);
        Exit(True);
      end;
      if Q <> reData then Exit;
      if Returned < SizeOf(TRegKeyBasic) then Exit;
      Info := Pointer(@Data[0]);
      if ((Info^.NameLength and 1) <> 0) or
         (Info^.NameLength > Returned - SizeOf(TRegKeyBasic)) then Exit;
      SetString(KeyName, PWideChar(@Data[SizeOf(TRegKeyBasic)]),
        Integer(Info^.NameLength) div SizeOf(WideChar));
      Items.Add(UpperCase(KeyName));
    end;
  finally
    Items.Free;
  end;
end;

function ReadDacl(Key: THandle; out Signature: UInt64): Boolean;
var
  Data: TBytes;
  LengthNeeded: Cardinal;
  Status: TRegNtStatus;
  SD: ^TRegSelfRelativeSD;
  ACL: ^TRegAclHeader;
  DaclAt: Cardinal;
  Flags: Cardinal;
begin
  Result := False;
  Signature := 0;
  SetLength(Data, 4096);
  Status := NativeRegistryDacl(Key, @Data[0], Length(Data), LengthNeeded);
  if (Cardinal(Status) = REG_STATUS_BUFFER_TOO_SMALL) and
     (LengthNeeded <= REG_MAX_SECURITY_BYTES) and
     (LengthNeeded > Cardinal(Length(Data))) then
  begin
    SetLength(Data, LengthNeeded);
    Status := NativeRegistryDacl(Key, @Data[0], Length(Data), LengthNeeded);
  end;
  if (Status < 0) or (LengthNeeded < SizeOf(TRegSelfRelativeSD)) or
     (LengthNeeded > Cardinal(Length(Data))) then Exit;
  SD := Pointer(@Data[0]);
  if (SD^.Control and $8000) = 0 then Exit; // require self-relative SD
  Flags := Cardinal(SD^.Control and ($0004 or $0100 or $0400 or $1000));
  Signature := HashCardinal(FNV_OFFSET, Flags);
  DaclAt := SD^.DaclOffset;
  if DaclAt = 0 then Exit(True); // NULL / absent DACL, flags distinguish
  if (DaclAt > LengthNeeded) or
     (SizeOf(TRegAclHeader) > LengthNeeded - DaclAt) then Exit(False);
  ACL := Pointer(NativeUInt(@Data[0]) + DaclAt);
  if (ACL^.AclSize < SizeOf(TRegAclHeader)) or
     (ACL^.AclSize > LengthNeeded - DaclAt) then Exit(False);
  Signature := HashBuffer(Signature,
    PByte(NativeUInt(@Data[0]) + DaclAt), ACL^.AclSize);
  Result := True;
end;

end.
