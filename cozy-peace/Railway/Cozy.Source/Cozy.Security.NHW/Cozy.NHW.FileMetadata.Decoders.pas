unit Cozy.NHW.FileMetadata.Decoders;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

{$POINTERMATH ON}
{$Q-} // Same wrapping hash arithmetic as the original.

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes;

const
  MAX_QUERY_BYTES = 256 * 1024;
  FNV_OFFSET = UInt64($CBF29CE484222325);
  FNV_PRIME = UInt64($100000001B3);

function DecodeFileName(const B: TBytes; out Name: string): Boolean;
procedure HashByte(var H: UInt64; Value: Byte);
procedure HashCardinal(var H: UInt64; V: Cardinal);
procedure HashString(var H: UInt64; const Text: string);
procedure HashMemory(var H: UInt64; P: PByte; Bytes: Cardinal);
function ReparsePayloadValid(const B: array of Byte;
  BytesReturned: Cardinal): Boolean;
function DecodeStreamSet(const B: TBytes; out Digest: UInt64): Boolean;
function DecodeFileDacl(const B: TBytes; ActualBytes: Cardinal;
  out Digest: UInt64): Boolean;
function DecodeLinkNames(const B: TBytes; out Digest: UInt64): Boolean;

implementation

function DecodeFileName(const B: TBytes; out Name: string): Boolean;
var
  Len: Cardinal;
begin
  Result := False;
  Name := '';
  if Length(B) < 4 then Exit;
  Len := PCardinal(@B[0])^;
  if (Len = 0) or ((Len and 1) <> 0) or
     (Len > Cardinal(Length(B) - 4)) or (Len > 32760 * SizeOf(WideChar)) then Exit;
  SetString(Name, PWideChar(@B[4]), Integer(Len) div SizeOf(WideChar));
  if Pos(#0, Name) <> 0 then
  begin
    Name := '';
    Exit;
  end;
  Result := True;
end;

procedure HashByte(var H: UInt64; Value: Byte);
begin
  H := (H xor UInt64(Value)) * FNV_PRIME;
end;

procedure HashCardinal(var H: UInt64; V: Cardinal);
var
  I: Integer;
begin
  for I := 0 to 3 do
    HashByte(H, Byte((V shr (I * 8)) and $FF));
end;

procedure HashString(var H: UInt64; const Text: string);
var
  I: Integer;
  W: Word;
begin
  HashCardinal(H, Cardinal(Length(Text)));
  for I := 1 to Length(Text) do
  begin
    W := Ord(Text[I]);
    HashByte(H, Byte(W and $FF));
    HashByte(H, Byte(W shr 8));
  end;
end;

procedure HashMemory(var H: UInt64; P: PByte; Bytes: Cardinal);
var
  I: Cardinal;
begin
  if Bytes = 0 then Exit;
  for I := 0 to Bytes - 1 do
    HashByte(H, P[I]);
end;

function ReparsePayloadValid(const B: array of Byte;
  BytesReturned: Cardinal): Boolean;
var
  DataBytes: Cardinal;
begin
  Result := False;
  if (BytesReturned < 8) or
     (NativeUInt(BytesReturned) > NativeUInt(Length(B))) then Exit;
  DataBytes := Cardinal(B[4]) or (Cardinal(B[5]) shl 8);
  // Generic/vendor reparse records may also include a GUID after the header.
  Result := DataBytes <= BytesReturned - 8;
end;

function DecodeStreamSet(const B: TBytes; out Digest: UInt64): Boolean;
var
  L: TStringList;
  Count, Offset, NextOffset, NameBytes, Remaining, EntryBytes: Cardinal;
  I: Integer;
  StreamSize, AllocationSize: Int64;
  Name: string;
  CandidateDigest: UInt64;
begin
  Result := False;
  Digest := 0;
  if (Length(B) < 24) or (Length(B) > MAX_QUERY_BYTES) then Exit;
  L := TStringList.Create;
  try
    L.Sorted := True;
    L.CaseSensitive := False;
    Offset := 0;
    Count := 0;
    repeat
      Remaining := Cardinal(Length(B)) - Offset;
      if Remaining < 24 then Exit;
      NextOffset := PCardinal(@B[Offset])^;
      NameBytes := PCardinal(@B[Offset + 4])^;
      StreamSize := PInt64(@B[Offset + 8])^;
      AllocationSize := PInt64(@B[Offset + 16])^;
      if (StreamSize < 0) or (AllocationSize < 0) then Exit;
      EntryBytes := Remaining;
      if NextOffset <> 0 then
      begin
        if (NextOffset < 24) or ((NextOffset and 7) <> 0) or
           (NextOffset > Remaining) then Exit;
        if Remaining - NextOffset < 24 then Exit;
        EntryBytes := NextOffset;
      end;
      if ((NameBytes and 1) <> 0) or (NameBytes > 32768) or
         (NameBytes > EntryBytes - 24) then Exit;
      Name := '';
      if NameBytes <> 0 then
        SetString(Name, PWideChar(@B[Offset + 24]), Integer(NameBytes) div 2);
      if Pos(#0, Name) <> 0 then Exit;
      if (Name <> '') and not SameText(Name, '::$DATA') then
        L.Add(LowerCase(Name) + '=' + IntToStr(StreamSize));
      Inc(Count);
      if Count > 1024 then Exit;
      if NextOffset = 0 then Break;
      Inc(Offset, NextOffset);
    until False;
    CandidateDigest := FNV_OFFSET;
    for I := 0 to L.Count - 1 do HashString(CandidateDigest, L[I]);
    Digest := CandidateDigest;
    Result := True;
  finally
    L.Free;
  end;
end;

function DecodeFileDacl(const B: TBytes; ActualBytes: Cardinal;
  out Digest: UInt64): Boolean;
var
  Offset, AclBytes, Cursor, I, AceBytes: Cardinal;
  Control, AceCount: Word;
  CandidateDigest: UInt64;
begin
  Result := False;
  Digest := 0;
  if (ActualBytes < 20) or (NativeUInt(ActualBytes) > NativeUInt(Length(B))) then Exit;
  if B[0] <> 1 then Exit; // SECURITY_DESCRIPTOR_REVISION
  Control := PWord(@B[2])^;
  if (Control and $8000) = 0 then Exit; // Relative offsets, not absolute pointers.
  Offset := PCardinal(@B[16])^;
  CandidateDigest := FNV_OFFSET;
  HashCardinal(CandidateDigest, Cardinal(Control and ($0004 or $0008 or $1000)));
  if (Control and $0004) <> 0 then
  begin
    if Offset <> 0 then
    begin
      if (Offset < 20) or ((Offset and 3) <> 0) or (Offset > ActualBytes - 8) then Exit;
      if (B[Offset] <> 2) and (B[Offset] <> 4) then Exit;
      AclBytes := PWord(@B[Offset + 2])^;
      if (AclBytes < 8) or (AclBytes > ActualBytes - Offset) or
         ((AclBytes and 3) <> 0) then Exit;
      AceCount := PWord(@B[Offset + 4])^;
      Cursor := 8;
      if AceCount <> 0 then
        for I := 0 to Cardinal(AceCount) - 1 do
        begin
          if Cursor > AclBytes - 4 then Exit;
          AceBytes := PWord(@B[Offset + Cursor + 2])^;
          if (AceBytes < 4) or ((AceBytes and 3) <> 0) or
             (AceBytes > AclBytes - Cursor) then Exit;
          Inc(Cursor, AceBytes);
        end;
      HashCardinal(CandidateDigest, AclBytes);
      HashMemory(CandidateDigest, @B[Offset], AclBytes);
    end
    else HashCardinal(CandidateDigest, 0);
  end
  else if Offset <> 0 then Exit;
  Digest := CandidateDigest;
  Result := True;
end;

function DecodeLinkNames(const B: TBytes; out Digest: UInt64): Boolean;
var
  L: TStringList;
  Offset, NextOffset, NameChars, ActualBytes, Remaining, EntryBytes: Cardinal;
  ParentId: Int64;
  Name: string;
  Entries, Count: Cardinal;
  I: Integer;
  CandidateDigest: UInt64;
begin
  Result := False;
  Digest := 0;
  if (Length(B) < 28) or (Length(B) > MAX_QUERY_BYTES) then Exit;
  ActualBytes := PCardinal(@B[0])^;
  Entries := PCardinal(@B[4])^;
  if (ActualBytes < 28) or (ActualBytes > Cardinal(Length(B))) or
     (Entries = 0) or (Entries > 1024) then Exit;
  Offset := 8;
  Count := 0;
  L := TStringList.Create;
  try
    L.Sorted := True;
    L.CaseSensitive := False;
    repeat
      Remaining := ActualBytes - Offset;
      if Remaining < 20 then Exit;
      NextOffset := PCardinal(@B[Offset])^;
      ParentId := PInt64(@B[Offset + 8])^;
      NameChars := PCardinal(@B[Offset + 16])^;
      EntryBytes := Remaining;
      if NextOffset <> 0 then
      begin
        if (NextOffset < 20) or ((NextOffset and 7) <> 0) or
           (NextOffset > Remaining) then Exit;
        if Remaining - NextOffset < 20 then Exit;
        EntryBytes := NextOffset;
      end;
      if (NameChars = 0) or (NameChars > 16384) or
         (NameChars > (EntryBytes - 20) div 2) then Exit;
      SetString(Name, PWideChar(@B[Offset + 20]), Integer(NameChars));
      if Pos(#0, Name) <> 0 then Exit;
      L.Add(IntToHex(UInt64(ParentId), 16) + ':' + LowerCase(Name));
      Inc(Count);
      if NextOffset = 0 then Break;
      if Count >= Entries then Exit;
      Inc(Offset, NextOffset);
    until False;
    if Count <> Entries then Exit;
    CandidateDigest := FNV_OFFSET;
    for I := 0 to L.Count - 1 do HashString(CandidateDigest, L[I]);
    Digest := CandidateDigest;
    Result := True;
  finally
    L.Free;
  end;
end;

end.
