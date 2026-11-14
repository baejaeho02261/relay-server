unit Cozy.NHW.Namespace.Decoders;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.SysUtils, System.Generics.Collections;

const
  SE_DACL_PRESENT_NS = $0004;
  SE_DACL_AUTO_INHERITED_NS = $0400;
  SE_DACL_PROTECTED_NS = $1000;
  SE_SELF_RELATIVE_NS = $8000;
  NS_MAX_ENTRIES = 4096;
  FNV_OFFSET_NS: UInt64 = $CBF29CE484222325;
  FNV_PRIME_NS: UInt64 = $100000001B3;

type
  TNamespaceEntry = record
    Name: string;
    TypeName: string;
    Target: string;
    TargetKnown: Boolean;
  end;
  TNamespaceEntries = TDictionary<string, TNamespaceEntry>;
  TNsUnicode = record
    Length: Word;
    MaximumLength: Word;
    Buffer: PWideChar;
  end;
  TNsObjectAttributes = record
    Length: Cardinal;
    RootDirectory: THandle;
    ObjectName: ^TNsUnicode;
    Attributes: Cardinal;
    SecurityDescriptor: Pointer;
    SecurityQualityOfService: Pointer;
  end;
  PNsDirectoryEntry = ^TNsDirectoryEntry;
  TNsDirectoryEntry = record
    Name: TNsUnicode;
    TypeName: TNsUnicode;
  end;

function NamespaceLayoutsValid: Boolean;
function ReadBoundedUnicode(const S: TNsUnicode; const Data: TBytes;
  Used, MaximumBytes: Cardinal; out Value: string): Boolean;
function ParseNamespacePage(const Data: TBytes; Used: Cardinal;
  Entries: TNamespaceEntries): Boolean;
function ParseNamespaceDacl(const Data: TBytes; Used: Cardinal;
  out Signature: UInt64): Boolean;

implementation

function NamespaceLayoutsValid: Boolean;
begin
  Result := (SizeOf(TNsUnicode) = 16) and
    (SizeOf(TNsDirectoryEntry) = 32) and (SizeOf(TNsObjectAttributes) = 48);
end;

function ReadBoundedUnicode(const S: TNsUnicode; const Data: TBytes;
  Used, MaximumBytes: Cardinal; out Value: string): Boolean;
var
  Base, Ptr, Offset: NativeUInt;
begin
  Result := False;
  Value := '';
  if (Used = 0) or (NativeUInt(Used) > NativeUInt(Length(Data))) then Exit;
  if ((S.Length and 1) <> 0) or ((S.MaximumLength and 1) <> 0) or
     (S.Length > S.MaximumLength) or (Cardinal(S.Length) > MaximumBytes) or
     (S.Buffer = nil) then Exit;
  Base := NativeUInt(@Data[0]);
  Ptr := NativeUInt(S.Buffer);
  if (Ptr < Base) or ((Ptr and 1) <> 0) then Exit;
  Offset := Ptr - Base;
  if Offset > NativeUInt(Used) then Exit;
  if NativeUInt(S.Length) > NativeUInt(Used) - Offset then Exit;
  SetString(Value, S.Buffer, Integer(S.Length div SizeOf(WideChar)));
  if Pos(#0, Value) <> 0 then
  begin
    Value := '';
    Exit;
  end;
  Result := True;
end;

function ParseNamespacePage(const Data: TBytes; Used: Cardinal;
  Entries: TNamespaceEntries): Boolean;
var
  Offset, StringFloor, Base, NameOffset, TypeOffset: NativeUInt;
  Info: PNsDirectoryEntry;
  Entry: TNamespaceEntry;
  Key: string;
  Terminated: Boolean;
begin
  Result := False;
  if Entries = nil then Exit;
  Entries.Clear;
  try
    if not NamespaceLayoutsValid then Exit;
    if (Used < SizeOf(TNsDirectoryEntry)) or
       (NativeUInt(Used) > NativeUInt(Length(Data))) then Exit;
    Base := NativeUInt(@Data[0]);
    Offset := 0;
    StringFloor := NativeUInt(Used);
    Terminated := False;
    while Offset <= NativeUInt(Used) - SizeOf(TNsDirectoryEntry) do
    begin
      // Headers may not overlap the string payload, even if inside allocation.
      if Offset + SizeOf(TNsDirectoryEntry) > StringFloor then Exit;
      Info := PNsDirectoryEntry(Base + Offset);
      if (Info^.Name.Buffer = nil) and (Info^.TypeName.Buffer = nil) then
      begin
        if (Info^.Name.Length <> 0) or (Info^.Name.MaximumLength <> 0) or
           (Info^.TypeName.Length <> 0) or (Info^.TypeName.MaximumLength <> 0) then Exit;
        Terminated := True;
        Break;
      end;
      Entry := Default(TNamespaceEntry);
      if not ReadBoundedUnicode(Info^.Name, Data, Used, 4096, Entry.Name) or
         not ReadBoundedUnicode(Info^.TypeName, Data, Used, 4096, Entry.TypeName) then Exit;
      if (Entry.Name = '') or (Entry.TypeName = '') or
         (Pos('\', Entry.Name) <> 0) then Exit;
      NameOffset := NativeUInt(Info^.Name.Buffer) - Base;
      TypeOffset := NativeUInt(Info^.TypeName.Buffer) - Base;
      if NameOffset < StringFloor then StringFloor := NameOffset;
      if TypeOffset < StringFloor then StringFloor := TypeOffset;
      if Offset + SizeOf(TNsDirectoryEntry) > StringFloor then Exit;
      Key := UpperCase(Entry.Name);
      if Entries.ContainsKey(Key) then Exit; // racing/ambiguous enumeration
      Entries.Add(Key, Entry);
      if Entries.Count > NS_MAX_ENTRIES then Exit;
      Inc(Offset, SizeOf(TNsDirectoryEntry));
    end;
    Result := Terminated;
  finally
    if not Result then Entries.Clear;
  end;
end;

{$IFOPT Q+}
  {$DEFINE NS_RESTORE_OVERFLOW_CHECK}
  {$Q-}
{$ENDIF}
function HashNsBytes(Hash: UInt64; Bytes: PByte; Size: NativeUInt): UInt64;
var I: NativeUInt;
begin
  Result := Hash;
  if Size = 0 then Exit;
  for I := 0 to Size - 1 do
  begin
    Result := (Result xor UInt64(Bytes^)) * FNV_PRIME_NS;
    Inc(Bytes);
  end;
end;
{$IFDEF NS_RESTORE_OVERFLOW_CHECK}
  {$Q+}
  {$UNDEF NS_RESTORE_OVERFLOW_CHECK}
{$ENDIF}

function ParseNamespaceDacl(const Data: TBytes; Used: Cardinal;
  out Signature: UInt64): Boolean;
var
  Offset, AcePos, I: Cardinal;
  Ctrl, AclBytes, AceCount, AceBytes: Word;
  Candidate: UInt64;
begin
  Result := False;
  Signature := 0;
  if (Used < 20) or (NativeUInt(Used) > NativeUInt(Length(Data))) then Exit;
  if Data[0] <> 1 then Exit;
  Ctrl := 0; Offset := 0; AclBytes := 0; AceCount := 0; AceBytes := 0;
  Move(Data[2], Ctrl, SizeOf(Ctrl));
  if (Ctrl and SE_SELF_RELATIVE_NS) = 0 then Exit;
  Move(Data[16], Offset, SizeOf(Offset));
  Ctrl := Ctrl and (SE_DACL_PRESENT_NS or SE_DACL_AUTO_INHERITED_NS or SE_DACL_PROTECTED_NS);
  Candidate := HashNsBytes(FNV_OFFSET_NS, PByte(@Ctrl), SizeOf(Ctrl));
  if (Ctrl and SE_DACL_PRESENT_NS) <> 0 then
  begin
    if Offset <> 0 then
    begin
      if (Offset < 20) or ((Offset and 3) <> 0) or (Offset > Used - 8) then Exit;
      if (Data[Integer(Offset)] <> 2) and (Data[Integer(Offset)] <> 4) then Exit;
      Move(Data[Integer(Offset) + 2], AclBytes, SizeOf(AclBytes));
      Move(Data[Integer(Offset) + 4], AceCount, SizeOf(AceCount));
      if (AclBytes < 8) or ((AclBytes and 3) <> 0) or
         (Cardinal(AclBytes) > Used - Offset) then Exit;
      AcePos := 8;
      if AceCount <> 0 then
        for I := 0 to Cardinal(AceCount) - 1 do
        begin
          if AcePos > Cardinal(AclBytes) - 4 then Exit;
          Move(Data[Integer(Offset + AcePos + 2)], AceBytes, SizeOf(AceBytes));
          if (AceBytes < 4) or ((AceBytes and 3) <> 0) or
             (Cardinal(AceBytes) > Cardinal(AclBytes) - AcePos) then Exit;
          Inc(AcePos, Cardinal(AceBytes));
        end;
      Candidate := HashNsBytes(Candidate, PByte(@Data[Integer(Offset)]), AclBytes);
    end;
  end
  else if Offset <> 0 then Exit;
  Signature := Candidate; // no partial signature is returned on a parse failure
  Result := True;
end;

end.
