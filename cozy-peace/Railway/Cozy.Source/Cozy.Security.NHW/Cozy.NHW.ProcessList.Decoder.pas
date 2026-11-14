unit Cozy.NHW.ProcessList.Decoder;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

// Internal read-only decoding layer; callers retain collection/handle ownership.
uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections,
  Cozy.NHW.Native, Cozy.NHW.NativeSafety;

type
  TProcessCandidate = record
    PID: Cardinal;
    Created: UInt64;
  end;

function ReadProcessRecord(const Data: TBytes; Offset: NativeUInt;
  out P: TProcessPrefix; out Span: NativeUInt; out Name: string;
  out Created: UInt64; out ErrorText: string): Boolean;
function CollectNameCandidates(const Data: TBytes; const TargetName: string;
  Candidates: TList<TProcessCandidate>; out ErrorText: string): Boolean;

implementation

// Parse one complete variable-size record before dereferencing its name. This
// is a local snapshot buffer; the name must belong to its own record, not to
// another process record. Offsets always progress inside the delivered buffer.
function ReadProcessRecord(const Data: TBytes; Offset: NativeUInt;
  out P: TProcessPrefix; out Span: NativeUInt; out Name: string;
  out Created: UInt64; out ErrorText: string): Boolean;
var
  Total, Base, Address, NameOffset: NativeUInt;
  SignedCreated: Int64;
begin
  Result := False;
  P := Default(TProcessPrefix);
  Span := 0;
  Name := '';
  Created := 0;
  ErrorText := '';
  Total := NativeUInt(Length(Data));
  if not NHWBufferSpan(Total, Offset, SizeOf(P)) then
  begin
    ErrorText := 'Truncated native process-list record.';
    Exit;
  end;
  Move(Data[NativeInt(Offset)], P, SizeOf(P));
  if P.NextEntryOffset = 0 then Span := Total - Offset
  else
  begin
    Span := NativeUInt(P.NextEntryOffset);
    if (Span < NativeUInt(SizeOf(P))) or ((Span and 7) <> 0) or
       not NHWBufferSpan(Total, Offset, Span) then
    begin
      ErrorText := 'Invalid native process-list offset.';
      Exit;
    end;
    if not NHWBufferSpan(Total, Offset + Span, SizeOf(P)) then
    begin
      ErrorText := 'Missing next native process-list record.';
      Exit;
    end;
  end;
  if ((P.ImageName.Length and 1) <> 0) or
     ((P.ImageName.MaximumLength and 1) <> 0) or
     (P.ImageName.Length > P.ImageName.MaximumLength) then
  begin
    ErrorText := 'Invalid native process-list name length.';
    Exit;
  end;
  if P.ImageName.Length <> 0 then
  begin
    Base := NativeUInt(@Data[NativeInt(Offset)]);
    Address := NativeUInt(P.ImageName.Buffer);
    if (Address < Base) or ((Address and 1) <> 0) then
    begin
      ErrorText := 'Invalid native process-list name address.';
      Exit;
    end;
    NameOffset := Address - Base;
    if (NameOffset < NativeUInt(SizeOf(P))) or
       not NHWBufferSpan(Span, NameOffset, P.ImageName.MaximumLength) then
    begin
      ErrorText := 'Native process-list name escapes its record.';
      Exit;
    end;
    SetString(Name, P.ImageName.Buffer, Integer(P.ImageName.Length) div SizeOf(WideChar));
    if Pos(#0, Name) <> 0 then
    begin
      Name := '';
      ErrorText := 'Embedded null in native process-list name.';
      Exit;
    end;
  end;
  // Existing x64 prefix reserves bytes 8..55. CreateTime occupies bytes
  // 32..39, i.e. Reserved1[24..31]. No change to the shared NHW.Native ABI.
  SignedCreated := 0;
  Move(P.Reserved1[24], SignedCreated, SizeOf(SignedCreated));
  if SignedCreated > 0 then Created := UInt64(SignedCreated);
  Result := True;
end;

function CollectNameCandidates(const Data: TBytes; const TargetName: string;
  Candidates: TList<TProcessCandidate>; out ErrorText: string): Boolean;
var
  Offset, Span: NativeUInt;
  P: TProcessPrefix;
  C: TProcessCandidate;
  Name: string;
  Created: UInt64;
  Seen: TDictionary<Cardinal, Byte>;
begin
  Result := False;
  ErrorText := '';
  Candidates.Clear;
  Seen := nil;
  try
    if (SizeOf(TNativeUnicode) <> 16) or (SizeOf(TProcessPrefix) <> 88) then
    begin
      ErrorText := 'Unexpected x64 process-list structure layout.';
      Exit;
    end;
    Seen := TDictionary<Cardinal, Byte>.Create;
    Offset := 0;
    repeat
      if not ReadProcessRecord(Data, Offset, P, Span, Name, Created, ErrorText) then Exit;
      if (Name <> '') and SameText(Name, TargetName) and
         (NativeUInt(P.UniqueProcessId) > 0) and
         (NativeUInt(P.UniqueProcessId) <= NativeUInt(High(Cardinal))) then
      begin
        C.PID := Cardinal(P.UniqueProcessId);
        C.Created := Created;
        if Seen.ContainsKey(C.PID) then
        begin
          ErrorText := 'Duplicate matching PID in native process list.';
          Exit;
        end;
        Seen.Add(C.PID, 1);
        // Without a creation epoch, identity cannot be tied to a later open.
        if C.Created <> 0 then Candidates.Add(C);
      end;
      if P.NextEntryOffset = 0 then Break;
      Inc(Offset, Span);
    until False;
    Result := True;
  finally
    Seen.Free;
    if not Result then Candidates.Clear;
  end;
end;

end.
