unit Cozy.NHW.Security.Snapshot;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows, System.SysUtils;

const
  MAX_SECURITY_DESCRIPTOR_BYTES = 65536;
  MAX_TOKEN_INFO_BYTES = 65536;
  STATUS_NO_TOKEN = $C000007C;
  DACL_SECURITY_INFORMATION_VALUE = $00000004;
  SE_SELF_RELATIVE = $8000;
  SE_DACL_PRESENT = $0004;
  SE_DACL_AUTO_INHERIT_REQ = $0100;
  SE_DACL_AUTO_INHERITED = $0400;
  SE_DACL_PROTECTED = $1000;
  TOKEN_PRIVILEGES_CLASS = 3;
  TOKEN_STATISTICS_CLASS = 10;
  TOKEN_ELEVATION_TYPE_CLASS = 18;
  TOKEN_LINKED_TOKEN_CLASS = 19;
  TOKEN_ELEVATION_CLASS = 20;
  TOKEN_HAS_RESTRICTIONS_CLASS = 21;
  TOKEN_INTEGRITY_LEVEL_CLASS = 25;
  TOKEN_IS_APPCONTAINER_CLASS = 29;
  MAX_TOKEN_PRIVILEGES = 256;
  TOKEN_FIELD_STATISTICS = $0001;
  TOKEN_FIELD_PRIVILEGES = $0002;
  TOKEN_FIELD_ELEVATION = $0004;
  TOKEN_FIELD_INTEGRITY = $0008;
  TOKEN_FIELD_RESTRICTED = $0010;
  TOKEN_FIELD_APPCONTAINER = $0020;
  TOKEN_FIELD_LINKED = $0040;
  TOKEN_DELTA_REPLACED = $0001;
  TOKEN_DELTA_PRIVILEGE_ESCALATED = $0002;
  TOKEN_DELTA_INTEGRITY_RAISED = $0004;
  TOKEN_DELTA_AUTHENTICATION_CHANGED = $0008;
  TOKEN_DELTA_TYPE_CHANGED = $0010;
  TOKEN_DELTA_RESTRICTION_REMOVED = $0020;
  TOKEN_DELTA_APPCONTAINER_REMOVED = $0040;
  TOKEN_DELTA_LINKED_CHANGED = $0080;
  TOKEN_DELTA_IMPERSONATION_CHANGED = $0100;
  FNV_OFFSET: UInt64 = $CBF29CE484222325;
  FNV_PRIME: UInt64 = $100000001B3;


type
  TTokenPrivilegeEntry = record
    Luid: UInt64;
    Attributes: Cardinal;
  end;
  { Fixed, RAM-only token state. Raw token/logon identifiers never go to the
    server. ValidFields distinguishes unavailable classes from measured zero. }
  TTokenSecuritySnapshot = record
    ValidFields: Word;
    TokenId, AuthenticationId, ModifiedId, LinkedTokenId: UInt64;
    TokenType, ImpersonationLevel, ElevationType, Elevated: Cardinal;
    IntegrityLevel, Restricted, AppContainer, PrivilegeCount: Cardinal;
    Privileges: array[0..MAX_TOKEN_PRIVILEGES - 1] of TTokenPrivilegeEntry;
  end;

function TryTokenStatisticsBuffer(const Data: TBytes; Returned: Cardinal;
  var Snapshot: TTokenSecuritySnapshot): Boolean;
function TryTokenPrivilegesBuffer(const Data: TBytes; Returned: Cardinal;
  var Snapshot: TTokenSecuritySnapshot): Boolean;
function TryTokenIntegrityBuffer(const Data: TBytes; Returned: Cardinal;
  out Level: Cardinal): Boolean;
function TryTokenSecuritySnapshot(Token: THandle;
  out Snapshot: TTokenSecuritySnapshot): Boolean;
function TokenSecurityDelta(const Previous, Current: TTokenSecuritySnapshot): Word;
procedure MergeTokenSecuritySnapshot(var Previous: TTokenSecuritySnapshot;
  const Current: TTokenSecuritySnapshot);

function HashBytes(Hash: UInt64; P: PByte; Len: NativeUInt): UInt64;
function HashCardinal(Hash: UInt64; Value: Cardinal): UInt64;
function HashUInt64(Hash: UInt64; Value: UInt64): UInt64;
function TryTokenId(Token: THandle; out Value: UInt64): Boolean;
function TryPrivilegeSignature(Token: THandle; out Signature: UInt64): Boolean;
function TryDaclBufferSignature(const Buffer: TBytes; Returned: Cardinal;
  out Signature: UInt64): Boolean;
function TryDaclSignature(H: THandle; out Signature: UInt64): Boolean;
function ThreadSecurityIdentity(ThreadID: Cardinal; CreateStamp: UInt64;
  out Identity: string): Boolean;
function TryThreadCreationStamp(H: THandle; out Stamp: UInt64): Boolean;
function SameProcessCreation(First, Second: THandle): Boolean;

implementation

uses
  Cozy.NHW.Native, Cozy.NHW.WinPointers;


function HashBytes(Hash: UInt64; P: PByte; Len: NativeUInt): UInt64;
{$Q-}
var
  I: NativeUInt;
begin
  Result := Hash;
  if Len = 0 then Exit;
  for I := 0 to Len - 1 do
  begin
    Result := (Result xor UInt64(P^)) * FNV_PRIME;
    Inc(P);
  end;
end;

function HashCardinal(Hash: UInt64; Value: Cardinal): UInt64;
begin
  Result := HashBytes(Hash, PByte(@Value), SizeOf(Value));
end;

function HashUInt64(Hash: UInt64; Value: UInt64): UInt64;
begin
  Result := HashBytes(Hash, PByte(@Value), SizeOf(Value));
end;

{ Windows SDK winnt.h TOKEN_STATISTICS: LUID(8), LUID(8), LARGE_INTEGER(8),
  two 32-bit enums, four DWORDs, LUID(8), total 56 bytes on Win64. All reads
  use Move from a validated blob; no returned pointer is blindly dereferenced. }
function TryTokenStatisticsBuffer(const Data: TBytes; Returned: Cardinal;
  var Snapshot: TTokenSecuritySnapshot): Boolean;
begin
  Result := False;
  Snapshot.ValidFields := Snapshot.ValidFields and not TOKEN_FIELD_STATISTICS;
  if (SizeOf(Pointer) <> 8) or (Returned <> 56) or
    (Returned > Cardinal(Length(Data))) then Exit;
  Move(Data[0], Snapshot.TokenId, 8);
  Move(Data[8], Snapshot.AuthenticationId, 8);
  Move(Data[24], Snapshot.TokenType, 4);
  Move(Data[28], Snapshot.ImpersonationLevel, 4);
  Move(Data[48], Snapshot.ModifiedId, 8);
  if (Snapshot.TokenId = 0) or
    ((Snapshot.TokenType <> 1) and (Snapshot.TokenType <> 2)) then Exit;
  if (Snapshot.TokenType = 2) and (Snapshot.ImpersonationLevel > 3) then Exit;
  if Snapshot.TokenType = 1 then Snapshot.ImpersonationLevel := 0;
  Snapshot.ValidFields := Snapshot.ValidFields or TOKEN_FIELD_STATISTICS;
  Result := True;
end;

function TryTokenPrivilegesBuffer(const Data: TBytes; Returned: Cardinal;
  var Snapshot: TTokenSecuritySnapshot): Boolean;
var Count: Cardinal; I, J: Integer; Entry: TTokenPrivilegeEntry;
begin
  Result := False;
  Snapshot.ValidFields := Snapshot.ValidFields and not TOKEN_FIELD_PRIVILEGES;
  if (Returned < 4) or (Returned > Cardinal(Length(Data))) or
    (Returned > MAX_TOKEN_INFO_BYTES) then Exit;
  Move(Data[0], Count, 4);
  { Windows LUID_AND_ATTRIBUTES uses a 12-byte wire stride, not the size of
    our Delphi record (which may include 8-byte alignment padding). }
  if (Count > MAX_TOKEN_PRIVILEGES) or (Count > (Returned - 4) div 12) then Exit;
  Snapshot.PrivilegeCount := Count;
  for I := 0 to Integer(Count) - 1 do
  begin
    Move(Data[4 + I * 12], Snapshot.Privileges[I].Luid, 8);
    Move(Data[12 + I * 12], Snapshot.Privileges[I].Attributes, 4);
    Snapshot.Privileges[I].Attributes := Snapshot.Privileges[I].Attributes and $7;
  end;
  if Count > 1 then
    for I := 1 to Integer(Count) - 1 do
    begin
      Entry := Snapshot.Privileges[I]; J := I - 1;
      while J >= 0 do
      begin
        if Snapshot.Privileges[J].Luid <= Entry.Luid then Break;
        Snapshot.Privileges[J + 1] := Snapshot.Privileges[J]; Dec(J);
      end;
      Snapshot.Privileges[J + 1] := Entry;
    end;
  for I := 1 to Integer(Count) - 1 do
    if Snapshot.Privileges[I - 1].Luid = Snapshot.Privileges[I].Luid then Exit;
  Snapshot.ValidFields := Snapshot.ValidFields or TOKEN_FIELD_PRIVILEGES;
  Result := True;
end;

function TryTokenIntegrityBuffer(const Data: TBytes; Returned: Cardinal;
  out Level: Cardinal): Boolean;
var Base, Sid, Offset: NativeUInt; Count: Byte; SidBytes: Cardinal;
begin
  Result := False; Level := 0;
  { Win64 SID_AND_ATTRIBUTES is 16 bytes. The SID pointer must point inside
    this exact returned allocation; range subtraction avoids addition wrap. }
  if (SizeOf(Pointer) <> 8) or (Returned < 16) or
    (Returned > Cardinal(Length(Data))) or (Returned > MAX_TOKEN_INFO_BYTES) then Exit;
  Base := NativeUInt(@Data[0]); Sid := 0;
  Move(Data[0], Sid, SizeOf(Sid));
  if (Sid = 0) or (Sid < Base) then Exit;
  Offset := Sid - Base;
  if (Offset < 16) or (Offset > Returned) then Exit;
  if NativeUInt(Returned) - Offset < 8 then Exit;
  if Data[Integer(Offset)] <> 1 then Exit;
  Count := Data[Integer(Offset) + 1];
  { A mandatory integrity SID is S-1-16-RID, exactly one subauthority.
    A well-framed but different SID is unavailable, not a fabricated level. }
  if Count <> 1 then Exit;
  SidBytes := 8 + Cardinal(Count) * 4;
  if NativeUInt(SidBytes) > NativeUInt(Returned) - Offset then Exit;
  { S-1-16 (mandatory label authority), encoded as six big-endian bytes. }
  if (Data[Integer(Offset) + 2] <> 0) or
    (Data[Integer(Offset) + 3] <> 0) or
    (Data[Integer(Offset) + 4] <> 0) or
    (Data[Integer(Offset) + 5] <> 0) or
    (Data[Integer(Offset) + 6] <> 0) or
    (Data[Integer(Offset) + 7] <> 16) then Exit;
  Move(Data[Integer(Offset) + Integer(SidBytes) - 4], Level, 4);
  Result := True;
end;

procedure WipeTokenBytes(var Data: TBytes);
begin
  if Length(Data) <> 0 then FillChar(Data[0], Length(Data), 0);
  Data := nil;
end;

function ReadTokenBlob(Token: THandle; InfoClass: Cardinal;
  var Data: TBytes; out Returned: Cardinal): Boolean;
var Status: TNTStatus; Attempt: Integer;
begin
  Result := False; Returned := 0;
  if (Token = 0) or (Length(Data) = 0) then Exit;
  for Attempt := 1 to 2 do
  begin
    FillChar(Data[0], Length(Data), 0);
    Status := QueryNativeTokenInformation(Token, InfoClass,
      @Data[0], Cardinal(Length(Data)), Returned);
    if Status >= 0 then
      Exit((Returned > 0) and (Returned <= Cardinal(Length(Data))));
    if (Cardinal(Status) <> $C0000023) and
      (Cardinal(Status) <> $80000005) and
      (Cardinal(Status) <> $C0000004) then Exit;
    if (Attempt = 2) or (Returned <= Cardinal(Length(Data))) or
      (Returned > MAX_TOKEN_INFO_BYTES) then Exit;
    WipeTokenBytes(Data); SetLength(Data, Integer(Returned));
  end;
end;

function ReadTokenCardinal(Token: THandle; InfoClass: Cardinal;
  out Value: Cardinal): Boolean;
var Returned: Cardinal;
begin
  Value := 0; Returned := 0;
  Result := (Token <> 0) and
    (QueryNativeTokenInformation(Token, InfoClass, @Value, SizeOf(Value), Returned) >= 0);
  Result := Result and (Returned = SizeOf(Value));
  if not Result then Value := 0;
end;

function TryTokenSecuritySnapshot(Token: THandle;
  out Snapshot: TTokenSecuritySnapshot): Boolean;
var Data, CheckData: TBytes; Returned: Cardinal; Linked: THandle;
  CheckState: TTokenSecuritySnapshot;
begin
  Snapshot := Default(TTokenSecuritySnapshot); Result := False;
  if (Token = 0) or (SizeOf(Pointer) <> 8) then Exit;
  Data := nil; CheckData := nil; Linked := 0;
  CheckState := Default(TTokenSecuritySnapshot);
  try
    SetLength(Data, 4096);
    if not ReadTokenBlob(Token, TOKEN_STATISTICS_CLASS, Data, Returned) or
      not TryTokenStatisticsBuffer(Data, Returned, Snapshot) then Exit;
    if ReadTokenBlob(Token, TOKEN_PRIVILEGES_CLASS, Data, Returned) then
      TryTokenPrivilegesBuffer(Data, Returned, Snapshot);
    if ReadTokenCardinal(Token, TOKEN_ELEVATION_TYPE_CLASS, Snapshot.ElevationType) and
      ReadTokenCardinal(Token, TOKEN_ELEVATION_CLASS, Snapshot.Elevated) and
      (Snapshot.ElevationType >= 1) and (Snapshot.ElevationType <= 3) and
      (Snapshot.Elevated <= 1) then
      Snapshot.ValidFields := Snapshot.ValidFields or TOKEN_FIELD_ELEVATION;
    if ReadTokenBlob(Token, TOKEN_INTEGRITY_LEVEL_CLASS, Data, Returned) and
      TryTokenIntegrityBuffer(Data, Returned, Snapshot.IntegrityLevel) then
      Snapshot.ValidFields := Snapshot.ValidFields or TOKEN_FIELD_INTEGRITY;
    if ReadTokenCardinal(Token, TOKEN_HAS_RESTRICTIONS_CLASS, Snapshot.Restricted) then
      Snapshot.ValidFields := Snapshot.ValidFields or TOKEN_FIELD_RESTRICTED;
    if ReadTokenCardinal(Token, TOKEN_IS_APPCONTAINER_CLASS, Snapshot.AppContainer) and
      (Snapshot.AppContainer <= 1) then
      Snapshot.ValidFields := Snapshot.ValidFields or TOKEN_FIELD_APPCONTAINER;
    if ((Snapshot.ValidFields and TOKEN_FIELD_ELEVATION) <> 0) and
      (Snapshot.ElevationType = 1) then
      Snapshot.ValidFields := Snapshot.ValidFields or TOKEN_FIELD_LINKED
    else
    begin
      Returned := 0;
      if QueryNativeTokenInformation(Token, TOKEN_LINKED_TOKEN_CLASS,
        @Linked, SizeOf(Linked), Returned) >= 0 then
        if (Returned = SizeOf(Linked)) and (Linked <> 0) and
          TryTokenId(Linked, Snapshot.LinkedTokenId) then
          Snapshot.ValidFields := Snapshot.ValidFields or TOKEN_FIELD_LINKED;
    end;
    { Reject a torn multi-query snapshot, retaining the previous baseline.
      ModifiedId is not itself a detection: legitimate use/rights reduction
      may change it. A later stable sample will be compared. }
    SetLength(CheckData, 56);
    if not ReadTokenBlob(Token, TOKEN_STATISTICS_CLASS, CheckData, Returned) or
      not TryTokenStatisticsBuffer(CheckData, Returned, CheckState) then Exit;
    if (Snapshot.TokenId <> CheckState.TokenId) or
      (Snapshot.ModifiedId <> CheckState.ModifiedId) then Exit;
    Result := True;
  finally
    CloseNativeProcess(Linked);
    WipeTokenBytes(CheckData); WipeTokenBytes(Data);
    FillChar(CheckState, SizeOf(CheckState), 0);
    if not Result then FillChar(Snapshot, SizeOf(Snapshot), 0);
  end;
end;

function TokenSecurityDelta(const Previous, Current: TTokenSecuritySnapshot): Word;
var Common: Word; I, J: Integer; PreviousAttributes: Cardinal; Found: Boolean;
begin
  Result := 0; Common := Previous.ValidFields and Current.ValidFields;
  if (Common and TOKEN_FIELD_STATISTICS) <> 0 then
  begin
    if Previous.TokenId <> Current.TokenId then Result := Result or TOKEN_DELTA_REPLACED;
    if Previous.AuthenticationId <> Current.AuthenticationId then
      Result := Result or TOKEN_DELTA_AUTHENTICATION_CHANGED;
    if Previous.TokenType <> Current.TokenType then Result := Result or TOKEN_DELTA_TYPE_CHANGED;
    if (Previous.TokenType = 2) and (Current.TokenType = 2) and
      (Current.ImpersonationLevel > Previous.ImpersonationLevel) then
      Result := Result or TOKEN_DELTA_IMPERSONATION_CHANGED;
  end;
  if (Common and TOKEN_FIELD_PRIVILEGES) <> 0 then
  begin
    if (Previous.PrivilegeCount > MAX_TOKEN_PRIVILEGES) or
      (Current.PrivilegeCount > MAX_TOKEN_PRIVILEGES) then Exit;
    for I := 0 to Integer(Current.PrivilegeCount) - 1 do
    begin
      if (Current.Privileges[I].Attributes and $4) <> 0 then Continue;
      Found := False; PreviousAttributes := 0;
      for J := 0 to Integer(Previous.PrivilegeCount) - 1 do
        if Current.Privileges[I].Luid = Previous.Privileges[J].Luid then
        begin Found := True; PreviousAttributes := Previous.Privileges[J].Attributes; Break; end;
      if not Found or ((PreviousAttributes and $4) <> 0) or
        (((Current.Privileges[I].Attributes and $2) <> 0) and
         ((PreviousAttributes and $2) = 0)) then
        Result := Result or TOKEN_DELTA_PRIVILEGE_ESCALATED;
    end;
  end;
  if (Common and TOKEN_FIELD_ELEVATION) <> 0 then
    if (Current.Elevated > Previous.Elevated) or
      ((Current.ElevationType = 2) and (Previous.ElevationType <> 2)) then
      Result := Result or TOKEN_DELTA_PRIVILEGE_ESCALATED;
  if ((Common and TOKEN_FIELD_INTEGRITY) <> 0) and
    (Current.IntegrityLevel > Previous.IntegrityLevel) then
    Result := Result or TOKEN_DELTA_INTEGRITY_RAISED;
  if ((Common and TOKEN_FIELD_RESTRICTED) <> 0) and
    (Previous.Restricted <> 0) and (Current.Restricted = 0) then
    Result := Result or TOKEN_DELTA_RESTRICTION_REMOVED;
  if ((Common and TOKEN_FIELD_APPCONTAINER) <> 0) and
    (Previous.AppContainer <> 0) and (Current.AppContainer = 0) then
    Result := Result or TOKEN_DELTA_APPCONTAINER_REMOVED;
  if ((Common and TOKEN_FIELD_LINKED) <> 0) and
    (Previous.LinkedTokenId <> Current.LinkedTokenId) then
    Result := Result or TOKEN_DELTA_LINKED_CHANGED;
end;

procedure MergeTokenSecuritySnapshot(var Previous: TTokenSecuritySnapshot;
  const Current: TTokenSecuritySnapshot);
begin
  if ((Previous.ValidFields and Current.ValidFields and TOKEN_FIELD_STATISTICS) <> 0) and
    (Previous.TokenId <> Current.TokenId) then
    FillChar(Previous, SizeOf(Previous), 0);
  if (Current.ValidFields and TOKEN_FIELD_STATISTICS) <> 0 then
  begin
    Previous.TokenId := Current.TokenId;
    Previous.AuthenticationId := Current.AuthenticationId;
    Previous.ModifiedId := Current.ModifiedId;
    Previous.TokenType := Current.TokenType;
    Previous.ImpersonationLevel := Current.ImpersonationLevel;
  end;
  if (Current.ValidFields and TOKEN_FIELD_PRIVILEGES) <> 0 then
  begin
    Previous.PrivilegeCount := Current.PrivilegeCount;
    Previous.Privileges := Current.Privileges;
  end;
  if (Current.ValidFields and TOKEN_FIELD_ELEVATION) <> 0 then
  begin Previous.ElevationType := Current.ElevationType; Previous.Elevated := Current.Elevated; end;
  if (Current.ValidFields and TOKEN_FIELD_INTEGRITY) <> 0 then Previous.IntegrityLevel := Current.IntegrityLevel;
  if (Current.ValidFields and TOKEN_FIELD_RESTRICTED) <> 0 then Previous.Restricted := Current.Restricted;
  if (Current.ValidFields and TOKEN_FIELD_APPCONTAINER) <> 0 then Previous.AppContainer := Current.AppContainer;
  if (Current.ValidFields and TOKEN_FIELD_LINKED) <> 0 then Previous.LinkedTokenId := Current.LinkedTokenId;
  Previous.ValidFields := Previous.ValidFields or Current.ValidFields;
end;

function TryTokenId(Token: THandle; out Value: UInt64): Boolean;
var
  Data: array[0..127] of Byte;
  Returned: Cardinal;
begin
  Value := 0;
  Result := False;
  if Token = 0 then Exit;
  FillChar(Data, SizeOf(Data), 0);
  Returned := 0;
  try
    if QueryNativeTokenInformation(Token, TOKEN_STATISTICS_CLASS,
      @Data[0], SizeOf(Data), Returned) < 0 then Exit;
    if (SizeOf(Pointer) <> 8) or (Returned <> 56) then Exit;
    Move(Data[0], Value, SizeOf(Value));
    Result := Value <> 0;
  finally
    FillChar(Data, SizeOf(Data), 0);
  end;
end;

function TryPrivilegeSignature(Token: THandle; out Signature: UInt64): Boolean;
var Data: TBytes; Returned: Cardinal; Snapshot: TTokenSecuritySnapshot; I: Integer;
begin
  Result := False; Signature := 0; Data := nil;
  Snapshot := Default(TTokenSecuritySnapshot);
  try
    SetLength(Data, 4096);
    if not ReadTokenBlob(Token, TOKEN_PRIVILEGES_CLASS, Data, Returned) or
      not TryTokenPrivilegesBuffer(Data, Returned, Snapshot) then Exit;
    Signature := HashCardinal(FNV_OFFSET, Snapshot.PrivilegeCount);
    for I := 0 to Integer(Snapshot.PrivilegeCount) - 1 do
    begin
      Signature := HashUInt64(Signature, Snapshot.Privileges[I].Luid);
      Signature := HashCardinal(Signature, Snapshot.Privileges[I].Attributes);
    end;
    Result := True;
  finally
    WipeTokenBytes(Data);
    FillChar(Snapshot, SizeOf(Snapshot), 0);
  end;
end;

function TryDaclBufferSignature(const Buffer: TBytes; Returned: Cardinal;
  out Signature: UInt64): Boolean;
var
  Offset, Cursor, AclEnd: Cardinal;
  Control, AclBytes, AceCount, AceBytes, Reserved: Word;
  I: Integer;
  Candidate: UInt64;
begin
  Result := False;
  Signature := 0;
  if (Returned < 20) or (Returned > Cardinal(Length(Buffer))) or
     (Returned > MAX_SECURITY_DESCRIPTOR_BYTES) then Exit;
  if Buffer[0] <> 1 then Exit;
  Move(Buffer[2], Control, SizeOf(Control));
  if (Control and SE_SELF_RELATIVE) = 0 then Exit;
  Move(Buffer[16], Offset, SizeOf(Offset));
  Candidate := HashCardinal(FNV_OFFSET, Control and
    (SE_DACL_PRESENT or SE_DACL_AUTO_INHERIT_REQ or
     SE_DACL_AUTO_INHERITED or SE_DACL_PROTECTED));
  if (Control and SE_DACL_PRESENT) = 0 then
  begin
    Signature := Candidate;
    Exit(True);
  end;
  if Offset = 0 then
  begin
    Signature := HashCardinal(Candidate, 0); // present NULL DACL
    Exit(True);
  end;
  // Validate the actual returned blob, not the allocated buffer capacity.
  if (Offset < 20) or ((Offset and 3) <> 0) or (Offset > Returned) then Exit;
  if Returned - Offset < 8 then Exit;
  if (Buffer[Integer(Offset)] <> 2) and (Buffer[Integer(Offset)] <> 4) then Exit;
  if Buffer[Integer(Offset) + 1] <> 0 then Exit;
  Move(Buffer[Integer(Offset) + 2], AclBytes, SizeOf(AclBytes));
  Move(Buffer[Integer(Offset) + 4], AceCount, SizeOf(AceCount));
  Move(Buffer[Integer(Offset) + 6], Reserved, SizeOf(Reserved));
  if Reserved <> 0 then Exit;
  if (AclBytes < 8) or (Cardinal(AclBytes) > Returned - Offset) then Exit;
  AclEnd := Offset + Cardinal(AclBytes); // bounded by Returned above
  Cursor := Offset + 8;
  for I := 0 to Integer(AceCount) - 1 do
  begin
    if AclEnd - Cursor < 4 then Exit;
    Move(Buffer[Integer(Cursor) + 2], AceBytes, SizeOf(AceBytes));
    if (AceBytes < 4) or ((AceBytes and 3) <> 0) then Exit;
    if Cardinal(AceBytes) > AclEnd - Cursor then Exit;
    Inc(Cursor, Cardinal(AceBytes));
  end;
  // Validate ACE framing without pretending to validate every future ACE type.
  // Preserve ACE order; exclude reserved/header padding and unused ACL slack.
  Candidate := HashCardinal(Candidate, 1); // non-NULL, including empty DACL
  Candidate := HashCardinal(Candidate, Buffer[Integer(Offset)]);
  Candidate := HashCardinal(Candidate, AceCount);
  if Cursor > Offset + 8 then
    Candidate := HashBytes(Candidate, @Buffer[Integer(Offset) + 8],
      NativeUInt(Cursor - Offset - 8));
  Signature := Candidate;
  Result := True;
end;

function TryDaclSignature(H: THandle; out Signature: UInt64): Boolean;
var
  Buffer: TBytes;
  Status: TNTStatus;
  Needed: Cardinal;
  Attempt: Integer;
begin
  Signature := 0;
  Result := False;
  if H = 0 then Exit;
  SetLength(Buffer, 1024);
  for Attempt := 1 to 3 do
  begin
    FillChar(Buffer[0], Length(Buffer), 0);
    Needed := 0;
    Status := QueryNativeSecurity(H, DACL_SECURITY_INFORMATION_VALUE,
      @Buffer[0], Cardinal(Length(Buffer)), Needed);
    if Status >= 0 then
      Exit(TryDaclBufferSignature(Buffer, Needed, Signature));
    if (Cardinal(Status) <> $C0000023) and
       (Cardinal(Status) <> $80000005) and
       (Cardinal(Status) <> $C0000004) then Exit;
    if (Needed <= Cardinal(Length(Buffer))) or
       (Needed > MAX_SECURITY_DESCRIPTOR_BYTES) or (Attempt = 3) then Exit;
    SetLength(Buffer, Integer(Needed));
  end;
end;

function ThreadSecurityIdentity(ThreadID: Cardinal; CreateStamp: UInt64;
  out Identity: string): Boolean;
begin
  Identity := '';
  Result := (ThreadID <> 0) and (CreateStamp <> 0);
  if Result then
    Identity := 'T:' + IntToStr(ThreadID) + ':' + UIntToStr(CreateStamp);
end;

function TryThreadCreationStamp(H: THandle; out Stamp: UInt64): Boolean;
var Created, Exited, Kernel, UserTime: TFileTime;
begin
  Stamp := 0;
  Result := False;
  if H = 0 then Exit;
  Created := Default(TFileTime);
  Exited := Default(TFileTime);
  Kernel := Default(TFileTime);
  UserTime := Default(TFileTime);
  if not WinGetThreadTimes(H, Created, Exited, Kernel, UserTime) then Exit;
  // ExitTime is undefined for a live thread; never use it as a liveness flag.
  Stamp := (UInt64(Created.dwHighDateTime) shl 32) or Created.dwLowDateTime;
  Result := Stamp <> 0;
end;

function SameProcessCreation(First, Second: THandle): Boolean;
var
  C1, C2, Exited, Kernel, UserTime: TFileTime;
  S1, S2: UInt64;
begin
  Result := False;
  if (First = 0) or (Second = 0) then Exit;
  C1 := Default(TFileTime);
  C2 := Default(TFileTime);
  Exited := Default(TFileTime);
  Kernel := Default(TFileTime);
  UserTime := Default(TFileTime);
  if not WinGetProcessTimes(First, C1, Exited, Kernel, UserTime) then Exit;
  if not WinGetProcessTimes(Second, C2, Exited, Kernel, UserTime) then Exit;
  S1 := (UInt64(C1.dwHighDateTime) shl 32) or C1.dwLowDateTime;
  S2 := (UInt64(C2.dwHighDateTime) shl 32) or C2.dwLowDateTime;
  Result := (S1 <> 0) and (S1 = S2);
end;

end.
