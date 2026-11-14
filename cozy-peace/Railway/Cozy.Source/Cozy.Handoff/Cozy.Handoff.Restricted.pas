unit Cozy.Handoff.Restricted;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$ALIGN 8}
{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Handoff,
 Winapi.Windows, System.SysUtils;

type
  EOverlayRestrictedProfile = class(Exception);

{ Optional O privilege reduction, not an AppContainer/filesystem/network
  sandbox. No linked/elevated token, credentials, shell, explicit privilege enablement,
  broker, or unrestricted fallback is used. The caller retains ownership of
  Process even when a suspended child's validation or resume raises. }
function CreateOverlayRestrictedToken: THandle;
procedure RequireOverlayRestrictedProcess(Process: THandle);
procedure CreateOverlayRestrictedProcess(const Executable: string;
  var CommandLine: string; const Environment, WorkingDirectory: string;
  var Startup: TStartupInfo; var Process: TProcessInformation);

implementation

uses Cozy.Platform.ExportResolver, Cozy.Api.Pointer, Cozy.Api.ROR13;

type
  TOpenProcessTokenProc = function(Process: THandle; Access: DWORD;
    out Token: THandle): BOOL; stdcall;
  TCreateRestrictedTokenProc = function(Token: THandle; Flags, DisableCount: DWORD;
    Disable: Pointer; DeleteCount: DWORD; Delete: Pointer; RestrictCount: DWORD;
    Restrict: Pointer; out Restricted: THandle): BOOL; stdcall;
  TGetTokenInformationProc = function(Token: THandle; Kind: Integer;
    Buffer: Pointer; Bytes: DWORD; out Required: DWORD): BOOL; stdcall;
  TSetTokenInformationProc = function(Token: THandle; Kind: Integer;
    Buffer: Pointer; Bytes: DWORD): BOOL; stdcall;
  TCreateProcessAsUserProc = function(Token: THandle; Application, Command: PWideChar;
    ProcessAttributes, ThreadAttributes: PSecurityAttributes; Inherit: BOOL;
    Flags: DWORD; Environment: Pointer; Directory: PWideChar;
    var Startup: TStartupInfo; var Process: TProcessInformation): BOOL; stdcall;
  TResumeThreadProc = function(Thread: THandle): DWORD; stdcall;
  TCloseHandleProc = function(Handle: THandle): BOOL; stdcall;
  TLookupPrivilegeValueProc = function(SystemName, Name: PWideChar;
    out Value: TLuid): BOOL; stdcall;
  TSidAttributesLocal = record
    Sid: Pointer;
    Attributes: DWORD;
  end;
  PSidAttributesLocal = ^TSidAttributesLocal;
  TWellKnownSidLocal = packed record
    Revision, Count: Byte;
    Authority: array[0..5] of Byte;
    SubAuthority: array[0..1] of DWORD;
  end;
  TTokenGroupHeaderLocal = record
    Count: DWORD;
    First: TSidAttributesLocal;
  end;
  PTokenGroupHeaderLocal = ^TTokenGroupHeaderLocal;
  TTokenLabelBufferLocal = record
    LabelInfo: TSidAttributesLocal;
    Sid: TWellKnownSidLocal;
  end;
  TPrivilegeLocal = packed record
    LowPart: DWORD;
    HighPart: LongInt;
    Attributes: DWORD;
  end;
  PPrivilegeLocal = ^TPrivilegeLocal;

var
  SlotOpenToken, SlotCreateRestricted, SlotGetToken, SlotSetToken,
    SlotCreateProcess, SlotResume, SlotClose, SlotLookupPrivilege: TEncodedApiPointer;

const
  TokenQueryAccess = $0008;
  TokenDuplicateAccess = $0002;
  TokenAssignPrimaryAccess = $0001;
  TokenAdjustDefaultAccess = $0080;
  TokenUserKind = 1;
  TokenGroupsKind = 2;
  TokenPrivilegesKind = 3;
  TokenSessionKind = 12;
  TokenElevationKind = 20;
  TokenIntegrityKind = 25;
  GroupEnabled = $00000004;
  GroupDenyOnly = $00000010;
  GroupIntegrity = $00000020;
  MediumIntegrityRID = $2000;
  DisableMaximumPrivileges = $00000001;
  LuaToken = $00000004;
  ExtendedStartupFlag = $00080000;
  UnicodeEnvironment = $00000400;
  { Administrators, Power Users, Account/Server/Print/Backup Operators and
    Replicator. Missing groups are ignored by CreateRestrictedToken. }
  DeniedBuiltinRIDs: array[0..6] of DWORD = (544, 547, 548, 549, 550, 551, 552);

procedure Require(Allowed: Boolean; const Code: string);
begin
  if not Allowed then raise EOverlayRestrictedProfile.Create(Code);
end;

procedure CloseToken(var Token: THandle);
begin
  if Token <> 0 then
  begin
    TCloseHandleProc(DecodeApiPointer(SlotClose))(Token);
    Token := 0;
  end;
end;

function QueryToken(Token: THandle; Kind: Integer): TBytes;
var Required, Returned: DWORD;
begin
  Result := nil;
  Required := 0;
  TGetTokenInformationProc(DecodeApiPointer(SlotGetToken))(
    Token, Kind, nil, 0, Required);
  Require((Required > 0) and (Required <= 65536), CozyText_Handoff_Restricted_OVERLAY_TOKEN_QUERY_SIZE_b4b9ec0c);
  SetLength(Result, Required);
  Returned := 0;
  Require(TGetTokenInformationProc(DecodeApiPointer(SlotGetToken))(
    Token, Kind, @Result[0], Required, Returned) and
    (Returned > 0) and (Returned <= Required), CozyText_Handoff_Restricted_OVERLAY_TOKEN_QUERY_FAILED_2f9561d2);
  { TOKEN_GROUPS/USER/LABEL contain pointers into this exact allocation.
    Shrinking/reallocating it after the query would invalidate those pointers. }
end;

function SidSizeInBuffer(const Buffer: TBytes; Sid: Pointer): NativeUInt;
var Address, First, Last: NativeUInt; Count: Byte;
begin
  Require((Length(Buffer) >= 8) and (Sid <> nil), CozyText_Handoff_Restricted_OVERLAY_TOKEN_SID_INVALID_1673534c);
  First := NativeUInt(@Buffer[0]); Last := First + NativeUInt(Length(Buffer));
  Address := NativeUInt(Sid);
  Require((Address >= First) and (Address <= Last - 8), CozyText_Handoff_Restricted_OVERLAY_TOKEN_SID_RANGE_4a069d82);
  Require(PByte(Sid)^ = 1, CozyText_Handoff_Restricted_OVERLAY_TOKEN_SID_REVISION_1b722121);
  Count := PByte(Address + 1)^;
  Require((Count > 0) and (Count <= 15), CozyText_Handoff_Restricted_OVERLAY_TOKEN_SID_COUNT_e6345cd2);
  Result := 8 + NativeUInt(Count) * 4;
  Require(Result <= Last - Address, CozyText_Handoff_Restricted_OVERLAY_TOKEN_SID_RANGE_4a069d82);
end;

function SidAuthority(Sid: Pointer; LastByte: Byte): Boolean;
var I: Integer;
begin
  Result := False;
  for I := 2 to 6 do if PByte(NativeUInt(Sid) + NativeUInt(I))^ <> 0 then Exit;
  Result := PByte(NativeUInt(Sid) + 7)^ = LastByte;
end;

function QueryIntegrity(Token: THandle): DWORD;
var Buffer: TBytes; Entry: PSidAttributesLocal;
begin
  Buffer := QueryToken(Token, TokenIntegrityKind);
  Require(Length(Buffer) >= SizeOf(TSidAttributesLocal), CozyText_Handoff_Restricted_OVERLAY_TOKEN_LABEL_SIZE_b8740861);
  Entry := PSidAttributesLocal(@Buffer[0]);
  Require((SidSizeInBuffer(Buffer, Entry.Sid) = 12) and
    SidAuthority(Entry.Sid, 16) and ((Entry.Attributes and GroupIntegrity) <> 0),
    CozyText_Handoff_Restricted_OVERLAY_TOKEN_LABEL_INVALID_3d59098a);
  Result := PDWORD(NativeUInt(Entry.Sid) + 8)^;
end;

procedure RequireInteractiveUser(Token: THandle);
var Buffer: TBytes; Entry: PSidAttributesLocal; Bytes, RID: NativeUInt;
begin
  Buffer := QueryToken(Token, TokenSessionKind);
  Require((Length(Buffer) = SizeOf(DWORD)) and (PDWORD(@Buffer[0])^ <> 0),
    CozyText_Handoff_Restricted_OVERLAY_INTERACTIVE_SESSION_REQUIRED_89fe3012);
  Buffer := QueryToken(Token, TokenUserKind);
  Require(Length(Buffer) >= SizeOf(TSidAttributesLocal), CozyText_Handoff_Restricted_OVERLAY_TOKEN_USER_SIZE_5911f8b8);
  Entry := PSidAttributesLocal(@Buffer[0]); Bytes := SidSizeInBuffer(Buffer, Entry.Sid);
  if (Bytes = 12) and SidAuthority(Entry.Sid, 5) then
  begin
    RID := PDWORD(NativeUInt(Entry.Sid) + 8)^;
    Require((RID <> 18) and (RID <> 19) and (RID <> 20),
      CozyText_Handoff_Restricted_OVERLAY_SERVICE_ACCOUNT_FORBIDDEN_b36f02e1);
  end;
end;

procedure RequireRestrictedToken(Token: THandle);
var Buffer: TBytes; Groups: PTokenGroupHeaderLocal;
  Entry: PSidAttributesLocal; Privilege: PPrivilegeLocal;
  Offset, Count, I, J, SidBytes: NativeUInt; RID: DWORD; Notify: TLuid;
begin
  RequireInteractiveUser(Token);
  Require(QueryIntegrity(Token) <= MediumIntegrityRID, CozyText_Handoff_Restricted_OVERLAY_TOKEN_INTEGRITY_TOO_HIGH_b5438147);
  Buffer := QueryToken(Token, TokenElevationKind);
  Require((Length(Buffer) = SizeOf(DWORD)) and (PDWORD(@Buffer[0])^ = 0),
    CozyText_Handoff_Restricted_OVERLAY_TOKEN_STILL_ELEVATED_d3c6ac90);
  Buffer := QueryToken(Token, TokenGroupsKind);
  { DWORD group count is padded to the native SID_AND_ATTRIBUTES alignment. }
  Offset := SizeOf(Pointer);
  Require(NativeUInt(Length(Buffer)) >= Offset, CozyText_Handoff_Restricted_OVERLAY_TOKEN_GROUPS_SIZE_6eeab213);
  Groups := PTokenGroupHeaderLocal(@Buffer[0]); Count := Groups.Count;
  Require((Count <= 4096) and
    (Count <= (NativeUInt(Length(Buffer)) - Offset) div SizeOf(TSidAttributesLocal)),
    CozyText_Handoff_Restricted_OVERLAY_TOKEN_GROUPS_BOUNDS_781fd6ef);
  for I := 0 to Count do
  begin
    if I = Count then Break;
    Entry := PSidAttributesLocal(NativeUInt(@Buffer[0]) + Offset + I * SizeOf(TSidAttributesLocal));
    SidBytes := SidSizeInBuffer(Buffer, Entry.Sid);
    if (SidBytes <> 16) or not SidAuthority(Entry.Sid, 5) or
      (PDWORD(NativeUInt(Entry.Sid) + 8)^ <> 32) then Continue;
    RID := PDWORD(NativeUInt(Entry.Sid) + 12)^;
    for J := 0 to High(DeniedBuiltinRIDs) do
      if RID = DeniedBuiltinRIDs[J] then
        Require(((Entry.Attributes and GroupDenyOnly) <> 0) and
          ((Entry.Attributes and GroupEnabled) = 0), CozyText_Handoff_Restricted_OVERLAY_TOKEN_PRIVILEGED_GROUP_ed415f8a);
  end;
  Require(TLookupPrivilegeValueProc(DecodeApiPointer(SlotLookupPrivilege))(
    nil, CozyText_Handoff_Restricted_SeChangeNotifyPrivilege_487ec2fd, Notify), CozyText_Handoff_Restricted_OVERLAY_TOKEN_PRIVILEGE_LOOKUP_04439171);
  Buffer := QueryToken(Token, TokenPrivilegesKind);
  Require(Length(Buffer) >= SizeOf(DWORD), CozyText_Handoff_Restricted_OVERLAY_TOKEN_PRIVILEGES_SIZE_d86f74ca);
  Count := PDWORD(@Buffer[0])^;
  Require((Count <= 1) and
    (Count <= (NativeUInt(Length(Buffer)) - SizeOf(DWORD)) div SizeOf(TPrivilegeLocal)),
    CozyText_Handoff_Restricted_OVERLAY_TOKEN_PRIVILEGES_REMAIN_931f9f76);
  if Count = 1 then
  begin
    Privilege := PPrivilegeLocal(NativeUInt(@Buffer[0]) + SizeOf(DWORD));
    Require((Privilege.LowPart = Notify.LowPart) and (Privilege.HighPart = Notify.HighPart),
      CozyText_Handoff_Restricted_OVERLAY_TOKEN_PRIVILEGES_REMAIN_931f9f76);
  end;
end;

function CreateOverlayRestrictedToken: THandle;
var Original: THandle; I: Integer;
  Sids: array[0..6] of TWellKnownSidLocal;
  Disabled: array[0..6] of TSidAttributesLocal;
  LabelBuffer: TTokenLabelBufferLocal;
begin
  Result := 0; Original := 0;
  FillChar(Sids, SizeOf(Sids), 0); FillChar(Disabled, SizeOf(Disabled), 0);
  FillChar(LabelBuffer, SizeOf(LabelBuffer), 0);
  try
    try
      { CreateRestrictedToken preserves the existing token HANDLE's rights.
        Keep the rights needed by SetTokenInformation and CreateProcessAsUser. }
      Require(TOpenProcessTokenProc(DecodeApiPointer(SlotOpenToken))(
        THandle(NativeInt(-1)),
        TokenQueryAccess or TokenDuplicateAccess or TokenAssignPrimaryAccess or
        TokenAdjustDefaultAccess, Original), CozyText_Handoff_Restricted_OVERLAY_SOURCE_TOKEN_OPEN_FAILED_7e48ef01);
      RequireInteractiveUser(Original);
      Require(QueryIntegrity(Original) >= MediumIntegrityRID,
        CozyText_Handoff_Restricted_OVERLAY_SOURCE_INTEGRITY_UNSUPPORTED_a8f84778);
      for I := 0 to High(Sids) do
      begin
        Sids[I].Revision := 1; Sids[I].Count := 2; Sids[I].Authority[5] := 5;
        Sids[I].SubAuthority[0] := 32; Sids[I].SubAuthority[1] := DeniedBuiltinRIDs[I];
        Disabled[I].Sid := @Sids[I];
      end;
      Require(TCreateRestrictedTokenProc(DecodeApiPointer(SlotCreateRestricted))(
        Original, DisableMaximumPrivileges or LuaToken, Length(Disabled), @Disabled[0],
        0, nil, 0, nil, Result), CozyText_Handoff_Restricted_OVERLAY_RESTRICTED_TOKEN_CREATE_FAILED_eb9f1925);
      LabelBuffer.Sid.Revision := 1; LabelBuffer.Sid.Count := 1;
      LabelBuffer.Sid.Authority[5] := 16;
      LabelBuffer.Sid.SubAuthority[0] := MediumIntegrityRID;
      LabelBuffer.LabelInfo.Sid := @LabelBuffer.Sid;
      LabelBuffer.LabelInfo.Attributes := GroupIntegrity;
      Require(TSetTokenInformationProc(DecodeApiPointer(SlotSetToken))(
        Result, TokenIntegrityKind, @LabelBuffer, SizeOf(TSidAttributesLocal) + 12),
        CozyText_Handoff_Restricted_OVERLAY_TOKEN_INTEGRITY_CAP_FAILED_fcfe9c04);
      RequireRestrictedToken(Result);
    except
      CloseToken(Result);
      raise;
    end;
  finally
    CloseToken(Original);
  end;
end;

procedure RequireOverlayRestrictedProcess(Process: THandle);
var Token: THandle;
begin
  Token := 0;
  try
    Require(TOpenProcessTokenProc(DecodeApiPointer(SlotOpenToken))(
      Process, TokenQueryAccess, Token), CozyText_Handoff_Restricted_OVERLAY_CHILD_TOKEN_OPEN_FAILED_a5f6a97d);
    RequireRestrictedToken(Token);
  finally CloseToken(Token); end;
end;

procedure CreateOverlayRestrictedProcess(const Executable: string;
  var CommandLine: string; const Environment, WorkingDirectory: string;
  var Startup: TStartupInfo; var Process: TProcessInformation);
var Token: THandle;
begin
  Require((Process.hProcess = 0) and (Process.hThread = 0),
    CozyText_Handoff_Restricted_OVERLAY_CHILD_PROCESS_SLOT_NOT_EMPTY_2feb45fd);
  Require((SizeOf(Pointer) = 8) and (SizeOf(TSidAttributesLocal) = 16) and
    (SizeOf(TPrivilegeLocal) = 12), CozyText_Handoff_Restricted_OVERLAY_TOKEN_ABI_UNSUPPORTED_73e1f72d);
  Token := CreateOverlayRestrictedToken;
  try
    UniqueString(CommandLine);
    Require(TCreateProcessAsUserProc(DecodeApiPointer(SlotCreateProcess))(Token,
      PWideChar(Executable), PWideChar(CommandLine), nil, nil, True,
      ExtendedStartupFlag or UnicodeEnvironment or CREATE_SUSPENDED,
      PWideChar(Environment), PWideChar(WorkingDirectory), Startup, Process),
      CozyText_Handoff_Restricted_OVERLAY_RESTRICTED_PROCESS_CREATE_FAILED_2a7f139c);
    { Before a single child instruction or grant is released, verify the
      actual kernel process token rather than trusting the requested token. }
    RequireOverlayRestrictedProcess(Process.hProcess);
    { Creation is complete. Retire the parent-held token modification rights
      before the child executes; the child owns its primary token independently. }
    CloseToken(Token);
    Require(TResumeThreadProc(DecodeApiPointer(SlotResume))(Process.hThread) = 1,
      CozyText_Handoff_Restricted_OVERLAY_RESTRICTED_PROCESS_RESUME_FAILED_78ff7ef9);
  finally CloseToken(Token); end;
end;

initialization
  BindApiPointer(SlotOpenToken, RequireProcAddressHash64(CozyText_Handoff_Restricted_advapi32_dll_08b0e050, HASH_OpenProcessToken));
  BindApiPointer(SlotCreateRestricted, RequireProcAddressHash64(CozyText_Handoff_Restricted_advapi32_dll_08b0e050, HASH_CreateRestrictedToken));
  BindApiPointer(SlotGetToken, RequireProcAddressHash64(CozyText_Handoff_Restricted_advapi32_dll_08b0e050, HASH_GetTokenInformation));
  BindApiPointer(SlotSetToken, RequireProcAddressHash64(CozyText_Handoff_Restricted_advapi32_dll_08b0e050, HASH_SetTokenInformation));
  BindApiPointer(SlotCreateProcess, RequireProcAddressHash64(CozyText_Handoff_Restricted_advapi32_dll_08b0e050, HASH_CreateProcessAsUserW));
  BindApiPointer(SlotResume, RequireProcAddressHash64(CozyText_Handoff_Restricted_kernel32_dll_bb8acc01, HASH_ResumeThread));
  BindApiPointer(SlotClose, RequireProcAddressHash64(CozyText_Handoff_Restricted_kernel32_dll_bb8acc01, HASH_CloseHandle));
  BindApiPointer(SlotLookupPrivilege, RequireProcAddressHash64(CozyText_Handoff_Restricted_advapi32_dll_08b0e050, HASH_LookupPrivilegeValueW));
end.
