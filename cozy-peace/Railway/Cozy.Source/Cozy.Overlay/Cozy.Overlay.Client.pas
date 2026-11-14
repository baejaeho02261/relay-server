unit Cozy.Overlay.Client;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Overlay,
 Cozy.OwnedRuntime, Winapi.Windows, System.SysUtils, Cozy.Lifetime, Cozy.Lifecycle, System.JSON, Cozy.Security,
  Cozy.Server.Profile, Cozy.Transport, Cozy.Bootstrap,
  Cozy.Integrity, Cozy.CodeIntegrity, Cozy.ModuleInventory, Cozy.Measurement, Cozy.ServerAuthority,
  Cozy.NHW.Guard, Cozy.NHW.TpmQuote;
type
  TOverlayDownloadFailureKind = (odfTimeout, odfTicketExpired);
  EOverlayDownloadFailure = class(EBootstrap)
  private
    FKind: TOverlayDownloadFailureKind;
  public
    constructor Create(Kind: TOverlayDownloadFailureKind); reintroduce;
    property Kind: TOverlayDownloadFailureKind read FKind;
    { Pure deadline calculation: it grants no session or download authority. }
    class function RequestDeadline(StartedTick, NowTick: UInt64;
      ExpiresAt, NowUTC: Int64): UInt64; static;
  end;
  TOverlayClient = class
  private
    FNHWAuthority: ICozyAuthorityExtension;
    FNHWQuoter: ICozyTpmQuoter;
    FRuntimeGraph: TCozyOwnedRuntimeGraph;
    FOwnImage: TImageIntegrity;
    FLifecycle: TLifecycleReporter;
    FGate: TGameCallGate;
    FLock: TObject;
    FClosed: Boolean;
    FCloseDeadline, FShutdownJoinElapsed: UInt64;
    FShutdownJoinMissed, FShutdownDiagnostics: Boolean;
    FTransport: TConnectTransport;
    FTransportProfile: TConnectServerProfile;
    FSession: TBootstrapSession;
    FParentSessionID: string;
    FStartupSecurity: TDeviceSecurity; { borrowed; owned by handoff Context }
    FStartupTick, FLeaseDeadlineTick, FLeaseRequestTick: UInt64;
    FSnapshotDeadlineTick: UInt64;
    FLeaseSnapshotLimited: Boolean;
    FLastSnapshotExpiresAt: Int64;
    FStartupSequence, FStartupPhaseCode: Cardinal;
    FLastLeaseServerTime, FLastLeaseDuration: Int64;
    FStartupDone: Boolean;
    FTransferConfirmed, FCapturePrivacy: Boolean;
    FProductID: string;
    FProductScopeKnown: Boolean;
    FStartSequence: Integer;
    function GetProductCard: Integer;
    procedure ReadProductScope(Reply: TJSONObject);
    function OwnRuntime(Security: TDeviceSecurity;
      CodeIntegrity: TCodeIntegrity): ICozyRuntimeMeasurement;
    procedure StartupPhaseCore(const Phase: string;
      const FailureStage: string = ''; FailureCode: Integer = 0);
    function GetLeaseDeadlineTick: UInt64;
    function GetLeaseRequestTick: UInt64;
    function GetSnapshotDeadlineTick: UInt64;
    function GetLeaseSnapshotLimited: Boolean;
    function Post(const Action: string; Body: TJSONObject;
      RequestDeadlineTick: UInt64 = 0): TJSONObject;
    function GetSession: TBootstrapSession;
    function GetTransferConfirmed: Boolean;
    function GetCapturePrivacy: Boolean;
    function ChunkCore(const Flow: TBootstrapFlow; Offset: Int64;
      RequestDeadlineTick: UInt64): TBytes;
    function ClaimCore(const OverlayID, Ticket, Canonical: string;
      Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity): TBootstrapSession;
    procedure ReportIntegrityCore(Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
      const Image: TImageDigest; IncludeModules: Boolean;
      const Cancelled: TModuleInventoryCancelled = nil;
      FailureStatus: TMeasurementStatus = msMeasured;
      OwnImage: TImageIntegrity = nil;
      const MaintainLease: TProc<Boolean> = nil);
    function VerifyCore(Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
      const Image: TImageDigest;
      const Cancelled: TModuleInventoryCancelled = nil): Int64;
    procedure CloseCore;
    procedure CommitTransferCore(Security: TDeviceSecurity;
      const ParentSessionID, ParentSessionToken, OverlayID: string);
    function AbortChildCore(Security: TDeviceSecurity; const ParentSessionID,
      ParentSessionToken, OverlayID, PrepareRequestID: string; SecurityStop: Boolean): Boolean;
    function GetSessionCore: TBootstrapSession;
    function GetTransferConfirmedCore: Boolean;
  public
    procedure AttachNHW(Guard: TCozyNHWGuard);
    procedure FlushNHWReports(TimeoutMS: Cardinal = 3500);
    constructor Create(Profile: TConnectServerProfile);
    destructor Destroy; override;
    function Chunk(const Flow: TBootstrapFlow; Offset: Int64;
      RequestDeadlineTick: UInt64 = 0): TBytes;
    function Claim(const OverlayID, Ticket, Canonical: string;
      Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity): TBootstrapSession;
    procedure ReportIntegrity(Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
      const Image: TImageDigest; IncludeModules: Boolean;
      const Cancelled: TModuleInventoryCancelled = nil;
      FailureStatus: TMeasurementStatus = msMeasured;
      OwnImage: TImageIntegrity = nil;
      const MaintainLease: TProc<Boolean> = nil);
    function Verify(Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
      const Image: TImageDigest;
      const Cancelled: TModuleInventoryCancelled = nil): Int64;
    { Call on the existing serialized worker after a verified live lease.
      Retain borrowed contexts until return; cancellation must not reenter/free. }
    function InvokeServerPolicy(Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
      const Image: TImageDigest; FunctionID: Word; const Args: array of Integer;
      const Cancelled: TModuleInventoryCancelled = nil): Integer;
    { Serialized worker only. Returns the monotonic deadline of this exact
      product authorization; never changes the ordinary session lease. }
    function AuthorizeProductStart(Security: TDeviceSecurity; Card: Integer;
      const Cancelled: TModuleInventoryCancelled = nil): UInt64;
    property ProductCard: Integer read GetProductCard;
    procedure Close;
    procedure CancelPending;
    procedure StartupPhase(const Phase: string);
    procedure StartupFailure(const Stage: string; NativeCode: Integer);
    property LeaseDeadlineTick: UInt64 read GetLeaseDeadlineTick;
    property LeaseRequestTick: UInt64 read GetLeaseRequestTick;
    property SnapshotDeadlineTick: UInt64 read GetSnapshotDeadlineTick;
    property LeaseSnapshotLimited: Boolean read GetLeaseSnapshotLimited;
    procedure PrepareLifecycle(DeadlineTick: UInt64);
    class procedure CloseSessionSnapshot(Profile: TConnectServerProfile;
      const Session: TBootstrapSession; DeadlineTick, JoinElapsedMs: UInt64); static;
    { Owner-only after worker join, before releasing the borrowed image. }
    procedure RetireOwnImageForShutdown;
    procedure ShutdownClose(DeadlineTick: UInt64; JoinElapsedMs: UInt64 = 0;
      JoinBudgetMissed: Boolean = False);
    { Authoritative cleanup of exactly this parent's child/preparation. A
      TRANSFERRED receipt preserves the already-authorized O execution. }
    function AbortChild(Security: TDeviceSecurity; const ParentSessionID,
      ParentSessionToken, OverlayID, PrepareRequestID: string;
      SecurityStop: Boolean = False): Boolean;
    procedure CommitTransfer(Security: TDeviceSecurity;
      const ParentSessionID, ParentSessionToken, OverlayID: string);
    property Session: TBootstrapSession read GetSession;
    property TransferConfirmed: Boolean read GetTransferConfirmed;
    property CapturePrivacy: Boolean read GetCapturePrivacy;
    property Lifecycle: TLifecycleReporter read FLifecycle;
  end;
function LaunchOverlay(Profile: TConnectServerProfile; Security: TDeviceSecurity;
  PrepareData: TJSONObject; const ParentSHA512, ParentSessionID: string;
  RestrictedPrivileges: Boolean = False;
  const MaintainParent: TProc<Boolean> = nil;
  const Progress: TProc<Integer> = nil): Boolean;
implementation
uses Cozy.Clock, Cozy.Overlay.State, System.Classes, System.NetEncoding, System.RegularExpressions,
  System.Generics.Collections, Cozy.Hashes, Cozy.Handoff,
  Cozy.NHW.Authority, Cozy.NHW.ResponsePath.Dispatch, Cozy.ProtocolJson, Cozy.ServerOperations, Cozy.OwnMeasurement, Cozy.DeviceIdentity, Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer;
{ Private API pointers: initialized before application code starts. }
var

  ApiSlot_CloseHandle: TEncodedApiPointer;
  ApiSlot_CreateFileW: TEncodedApiPointer;
  ApiSlot_GetFileInformationByHandle: TEncodedApiPointer;
  ApiSlot_GetFileType: TEncodedApiPointer;
  ApiSlot_WriteFile: TEncodedApiPointer;
  ApiSlot_FlushFileBuffers: TEncodedApiPointer;


type
  TDirectoryPins = class
  private
    FHandles: TList<THandle>;
  public
    constructor Create(const Directory: string);
    destructor Destroy; override;
  end;
  TLauncherDispositionInfo = record
    DeleteFile: Byte;
  end;

const
  { Windows SDK FILE_FLAG_OPEN_REPARSE_POINT; preserve no-follow validation. }
  OpenReparsePointFlag: DWORD = $00200000;
  DownloadDeadlineMS = 300000;
  FileDispositionInfoClass = 4;
  DeleteAccess = $00010000;

type
  TResolved_LauncherSetFileInformationByHandle = function(Handle: THandle;
  InformationClass: Integer; Information: Pointer; InformationSize: DWORD): BOOL; stdcall;
var
  ApiSlot_LauncherSetFileInformationByHandle: TEncodedApiPointer;

{ POINTER WRAPPERS 1 BEGIN }

function CloseHandle(Handle: THandle): BOOL; stdcall;
var
  ApiTarget: TApiCloseHandle;
begin
  ApiTarget := TApiCloseHandle(DecodeApiPointer(ApiSlot_CloseHandle));
  Result := ApiTarget(Handle);
end;

function CreateFileW(FileName: PWideChar; DesiredAccess, ShareMode: DWORD;
    Attributes: PSecurityAttributes; CreationDisposition, FlagsAndAttributes: DWORD;
    TemplateFile: THandle): THandle; stdcall;
var
  ApiTarget: TApiCreateFileW;
begin
  ApiTarget := TApiCreateFileW(DecodeApiPointer(ApiSlot_CreateFileW));
  Result := ApiTarget(FileName, DesiredAccess, ShareMode, Attributes, CreationDisposition, FlagsAndAttributes, TemplateFile);
end;

function GetFileInformationByHandle(Handle: THandle;
    var Information: TByHandleFileInformation): BOOL; stdcall;
var
  ApiTarget: TApiGetFileInformationByHandle;
begin
  ApiTarget := TApiGetFileInformationByHandle(DecodeApiPointer(ApiSlot_GetFileInformationByHandle));
  Result := ApiTarget(Handle, Information);
end;

function GetFileType(Handle: THandle): DWORD; stdcall;
var
  ApiTarget: TApiGetFileType;
begin
  ApiTarget := TApiGetFileType(DecodeApiPointer(ApiSlot_GetFileType));
  Result := ApiTarget(Handle);
end;

function WriteFile(Handle: THandle; const Buffer; Count: DWORD; var BytesWritten: DWORD;
    Overlapped: POverlapped): BOOL; stdcall;
var
  ApiTarget: TApiWriteFile;
begin
  ApiTarget := TApiWriteFile(DecodeApiPointer(ApiSlot_WriteFile));
  Result := ApiTarget(Handle, Buffer, Count, BytesWritten, Overlapped);
end;

function FlushFileBuffers(Handle: THandle): BOOL; stdcall;
var
  ApiTarget: TApiFlushFileBuffers;
begin
  ApiTarget := TApiFlushFileBuffers(DecodeApiPointer(ApiSlot_FlushFileBuffers));
  Result := ApiTarget(Handle);
end;

function LauncherSetFileInformationByHandle(Handle: THandle;
  InformationClass: Integer; Information: Pointer; InformationSize: DWORD): BOOL; stdcall;
var
  ApiTarget: TResolved_LauncherSetFileInformationByHandle;
begin
  ApiTarget := TResolved_LauncherSetFileInformationByHandle(DecodeApiPointer(ApiSlot_LauncherSetFileInformationByHandle));
  Result := ApiTarget(Handle, InformationClass, Information, InformationSize);
end;
{ POINTER WRAPPERS 1 END }

constructor EOverlayDownloadFailure.Create(Kind: TOverlayDownloadFailureKind);
begin
  FKind := Kind;
  case Kind of
    odfTimeout: inherited Create(CozyText_Overlay_Client_OVERLAY_DOWNLOAD_TIMEOUT_b6138b31);
    odfTicketExpired: inherited Create(CozyText_Overlay_Client_OVERLAY_DOWNLOAD_TICKET_EXPIRED_77f45a01);
  end;
end;

class function EOverlayDownloadFailure.RequestDeadline(StartedTick, NowTick: UInt64;
  ExpiresAt, NowUTC: Int64): UInt64;
var Remaining: UInt64;
begin
  { Neither retries nor parent renewal may restart the immutable 300 s budget. }
  if (NowTick < StartedTick) or (NowTick - StartedTick >= DownloadDeadlineMS) then
    raise EOverlayDownloadFailure.Create(odfTimeout);
  if (NowUTC < 0) or (ExpiresAt <= NowUTC) then
    raise EOverlayDownloadFailure.Create(odfTicketExpired);
  Remaining := DownloadDeadlineMS - (NowTick - StartedTick);
  if UInt64(ExpiresAt - NowUTC) < Remaining then Remaining := UInt64(ExpiresAt - NowUTC);
  if Remaining > High(UInt64) - NowTick then
    raise EOverlayDownloadFailure.Create(odfTimeout);
  Result := NowTick + Remaining;
end;

procedure Fail;
begin
  raise EBootstrap.Create(CozyText_Overlay_Client_The_launcher_could_not_complete_securely_3083ae57);
end;

procedure CheckRegularFile(Handle: THandle; out Info: TByHandleFileInformation);
begin
  if not GetFileInformationByHandle(Handle, Info) or
    ((Info.dwFileAttributes and (FILE_ATTRIBUTE_DIRECTORY or
      FILE_ATTRIBUTE_REPARSE_POINT)) <> 0) or
    (GetFileType(Handle) <> FILE_TYPE_DISK) or
    (Info.nNumberOfLinks <> 1) or
    ((Info.nFileIndexHigh = 0) and (Info.nFileIndexLow = 0)) then Fail;
end;

function FileSize(const Info: TByHandleFileInformation): UInt64;
begin
  Result := (UInt64(Info.nFileSizeHigh) shl 32) or Info.nFileSizeLow;
end;

constructor TDirectoryPins.Create(const Directory: string);
var Full, Part, Component: string; I, StartAt: Integer;
  Handle: THandle; Info: TByHandleFileInformation;
  procedure Pin(const Path: string);
  begin
    Handle := CreateFileW(PWideChar(Path), FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ, nil, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS or OpenReparsePointFlag, 0);
    if Handle = INVALID_HANDLE_VALUE then Fail;
    try
      if not GetFileInformationByHandle(Handle, Info) or
        ((Info.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) = 0) or
        ((Info.dwFileAttributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0) then Fail;
      FHandles.Add(Handle);
      Handle := INVALID_HANDLE_VALUE;
    finally
      if Handle <> INVALID_HANDLE_VALUE then CloseHandle(Handle);
    end;
  end;
begin
  inherited Create;
  FHandles := TList<THandle>.Create;
  Full := Directory;
  while (Length(Full) > 3) and (Full[Length(Full)] = '\') do
    Delete(Full, Length(Full), 1);
  { Restrict execution to a canonical local drive path. This avoids UNC,
    device namespaces, stream names and ambiguous dot/space components. }
  if (Length(Full) < 3) or not CharInSet(Full[1], ['A'..'Z','a'..'z']) or
    (Copy(Full, 2, 2) <> CozyText_Overlay_Client_Text_f769b8c1) or (Pos('/', Full) > 0) or
    (Pos(':', Copy(Full, 3, MaxInt)) > 0) then Fail;
  Part := Copy(Full, 1, 3);
  Pin(Part);
  if Length(Full) = 3 then Exit;
  StartAt := 4;
  for I := 4 to Length(Full) + 1 do
    if (I > Length(Full)) or (Full[I] = '\') then
    begin
      Component := Copy(Full, StartAt, I - StartAt);
      if (Component = '') or (Component = '.') or (Component = CozyText_Overlay_Client_Text_73f7298d) or
        CharInSet(Component[Length(Component)], [' ', '.']) then Fail;
      Part := IncludeTrailingPathDelimiter(Part) + Component;
      Pin(Part);
      StartAt := I + 1;
    end;
end;

destructor TDirectoryPins.Destroy;
var Handle: THandle;
begin
  if FHandles <> nil then
  begin
    for Handle in FHandles do CloseHandle(Handle);
    FHandles.Free;
  end;
  inherited;
end;

procedure InvalidResponse; forward;
procedure RequireOverlayDocument(const Name: string; Value: TJSONObject);
begin
  try ValidateProtocolDocument(Name, Value);
  except on E: EConvertError do InvalidResponse; end;
end;
function ParseHex(Obj: TJSONObject; const Name: string; Digits: Integer): string;
var C: Char;
begin
  Result := BootstrapString(Obj, Name, Digits);
  if Length(Result) <> Digits then InvalidResponse;
  for C in Result do
    if not CharInSet(C, ['0'..'9', 'a'..'f']) then InvalidResponse;
end;

function ParseRelease(Obj: TJSONObject): TBootstrapRelease;
begin
  RequireOverlayDocument(CozyText_Overlay_Client_overlayRelease_7195dcd7, Obj);
  BootstrapValidateObject(Obj, CozyText_Overlay_Client_id_version_hashVersion_sha512_crc64_xxh3_128_bla_b18c2bc9, 13);
  if BootstrapInteger(Obj, CozyText_Overlay_Client_hashVersion_45a60e5e) <> 3 then InvalidResponse;
  Result.ID := BootstrapString(Obj, CozyText_Overlay_Client_id_4c756c2e, 128);
  Result.Version := BootstrapString(Obj, CozyText_Overlay_Client_version_2c126698, 80);
  Result.SHA512 := BootstrapString(Obj, CozyText_Overlay_Client_sha512_1bcadd0f, 128);
  BootstrapCheckSHA512(Result.SHA512);
  Result.CRC64 := BootstrapString(Obj, CozyText_Overlay_Client_crc64_f1092498, 16);
  BootstrapCheckCRC64(Result.CRC64);
  Result.CodeSHA512 := BootstrapString(Obj, CozyText_Overlay_Client_codeSha512_ec69005b, 128);
  BootstrapCheckSHA512(Result.CodeSHA512);
  Result.XXH3_128 := ParseHex(Obj, CozyText_Overlay_Client_xxh3_128_96b4d0d8, 32);
  Result.Blake3 := ParseHex(Obj, CozyText_Overlay_Client_blake3_904ab45e, 64);
  Result.CodeXXH3_128 := ParseHex(Obj, CozyText_Overlay_Client_codeXxh3_128_e16e3fad, 32);
  Result.CodeBlake3 := ParseHex(Obj, CozyText_Overlay_Client_codeBlake3_c0771ac7, 64);
  Result.CodeCRC64 := BootstrapString(Obj, CozyText_Overlay_Client_codeCrc64_c91b93a5, 16);
  BootstrapCheckCRC64(Result.CodeCRC64);
  if BootstrapString(Obj, CozyText_Overlay_Client_codeAlgorithm_32096cfe, 32) <> CozyText_Overlay_Client_PE64_CODE_V1_0a9f535a then InvalidResponse;
  Result.Size := BootstrapInteger(Obj, CozyText_Overlay_Client_size_06a3246c);
  if (Result.Size < 1) or (Result.Size > 64 * 1024 * 1024) then InvalidResponse;
end;

function RequiredObject(Obj: TJSONObject; const Name: string): TJSONObject;
var V: TJSONValue;
begin
  V := Obj.GetValue(Name);
  if not (V is TJSONObject) then InvalidResponse;
  Result := TJSONObject(V);
end;

function SameFileIdentity(const A, B: TByHandleFileInformation): Boolean;
begin
  Result := (A.dwVolumeSerialNumber = B.dwVolumeSerialNumber) and
    (A.nFileIndexHigh = B.nFileIndexHigh) and
    (A.nFileIndexLow = B.nFileIndexLow);
end;

procedure DeleteCreatedBinary(const BinaryPath, SHA512: string;
  const CreatedInfo: TByHandleFileInformation);
var Handle: THandle; Info: TByHandleFileInformation;
  DeleteInfo: TLauncherDispositionInfo;
begin
  if (BinaryPath = '') or ((CreatedInfo.nFileIndexHigh = 0) and
    (CreatedInfo.nFileIndexLow = 0)) then Exit;
  Handle := CreateFileW(PWideChar(BinaryPath), GENERIC_READ or DeleteAccess,
    FILE_SHARE_READ, nil, OPEN_EXISTING,
    OpenReparsePointFlag or FILE_FLAG_SEQUENTIAL_SCAN, 0);
  if Handle = INVALID_HANDLE_VALUE then Exit;
  try
    CheckRegularFile(Handle, Info);
    if not SameFileIdentity(Info, CreatedInfo) or
      (HashHandleSHA512(Handle) <> SHA512) then Fail;
    { Ordinary deletion after our exact child has terminated. Never delete
      a colliding or substituted pathname, even if its contents match. }
    DeleteInfo.DeleteFile := 1;
    if not LauncherSetFileInformationByHandle(Handle, FileDispositionInfoClass,
      @DeleteInfo, SizeOf(DeleteInfo)) then Fail;
  finally
    CloseHandle(Handle);
  end;
end;

function DownloadVerifiedBinary(Client: TOverlayClient;
  const Flow: TBootstrapFlow; const BinaryPath: string;
  out CreatedInfo: TByHandleFileInformation;
  const MaintainParent: TProc<Boolean>; const Progress: TProc<Integer>): THandle;
var Handle: THandle; Info: TByHandleFileInformation;
  Bytes, Download: TBytes; Offset: Int64; Written, Part: DWORD;
  Started, RequestDeadlineTick: UInt64;
  DeleteInfo: TLauncherDispositionInfo; Created, Succeeded: Boolean;
  Digest: TImageDigest;
begin
  Result := INVALID_HANDLE_VALUE;
  Handle := INVALID_HANDLE_VALUE;
  Created := False;
  Succeeded := False;
  FillChar(CreatedInfo, SizeOf(CreatedInfo), 0);
  Started := CozyTick;
  try
    { Receive a bounded image into process memory. No partially downloaded
      plaintext temporary file or persistent download ticket is created. }
    if (Flow.Release.Size < 1) or (Flow.Release.Size > 64 * 1024 * 1024) then Fail;
    SetLength(Download, Integer(Flow.Release.Size));
    Offset := 0;
    while Offset < Flow.Release.Size do
    begin
      if Assigned(MaintainParent) then MaintainParent(False);
      RequestDeadlineTick := EOverlayDownloadFailure.RequestDeadline(Started,
        CozyTick, Flow.ExpiresAt, BootstrapUTCNowMS);
      try
        Bytes := Client.Chunk(Flow, Offset, RequestDeadlineTick);
      except
        on E: EConnectTransport do
        begin
          { Preserve authentication/cancellation errors. Only an elapsed
            boundary classifies a transport timeout as download exhaustion. }
          if (E.Code = CozyText_Overlay_Client_CONNECT_TIMEOUT_4fb4b726) or
            (E.Code = CozyText_Overlay_Client_CONNECT_UNAVAILABLE_2477720e) or
            (E.Code = CozyText_Overlay_Client_CONNECT_SEND_FAILED_8a598241) or
            (E.Code = CozyText_Overlay_Client_CONNECT_RECEIVE_FAILED_703bdde2) or
            (E.Code = CozyText_Overlay_Client_NETWORK_UNAVAILABLE_f4bc46ee) then
            EOverlayDownloadFailure.RequestDeadline(Started, CozyTick,
              Flow.ExpiresAt, BootstrapUTCNowMS);
          raise;
        end;
      end;
      EOverlayDownloadFailure.RequestDeadline(Started, CozyTick,
        Flow.ExpiresAt, BootstrapUTCNowMS);
      if (Length(Bytes) < 1) or
        (Int64(Length(Bytes)) > Flow.Release.Size - Offset) then Fail;
      Move(Bytes[0], Download[Integer(Offset)], Length(Bytes));
      Inc(Offset, Length(Bytes));
      WipeBytes(Bytes);
      if Assigned(Progress) then Progress(60 + Integer((Offset * 28) div Flow.Release.Size));
    end;
    EOverlayDownloadFailure.RequestDeadline(Started, CozyTick,
      Flow.ExpiresAt, BootstrapUTCNowMS);
    if (IntegritySHA512Bytes(Download) <> Flow.Release.SHA512) or
      (IntegrityCRC64Bytes(Download) <> Flow.Release.CRC64) or
      (XXHash3_128Bytes(Download) <> Flow.Release.XXH3_128) or
      (Blake3Bytes(Download) <> Flow.Release.Blake3) then Fail;
    { Windows needs an ordinary PE file for CreateProcess. Write only the
      authenticated complete image under its final random name; never replace
      an existing pathname and keep exact identity checks throughout. }
    Handle := CreateFileW(PWideChar(BinaryPath), GENERIC_READ or GENERIC_WRITE or
      DeleteAccess, FILE_SHARE_READ, nil, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL or OpenReparsePointFlag or
      FILE_FLAG_SEQUENTIAL_SCAN, 0);
    if Handle = INVALID_HANDLE_VALUE then Fail;
    Created := True;
    CheckRegularFile(Handle, Info);
    Offset := 0;
    while Offset < Length(Download) do
    begin
      Part := DWORD(Length(Download) - Offset);
      if Part > 1048576 then Part := 1048576;
      if not WriteFile(Handle, Download[Integer(Offset)], Part, Written, nil) or
        (Written <> Part) then Fail;
      Inc(Offset, Written);
    end;
    WipeBytes(Download);
    if not FlushFileBuffers(Handle) then Fail;
    CheckRegularFile(Handle, CreatedInfo);
    Digest := IntegrityHashHandle(Handle);
    if (FileSize(CreatedInfo) <> UInt64(Flow.Release.Size)) or
      (Digest.SHA512 <> Flow.Release.SHA512) or
      (Digest.CRC64 <> Flow.Release.CRC64) or
      (Digest.XXH3_128 <> Flow.Release.XXH3_128) or
      (Digest.Blake3 <> Flow.Release.Blake3) then Fail;
    CloseHandle(Handle);
    Handle := INVALID_HANDLE_VALUE;
    { CloseCore the writer before Windows maps the image, then reopen/pin and
      compare the exact file identity plus both authenticated digests. }
    Result := CreateFileW(PWideChar(BinaryPath), GENERIC_READ, FILE_SHARE_READ,
      nil, OPEN_EXISTING, OpenReparsePointFlag or
      FILE_FLAG_SEQUENTIAL_SCAN, 0);
    if Result = INVALID_HANDLE_VALUE then Fail;
    CheckRegularFile(Result, Info);
    Digest := IntegrityHashHandle(Result);
    if not SameFileIdentity(Info, CreatedInfo) or
      (FileSize(Info) <> UInt64(Flow.Release.Size)) or
      (Digest.SHA512 <> Flow.Release.SHA512) or
      (Digest.CRC64 <> Flow.Release.CRC64) or
      (Digest.XXH3_128 <> Flow.Release.XXH3_128) or
      (Digest.Blake3 <> Flow.Release.Blake3) then Fail;
    EOverlayDownloadFailure.RequestDeadline(Started, CozyTick,
      Flow.ExpiresAt, BootstrapUTCNowMS);
    Succeeded := True;
  finally
    WipeBytes(Bytes);
    WipeBytes(Download);
    if not Succeeded and (Result <> INVALID_HANDLE_VALUE) then
    begin
      CloseHandle(Result);
      Result := INVALID_HANDLE_VALUE;
    end;
    if Handle <> INVALID_HANDLE_VALUE then
    begin
      { Delete only the exact handle this CREATE_NEW operation created. }
      DeleteInfo.DeleteFile := 1;
      LauncherSetFileInformationByHandle(Handle, FileDispositionInfoClass,
        @DeleteInfo, SizeOf(DeleteInfo));
      CloseHandle(Handle);
    end
    else if Created and not Succeeded then
    begin
      try
        DeleteCreatedBinary(BinaryPath, Flow.Release.SHA512, CreatedInfo);
      except
        { Cleanup failure cannot authorize execution. }
      end;
    end;
  end;
end;


procedure InvalidResponse;
begin
  raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_RESPONSE_INVALID_18808964);
end;
function TOverlayClient.OwnRuntime(Security: TDeviceSecurity;
  CodeIntegrity: TCodeIntegrity): ICozyRuntimeMeasurement;
begin
  if FRuntimeGraph = nil then raise ECozyRuntimeGraph.Create(CozyText_Overlay_Client_RUNTIME_GRAPH_REQUIRED_0882fe99);
  { Registration is explicit and rejects replacement of a live binding.
    All captures occur inside this client's existing lifetime gate. }
  FRuntimeGraph.BindDependencies(Security, FOwnImage, CodeIntegrity);
  Result := FRuntimeGraph.Measurement(
    function: TCozyRuntimeBindings
    begin
      Result := CozyRuntimeBindings(Self, FGate, FTransport, Security,
        FOwnImage, CodeIntegrity);
    end);
end;

procedure TOverlayClient.FlushNHWReports(TimeoutMS: Cardinal);
begin
  { Best effort on independent report connections. A network failure never
    prevents exact-session cleanup and does not claim report delivery. }
  if TimeoutMS > 3500 then TimeoutMS := 3500;
  try
    if FNHWAuthority <> nil then FNHWAuthority.FlushSecurityReports(TimeoutMS);
  except
    { Session revocation and local disposal must still run. }
  end;
end;

procedure TOverlayClient.AttachNHW(Guard: TCozyNHWGuard);
begin
  if (Guard = nil) or (FNHWAuthority <> nil) then
    raise EInvalidOpException.Create(CozyText_Overlay_Client_NHW_attachment_is_not_available_1b675db4);
  FNHWAuthority := TCozyNHWAuthority.Create(
    function(out State: TCozyNHWKernelState): Boolean
    begin Result := Guard.TryReadKernelState(State); end,
    function(Channel: TResponsePathChannel; out State: TCozyNHWKernelState): Boolean
    begin Result := Guard.TryReadPathState(Channel, State); end,
    procedure begin Guard.ApplyAuthenticatedServerStop; end, Guard);
  FNHWAuthority.SetQuoteProvider(FNHWQuoter);
end;

constructor TOverlayClient.Create(Profile: TConnectServerProfile);
begin
  inherited Create;
  FGate := TGameCallGate.Create;
  FLock := TObject.Create;
  FTransportProfile := Profile.Clone;
  FTransport := TConnectTransport.Create(Profile);
  FRuntimeGraph := TCozyOwnedRuntimeGraph.Create(rpOverlayClient, Self, FGate, FTransport);
end;
destructor TOverlayClient.Destroy;
begin
  if FGate <> nil then FGate.CloseAndWait;
  if FRuntimeGraph <> nil then
  begin
    try FRuntimeGraph.Close;
    except { Teardown still releases resources; no closed graph can be evidence. } end;
    FreeAndNil(FRuntimeGraph);
  end;
  FNHWAuthority := nil;
  FNHWQuoter := nil;
  FSession.ClearSecrets;
  FLifecycle.Free;
  FTransportProfile.Free;
  FTransport.Free;
  FLock.Free;
  FGate.Free;
  inherited;
end;
function TOverlayClient.Post(const Action: string; Body: TJSONObject;
  RequestDeadlineTick: UInt64): TJSONObject;
var Reply: TJSONObject; Value: TJSONValue; Attempt, Attempts: Integer;
  Deadline, NowTick: UInt64;
begin
  Body.AddPair(CozyText_Overlay_Client_action_fbec0782, Action);
  Reply := nil;
  Attempts := 1;
  if (Action = CozyText_Overlay_Client_overlayChunk_7527da33) or (Action = CozyText_Overlay_Client_overlayFinish_b7ed5abe) or
    (Action = CozyText_Overlay_Client_overlayClaim_80b4d4b5) or (Action = CozyText_Overlay_Client_overlayCommit_f6c7f768) or
    (Action = CozyText_Overlay_Client_overlayAbort_62344286) or (Action = CozyText_Overlay_Client_overlayClose_3d24a01b) or
    (Action = CozyText_Overlay_Client_overlayStart_27f8a946) then Attempts := 2;
  Deadline := CozyTick + 15000;
  if (RequestDeadlineTick <> 0) and (RequestDeadlineTick < Deadline) then
    Deadline := RequestDeadlineTick;
  if (Action = CozyText_Overlay_Client_overlayClose_3d24a01b) and (FCloseDeadline <> 0) and
    (FCloseDeadline < Deadline) then Deadline := FCloseDeadline;
  for Attempt := 1 to Attempts do
  begin
    NowTick := CozyTick;
    if NowTick >= Deadline then
      raise EConnectTransport.Create(CozyText_Overlay_Client_CONNECT_TIMEOUT_4fb4b726, CozyText_Overlay_Client_Overlay_retry_deadline_expired_967d2f5d);
    try
      { Exact same body/signature: server recovery is idempotent. Never retry
        an authentication rejection, only loss of the bounded transport. }
      Reply := FTransport.PostJSON(CozyText_Overlay_Client_bootstrap_a83d45a9, Body, Cardinal(Deadline - NowTick));
      Break;
    except
      on E: EConnectTransport do
        if (Attempt = Attempts) or
          ((E.Code <> CozyText_Overlay_Client_CONNECT_TIMEOUT_4fb4b726) and (E.Code <> CozyText_Overlay_Client_CONNECT_UNAVAILABLE_2477720e) and
           (E.Code <> CozyText_Overlay_Client_CONNECT_SEND_FAILED_8a598241) and (E.Code <> CozyText_Overlay_Client_CONNECT_RECEIVE_FAILED_703bdde2) and
           (E.Code <> CozyText_Overlay_Client_NETWORK_UNAVAILABLE_f4bc46ee)) then raise;
    end;
  end;
  try
    if Reply = nil then InvalidResponse;
    Value := Reply.GetValue(CozyText_Overlay_Client_ok_bacb1b07);
    if not (Value is TJSONBool) or (Value.Value <> CozyText_Overlay_Client_true_5454fec4) then
      raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_SERVER_REJECTED_bf6c33b9);
    Value := Reply.GetValue(CozyText_Overlay_Client_data_4bb0a19a);
    if not (Value is TJSONObject) then InvalidResponse;
    RequireOverlayDocument(Action, TJSONObject(Value));
    Result := TJSONObject(Value.Clone);
  finally
    Reply.Free;
  end;
end;
function OverlayCanonical(const Kind, ID, ParentSessionID: string;
  Security: TDeviceSecurity; const Release: TBootstrapRelease;
  const Ticket: string; ExpiresAt: Int64; const ParentDeviceID: string = ''): string;
var DeviceID: string;
begin
  DeviceID := ParentDeviceID;
  if DeviceID = '' then DeviceID := Security.DeviceID;
  Result := CozyText_Overlay_Client_GAME_OVERLAY_0f8c6c16 + Kind + CozyText_Overlay_Client_V2_9fd95a5d + #10 + '3' + #10 + ID + #10 +
    ParentSessionID + #10 + DeviceID + #10 + Security.MachineID + #10 +
    Release.ID + #10 + Release.SHA512 + #10 + Release.CRC64 + #10 +
    Release.XXH3_128 + #10 + Release.Blake3 + #10 + Release.CodeSHA512 + #10 +
    Release.CodeCRC64 + #10 + Release.CodeXXH3_128 + #10 + Release.CodeBlake3 + #10 +
    IntToStr(Release.Size) + #10 + IntegritySHA512Text(Ticket) + #10 + IntToStr(ExpiresAt);
end;
function TOverlayClient.AbortChildCore(Security: TDeviceSecurity;
  const ParentSessionID, ParentSessionToken, OverlayID, PrepareRequestID: string;
  SecurityStop: Boolean): Boolean;
var Body, Reply: TJSONObject; Canonical, Scope, Identifier, Status, ReturnedID: string;
  Value: TJSONValue;
begin
  if (Security = nil) or (ParentSessionToken = '') or
    not TRegEx.IsMatch(ParentSessionID, CozyText_Overlay_Client_Pattern_6b1824b5) or
    ((OverlayID = '') = (PrepareRequestID = '')) or
    (SecurityStop and (OverlayID = '')) then InvalidResponse;
  if OverlayID <> '' then
  begin
    if not TRegEx.IsMatch(OverlayID, CozyText_Overlay_Client_Pattern_6b1824b5) then InvalidResponse;
    if SecurityStop then Scope := CozyText_Overlay_Client_COHORT_0dfa039c
    else Scope := CozyText_Overlay_Client_OVERLAY_9bcbd8db;
    Identifier := OverlayID;
  end
  else
  begin
    if not TRegEx.IsMatch(PrepareRequestID, CozyText_Overlay_Client_Pattern_82a741c7) then InvalidResponse;
    Scope := CozyText_Overlay_Client_PREPARE_f3f0e3ad; Identifier := PrepareRequestID;
  end;
  Canonical := CozyText_Overlay_Client_GAME_OVERLAY_ABORT_V3_396e869c + #10 + ParentSessionID + #10 + Scope + #10 + Identifier;
  Body := TJSONObject.Create; Reply := nil;
  try
    Body.AddPair(CozyText_Overlay_Client_handoffVersion_d5aa061e, TJSONNumber.Create(3));
    Body.AddPair(CozyText_Overlay_Client_parentSessionId_c6ae22be, ParentSessionID);
    Body.AddPair(CozyText_Overlay_Client_parentSessionToken_d907fecc, ParentSessionToken);
    if SecurityStop then Body.AddPair(CozyText_Overlay_Client_securityStop_74b7adff, TJSONBool.Create(True));
    if OverlayID <> '' then Body.AddPair(CozyText_Overlay_Client_overlayId_83d35c2a, Identifier)
    else Body.AddPair(CozyText_Overlay_Client_prepareRequestId_38a46704, Identifier);
    Body.AddPair(CozyText_Overlay_Client_signature_3b2323b0, Security.Sign(Canonical));
    if SecurityStop then
      Reply := Post(CozyText_Overlay_Client_overlayAbort_62344286, Body, CozyTick + 4000)
    else
      Reply := Post(CozyText_Overlay_Client_overlayAbort_62344286, Body);
    BootstrapValidateObject(Reply, CozyText_Overlay_Client_handoffVersion_parentSessionId_overlayId_status_0b93775b, 4);
    if (BootstrapInteger(Reply, CozyText_Overlay_Client_handoffVersion_d5aa061e) <> 3) or
      (BootstrapString(Reply, CozyText_Overlay_Client_parentSessionId_c6ae22be, 24) <> ParentSessionID) then InvalidResponse;
    Status := BootstrapString(Reply, CozyText_Overlay_Client_status_2aa55de1, 24);
    Value := Reply.GetValue(CozyText_Overlay_Client_overlayId_83d35c2a);
    if not (Value is TJSONString) then InvalidResponse;
    ReturnedID := Value.Value;
    if (Length(ReturnedID) > 24) or (Pos(#0, ReturnedID) > 0) then InvalidResponse;
    if (Status <> CozyText_Overlay_Client_CLOSED_72591315) and (Status <> CozyText_Overlay_Client_REVOKED_b5ed5567) and (Status <> CozyText_Overlay_Client_EXPIRED_d08cdfc0) and
      (Status <> CozyText_Overlay_Client_TRANSFERRED_6fd5ff48) and (Status <> CozyText_Overlay_Client_NOT_PREPARED_e9f8b31b) then InvalidResponse;
    if Status = CozyText_Overlay_Client_NOT_PREPARED_e9f8b31b then
    begin
      if (Scope <> CozyText_Overlay_Client_PREPARE_f3f0e3ad) or (ReturnedID <> '') then InvalidResponse;
    end
    else if not TRegEx.IsMatch(ReturnedID, CozyText_Overlay_Client_Pattern_6b1824b5) then InvalidResponse;
    if (OverlayID <> '') and (ReturnedID <> OverlayID) then InvalidResponse;
    if SecurityStop and ((Status = CozyText_Overlay_Client_TRANSFERRED_6fd5ff48) or
      (Status = CozyText_Overlay_Client_NOT_PREPARED_e9f8b31b)) then InvalidResponse;
    Result := Status = CozyText_Overlay_Client_TRANSFERRED_6fd5ff48;
  finally
    WipeText(Canonical); WipeText(Identifier);
    Reply.Free; Body.Free;
  end;
end;

procedure TOverlayClient.CommitTransferCore(Security: TDeviceSecurity;
  const ParentSessionID, ParentSessionToken, OverlayID: string);
var Body, Reply: TJSONObject; Canonical, OverlaySessionID: string;
begin
  if (Security = nil) or (ParentSessionToken = '') or
    not TRegEx.IsMatch(ParentSessionID, CozyText_Overlay_Client_Pattern_6b1824b5) or
    not TRegEx.IsMatch(OverlayID, CozyText_Overlay_Client_Pattern_6b1824b5) then InvalidResponse;
  Body := TJSONObject.Create;
  Reply := nil;
  try
    Canonical := CozyText_Overlay_Client_GAME_OVERLAY_TRANSFER_V1_79f7b173 + #10 + ParentSessionID + #10 + OverlayID;
    Body.AddPair(CozyText_Overlay_Client_handoffVersion_d5aa061e, TJSONNumber.Create(1));
    Body.AddPair(CozyText_Overlay_Client_sessionId_3c9f1b20, ParentSessionID);
    Body.AddPair(CozyText_Overlay_Client_sessionToken_1e6f5a77, ParentSessionToken);
    Body.AddPair(CozyText_Overlay_Client_overlayId_83d35c2a, OverlayID);
    Body.AddPair(CozyText_Overlay_Client_signature_3b2323b0, Security.Sign(Canonical));
    Reply := Post(CozyText_Overlay_Client_overlayCommit_f6c7f768, Body);
    BootstrapValidateObject(Reply,
      CozyText_Overlay_Client_handoffVersion_status_parentSessionId_overlayId__f9eebc82, 5);
    OverlaySessionID := BootstrapString(Reply, CozyText_Overlay_Client_overlaySessionId_a6df1716, 24);
    if (BootstrapInteger(Reply, CozyText_Overlay_Client_handoffVersion_d5aa061e) <> 1) or
      (BootstrapString(Reply, CozyText_Overlay_Client_status_2aa55de1, 16) <> CozyText_Overlay_Client_TRANSFERRED_6fd5ff48) or
      (BootstrapString(Reply, CozyText_Overlay_Client_parentSessionId_c6ae22be, 24) <> ParentSessionID) or
      (BootstrapString(Reply, CozyText_Overlay_Client_overlayId_83d35c2a, 24) <> OverlayID) or
      not TRegEx.IsMatch(OverlaySessionID, CozyText_Overlay_Client_Pattern_6b1824b5) or
      (OverlaySessionID = ParentSessionID) then InvalidResponse;
  finally
    WipeText(Canonical);
    Reply.Free;
    Body.Free;
  end;
end;
function LaunchOverlay(Profile: TConnectServerProfile; Security: TDeviceSecurity;
  PrepareData: TJSONObject; const ParentSHA512, ParentSessionID: string;
  RestrictedPrivileges: Boolean; const MaintainParent: TProc<Boolean>;
  const Progress: TProc<Integer>): Boolean;
var Client: TOverlayClient; Flow: TBootstrapFlow; Pins: TDirectoryPins;
  FileHandle: THandle; CreatedInfo: TByHandleFileInformation;
  Body, Reply: TJSONObject; BinaryPath, ClaimText, FinishText: string;
  LaunchProfile: THandoffLaunchProfile;
  WaitMaintenance: TProc;
  OwnedParentMaintenance: TProc<Boolean>;
begin
  WaitMaintenance := nil;
  { Delphi anonymous methods cannot capture a const parameter directly. }
  OwnedParentMaintenance := MaintainParent;
  Result := False; Client := nil; Pins := nil; Body := nil; Reply := nil;
  FileHandle := INVALID_HANDLE_VALUE;
  Flow := Default(TBootstrapFlow);
  FillChar(CreatedInfo, SizeOf(CreatedInfo), 0);
  try
    RequireOverlayDocument(CozyText_Overlay_Client_overlayPrepare_a6a6dcd1, PrepareData);
    BootstrapValidateObject(PrepareData,
      CozyText_Overlay_Client_overlayId_parentSessionId_overlayTicket_release__f504952a, 8);
    if BootstrapString(PrepareData, CozyText_Overlay_Client_parentSessionId_c6ae22be, 24) <> ParentSessionID then InvalidResponse;
    Flow.FlowID := BootstrapString(PrepareData, CozyText_Overlay_Client_overlayId_83d35c2a, 24);
    if not TRegEx.IsMatch(Flow.FlowID, CozyText_Overlay_Client_Pattern_6b1824b5) then InvalidResponse;
    Flow.DownloadTicket := BootstrapString(PrepareData, CozyText_Overlay_Client_overlayTicket_f8bf593b, 512);
    Flow.Release := ParseRelease(RequiredObject(PrepareData, CozyText_Overlay_Client_release_a4521110));
    Flow.ExpiresAt := BootstrapInteger(PrepareData, CozyText_Overlay_Client_expiresAt_9fb7f3ca);
    Flow.ChunkSize := 262144;
    if BootstrapInteger(PrepareData, CozyText_Overlay_Client_chunkSize_5c98ff68) <> Flow.ChunkSize then InvalidResponse;
    if Flow.ExpiresAt <= BootstrapUTCNowMS then
      raise EOverlayDownloadFailure.Create(odfTicketExpired);
    FinishText := OverlayCanonical(CozyText_Overlay_Client_FINISH_aba8cf24, Flow.FlowID, ParentSessionID,
      Security, Flow.Release, Flow.DownloadTicket, Flow.ExpiresAt);
    ClaimText := OverlayCanonical(CozyText_Overlay_Client_CLAIM_beb80cdd, Flow.FlowID, ParentSessionID,
      Security, Flow.Release, Flow.DownloadTicket, Flow.ExpiresAt);
    if (BootstrapString(PrepareData, CozyText_Overlay_Client_finishCanonical_04794ecc) <> FinishText) or
      (BootstrapString(PrepareData, CozyText_Overlay_Client_claimCanonical_07478624) <> ClaimText) then InvalidResponse;
    Client := TOverlayClient.Create(Profile);
    BinaryPath := ExtractFilePath(CurrentImagePath) + BootstrapRandomFileName(CozyText_Overlay_Client_exe_4a968ba2);
    Pins := TDirectoryPins.Create(ExtractFilePath(BinaryPath));
    FileHandle := DownloadVerifiedBinary(Client, Flow, BinaryPath, CreatedInfo,
      OwnedParentMaintenance, Progress);
    if Assigned(Progress) then Progress(90);
    Body := TJSONObject.Create;
    Body.AddPair(CozyText_Overlay_Client_overlayId_83d35c2a, Flow.FlowID);
    Body.AddPair(CozyText_Overlay_Client_overlayTicket_f8bf593b, Flow.DownloadTicket);
    Body.AddPair(CozyText_Overlay_Client_signature_3b2323b0, Security.Sign(FinishText));
    Reply := Client.Post(CozyText_Overlay_Client_overlayFinish_b7ed5abe, Body);
    BootstrapValidateObject(Reply, CozyText_Overlay_Client_overlayId_overlayTicket_claimCanonical_expiresAt_b13f90da, 4);
    if (BootstrapString(Reply, CozyText_Overlay_Client_overlayId_83d35c2a, 24) <> Flow.FlowID) or
      (BootstrapString(Reply, CozyText_Overlay_Client_overlayTicket_f8bf593b, 512) <> Flow.DownloadTicket) or
      (BootstrapString(Reply, CozyText_Overlay_Client_claimCanonical_07478624) <> ClaimText) or
      (BootstrapInteger(Reply, CozyText_Overlay_Client_expiresAt_9fb7f3ca) <> Flow.ExpiresAt) then InvalidResponse;
    LaunchProfile := hlpInherit;
    if RestrictedPrivileges then LaunchProfile := hlpOverlayRestricted;
    { Claim inherits the parent's current lease ceiling. Renew only AFTER the
      completed download/finish and immediately before creating the child. }
    if BootstrapUTCNowMS >= Flow.ExpiresAt then
      raise EOverlayDownloadFailure.Create(odfTicketExpired);
    if Assigned(OwnedParentMaintenance) then
    begin
      OwnedParentMaintenance(True);
      WaitMaintenance :=
        procedure
        begin OwnedParentMaintenance(False); end;
    end;
    if BootstrapUTCNowMS >= Flow.ExpiresAt then
      raise EOverlayDownloadFailure.Create(odfTicketExpired);
    Result := LaunchWithHandoff(BinaryPath, Profile, Security, Flow.FlowID,
      Flow.DownloadTicket, ClaimText, ParentSHA512, Flow.Release.SHA512, True,
      LaunchProfile, WaitMaintenance);
    if not Result then raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_HANDOFF_FAILED_72b2f472);
  finally
    if FileHandle <> INVALID_HANDLE_VALUE then CloseHandle(FileHandle);
    if not Result and (BinaryPath <> '') then
      try DeleteCreatedBinary(BinaryPath, Flow.Release.SHA512, CreatedInfo); except end;
    WaitMaintenance := nil; OwnedParentMaintenance := nil;
    Reply.Free; Body.Free; Pins.Free; Client.Free;
    Flow.ClearSecrets; WipeText(ClaimText); WipeText(FinishText);
  end;
end;
function TOverlayClient.ClaimCore(const OverlayID, Ticket, Canonical: string;
  Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity): TBootstrapSession;
var Parts: TArray<string>; Expected: TBootstrapRelease; Actual: TImageDigest;
  Code: TCodeIntegrityMeasurement; Body, Reply: TJSONObject; Expiry: Int64;
  DiagnosticDeadline: UInt64;
begin
  Parts := Canonical.Split([#10]);
  if (Length(Parts) <> 18) or (Parts[0] <> CozyText_Overlay_Client_GAME_OVERLAY_CLAIM_V2_da8f4b0d) or
    (Parts[1] <> '3') or (Parts[2] <> OverlayID) or
    not TRegEx.IsMatch(Parts[3], CozyText_Overlay_Client_Pattern_6b1824b5) or
    not TRegEx.IsMatch(Parts[6], CozyText_Overlay_Client_Pattern_6b1824b5) or
    not TryStrToInt64(Parts[17], Expiry) or (Expiry <= BootstrapUTCNowMS) then InvalidResponse;
  Actual := IntegrityHashFile(CurrentImagePath);
  Code := CodeIntegrity.MeasureNow;
  Expected := Default(TBootstrapRelease);
  Expected.ID := Parts[6]; Expected.SHA512 := Actual.SHA512; Expected.CRC64 := Actual.CRC64;
  Expected.XXH3_128 := Actual.XXH3_128; Expected.Blake3 := Actual.Blake3;
  Expected.CodeSHA512 := Code.SHA512; Expected.CodeCRC64 := Code.CRC64;
  Expected.CodeXXH3_128 := Code.XXH3_128; Expected.CodeBlake3 := Code.Blake3;
  Expected.Size := Actual.Size;
  if Canonical <> OverlayCanonical(CozyText_Overlay_Client_CLAIM_beb80cdd, OverlayID, Parts[3], Security,
    Expected, Ticket, Expiry, Security.ParentDeviceID) then InvalidResponse;
  Body := TJSONObject.Create; Reply := nil;
  try
    Body.AddPair(CozyText_Overlay_Client_overlayId_83d35c2a, OverlayID); Body.AddPair(CozyText_Overlay_Client_overlayTicket_f8bf593b, Ticket);
    Body.AddPair(CozyText_Overlay_Client_handoffVersion_d5aa061e, TJSONNumber.Create(3));
    Body.AddPair(CozyText_Overlay_Client_childPublicKey_4173146d, Security.PublicKeyBlob);
    Body.AddPair(CozyText_Overlay_Client_childKeyId_336aa557, Security.DeviceID);
    Body.AddPair(CozyText_Overlay_Client_childNonce_6b9f3257, Security.HandoffNonce);
    Body.AddPair(CozyText_Overlay_Client_delegationSignature_d0920a15, Security.DelegationSignature);
    Body.AddPair(CozyText_Overlay_Client_signature_3b2323b0, Security.SignHandoffClaim('O', Canonical));
    Body.AddPair(CozyText_Overlay_Client_binarySha512_a704367f, Actual.SHA512); Body.AddPair(CozyText_Overlay_Client_crc64_f1092498, Actual.CRC64);
    Body.AddPair(CozyText_Overlay_Client_oCodeSha512_6f4eaad8, Code.SHA512); Body.AddPair(CozyText_Overlay_Client_oCodeCrc64_15a04989, Code.CRC64);
    Body.AddPair(CozyText_Overlay_Client_productScopeVersion_86736c8d, TJSONNumber.Create(1));
    Reply := Post(CozyText_Overlay_Client_overlayClaim_80b4d4b5, Body);
    BootstrapValidateObject(Reply, CozyText_Overlay_Client_sessionId_sessionToken_expiresAt_release_product_0cd40868, 6);
    ReadProductScope(Reply);
    FSession.SessionID := BootstrapString(Reply, CozyText_Overlay_Client_sessionId_3c9f1b20, 24);
    if not TRegEx.IsMatch(FSession.SessionID, CozyText_Overlay_Client_Pattern_6b1824b5) then InvalidResponse;
    FSession.SessionToken := BootstrapString(Reply, CozyText_Overlay_Client_sessionToken_1e6f5a77, 512);
    FSession.ExpiresAt := BootstrapInteger(Reply, CozyText_Overlay_Client_expiresAt_9fb7f3ca);
    FSession.Release := ParseRelease(RequiredObject(Reply, CozyText_Overlay_Client_release_a4521110));
    if (FSession.Release.ID <> Expected.ID) or (FSession.Release.SHA512 <> Expected.SHA512) or
      (FSession.Release.CRC64 <> Expected.CRC64) or
      (FSession.Release.XXH3_128 <> Expected.XXH3_128) or
      (FSession.Release.Blake3 <> Expected.Blake3) or
      (FSession.Release.CodeCRC64 <> Expected.CodeCRC64) or
      (FSession.Release.CodeXXH3_128 <> Expected.CodeXXH3_128) or
      (FSession.Release.CodeBlake3 <> Expected.CodeBlake3) or
      (FSession.Release.CodeSHA512 <> Expected.CodeSHA512) or
      (FSession.ExpiresAt <= BootstrapUTCNowMS) then InvalidResponse;
    Security.CompleteHandoff;
    FParentSessionID := Parts[3];
    FTransferConfirmed := False;
    EnsureDeviceIdentity(FTransport, Security, 'O', FSession.SessionID, FSession.SessionToken, FNHWQuoter);
    if FNHWAuthority <> nil then FNHWAuthority.SetQuoteProvider(FNHWQuoter);
    FStartupSecurity := Security; FStartupTick := CozyTick;
    StartupPhaseCore(CozyText_Overlay_Client_CLAIMED_a85fc867);
    try FLifecycle := TLifecycleReporter.Create(FTransportProfile, Security, 'O');
    except FLifecycle := nil; end;
    if FLifecycle <> nil then
    begin
      DiagnosticDeadline := CozyTick + 1500;
      FLifecycle.Prepare('O', FSession.SessionID, FSession.SessionToken, DiagnosticDeadline);
      DiagnosticDeadline := CozyTick + 1500;
      FLifecycle.Prepare('B', FSession.SessionID, FSession.SessionToken, DiagnosticDeadline);
    end;
    Result := FSession;
  finally
    Reply.Free; Body.Free;
  end;
end;
function TOverlayClient.VerifyCore(Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
  const Image: TImageDigest; const Cancelled: TModuleInventoryCancelled): Int64;
var Body, Reply: TJSONObject; Code: TCodeIntegrityMeasurement; ServerTime: Int64;
  TransferValue, PrivacyValue, BudgetValue: TJSONValue;
  SnapshotExpiresAt, ObservationExpiresAt, Remaining: Int64;
  SnapshotDeadline, OldSnapshotDeadline: UInt64;
  AllowedFields: string; FieldCount: Integer;
  VerifyRequestTick, PreviousDeadline, PreviousRequestTick: UInt64;
begin
  OldSnapshotDeadline := FSnapshotDeadlineTick;
  FLeaseSnapshotLimited := False;
  PreviousRequestTick := FLeaseRequestTick;
  PreviousDeadline := FLeaseDeadlineTick;
  FLeaseDeadlineTick := 0;
  FLeaseRequestTick := 0;
  StartupPhaseCore(CozyText_Overlay_Client_AUTHORITY_BEGIN_5dd129b6);
  RequireServerObservation(FTransport, Security, CodeIntegrity, 'O',
    FSession.SessionID, FSession.SessionToken, CozyText_Overlay_Client_verify_ef5aa193,
    AuthorityBinding(FSession.SessionID, Image.SHA512), Image.SHA512, Image.CRC64,
    function: Boolean
    begin
      Result := Assigned(Cancelled) and Cancelled();
    end, FOwnImage, OwnRuntime(Security, CodeIntegrity), FNHWAuthority);
  if Assigned(Cancelled) and Cancelled() then
    raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_CLOSING_73a70ed5);
  Code := CodeIntegrity.MeasureNow(TMeasurementBudget.Start(128 * 1024 * 1024, 30000,
    function: Boolean begin Result := FGate.IsClosing or (Assigned(Cancelled) and Cancelled()); end));
  Body := TJSONObject.Create; Reply := nil;
  try
    Body.AddPair(CozyText_Overlay_Client_sessionId_3c9f1b20, FSession.SessionID); Body.AddPair(CozyText_Overlay_Client_sessionToken_1e6f5a77, FSession.SessionToken);
    Body.AddPair(CozyText_Overlay_Client_machineId_960c6888, Security.MachineID); Body.AddPair(CozyText_Overlay_Client_binarySha512_a704367f, Image.SHA512);
    Body.AddPair(CozyText_Overlay_Client_binaryCrc64_41add33f, Image.CRC64); Body.AddPair(CozyText_Overlay_Client_codeSha512_ec69005b, Code.SHA512);
    Body.AddPair(CozyText_Overlay_Client_codeCrc64_c91b93a5, Code.CRC64);
    Body.AddPair(CozyText_Overlay_Client_capturePrivacyVersion_fa82d189, TJSONNumber.Create(1));
    Body.AddPair(CozyText_Overlay_Client_renewalBudgetVersion_7a6558d0, TJSONNumber.Create(1));
    Body.AddPair(CozyText_Overlay_Client_productScopeVersion_86736c8d, TJSONNumber.Create(1));
    VerifyRequestTick := CozyTick;
    Reply := Post(CozyText_Overlay_Client_overlayVerify_4bb73784, Body);
    PrivacyValue := Reply.GetValue(CozyText_Overlay_Client_capturePrivacy_76a63293);
    BudgetValue := Reply.GetValue(CozyText_Overlay_Client_renewalBudget_e55f3d83);
    AllowedFields := CozyText_Overlay_Client_status_leaseExpiresAt_serverTime_expiresAt_hando_c49154ec;
    AllowedFields := AllowedFields + CozyText_Overlay_Client_productScopeVersion_productId_571ea44e;
    FieldCount := 9;
    if PrivacyValue <> nil then
    begin
      if not (PrivacyValue is TJSONBool) then InvalidResponse;
      AllowedFields := AllowedFields + CozyText_Overlay_Client_capturePrivacy_2c91ed6e; Inc(FieldCount);
    end;
    if BudgetValue <> nil then
    begin
      if not (BudgetValue is TJSONObject) then InvalidResponse;
      AllowedFields := AllowedFields + CozyText_Overlay_Client_renewalBudget_7bb35d0b; Inc(FieldCount);
      BootstrapValidateObject(TJSONObject(BudgetValue),
        CozyText_Overlay_Client_version_snapshotExpiresAt_observationExpiresAt_62af5aed, 3);
      if BootstrapInteger(TJSONObject(BudgetValue), CozyText_Overlay_Client_version_2c126698) <> 1 then InvalidResponse;
    end;
    BootstrapValidateObject(Reply, AllowedFields, FieldCount);
    ReadProductScope(Reply);
    TransferValue := Reply.GetValue(CozyText_Overlay_Client_transferConfirmed_53c12287);
    if (BootstrapString(Reply, CozyText_Overlay_Client_status_2aa55de1, 16) <> CozyText_Overlay_Client_ACTIVE_3407f3d7) or
      (BootstrapInteger(Reply, CozyText_Overlay_Client_handoffVersion_d5aa061e) <> 1) or
      (BootstrapString(Reply, CozyText_Overlay_Client_parentSessionId_c6ae22be, 24) <> FParentSessionID) or
      not (TransferValue is TJSONBool) then InvalidResponse;
    ServerTime := BootstrapInteger(Reply, CozyText_Overlay_Client_serverTime_64c90dcb);
    Result := BootstrapInteger(Reply, CozyText_Overlay_Client_leaseExpiresAt_179cae2c) - ServerTime;
    if (Result <= 0) or (Result > 120000) or
      (BootstrapInteger(Reply, CozyText_Overlay_Client_expiresAt_9fb7f3ca) <> ServerTime + Result) then InvalidResponse;
    if FTransferConfirmed and (TransferValue.Value <> CozyText_Overlay_Client_true_5454fec4) then InvalidResponse;
    if VerifyRequestTick > High(UInt64) - UInt64(Result) then InvalidResponse;
    if ServerTime < FLastLeaseServerTime then InvalidResponse;
    FLeaseDeadlineTick := VerifyRequestTick + UInt64(Result);
    FLeaseRequestTick := VerifyRequestTick;
    if (ServerTime = FLastLeaseServerTime) and (FLastLeaseServerTime <> 0) then
    begin
      { An exact old receipt must keep its first local monotonic bound. }
      if (PreviousDeadline = 0) or (PreviousRequestTick = 0) or
        (Result <> FLastLeaseDuration) or
        (PreviousRequestTick > High(UInt64) - UInt64(Result)) or
        (PreviousRequestTick + UInt64(Result) <> PreviousDeadline) then InvalidResponse;
      if PreviousDeadline < FLeaseDeadlineTick then FLeaseDeadlineTick := PreviousDeadline;
      FLeaseRequestTick := PreviousRequestTick;
    end;
    FLastLeaseServerTime := ServerTime;
    FLastLeaseDuration := Result;
    if FLeaseDeadlineTick <= CozyTick then
      raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_LEASE_EXPIRED_9b53a056);
    { This bound is only for scheduling a full module transaction. It cannot
      enlarge the runtime lease above. Keep one snapshot's earliest mapped
      monotonic deadline despite later responses/network delay. }
    if BudgetValue <> nil then
    begin
      SnapshotExpiresAt := BootstrapInteger(TJSONObject(BudgetValue), CozyText_Overlay_Client_snapshotExpiresAt_439ec118);
      ObservationExpiresAt := BootstrapInteger(TJSONObject(BudgetValue), CozyText_Overlay_Client_observationExpiresAt_e022a144);
      if (SnapshotExpiresAt < 0) or
        (ObservationExpiresAt < ServerTime + Result) then InvalidResponse;
      SnapshotDeadline := 0;
      if SnapshotExpiresAt <> 0 then
      begin
        Remaining := SnapshotExpiresAt - ServerTime;
        if (Remaining < Result) or (Remaining > 120000) or
          (VerifyRequestTick > High(UInt64) - UInt64(Remaining)) then InvalidResponse;
        if (FLastSnapshotExpiresAt <> 0) and
          (SnapshotExpiresAt < FLastSnapshotExpiresAt) then InvalidResponse;
        SnapshotDeadline := VerifyRequestTick + UInt64(Remaining);
        if (SnapshotExpiresAt = FLastSnapshotExpiresAt) and (OldSnapshotDeadline <> 0) and
          (OldSnapshotDeadline < SnapshotDeadline) then SnapshotDeadline := OldSnapshotDeadline;
      end;
      FSnapshotDeadlineTick := SnapshotDeadline;
      FLastSnapshotExpiresAt := SnapshotExpiresAt;
      { Compare the authenticated SERVER bounds, not differently delayed local
        clock mappings. This bit is scheduling advice, never runtime authority. }
      FLeaseSnapshotLimited := (SnapshotExpiresAt <> 0) and
        (SnapshotExpiresAt = ServerTime + Result);
    end;
    StartupPhaseCore(CozyText_Overlay_Client_AUTHORIZED_c6818a7e);
    FTransferConfirmed := TransferValue.Value = CozyText_Overlay_Client_true_5454fec4;
    FCapturePrivacy := (PrivacyValue <> nil) and (PrivacyValue.Value = CozyText_Overlay_Client_true_5454fec4);
    { Diagnostic permits are prepared by the worker only AFTER it publishes
      this new runtime deadline. No diagnostic I/O delays lease publication. }
  finally Reply.Free; Body.Free; end;
end;
function TOverlayClient.ChunkCore(const Flow: TBootstrapFlow;
  Offset: Int64; RequestDeadlineTick: UInt64): TBytes;
var Body, Data: TJSONObject; Encoded: string; Encoding: TBase64Encoding;
  Expected: Int64;
begin
  if (Offset < 0) or (Offset >= Flow.Release.Size) then InvalidResponse;
  Body := TJSONObject.Create;
  Data := nil;
  Encoding := TBase64Encoding.Create(0);
  try
    Body.AddPair(CozyText_Overlay_Client_overlayId_83d35c2a, Flow.FlowID);
    Body.AddPair(CozyText_Overlay_Client_overlayTicket_f8bf593b, Flow.DownloadTicket);
    Body.AddPair(CozyText_Overlay_Client_offset_55523723, TJSONNumber.Create(Offset));
    Data := Post(CozyText_Overlay_Client_overlayChunk_7527da33, Body, RequestDeadlineTick);
    if BootstrapInteger(Data, CozyText_Overlay_Client_offset_55523723) <> Offset then InvalidResponse;
    Expected := Flow.Release.Size - Offset;
    if Expected > Flow.ChunkSize then Expected := Flow.ChunkSize;
    if BootstrapInteger(Data, CozyText_Overlay_Client_size_06a3246c) <> Expected then InvalidResponse;
    Encoded := BootstrapString(Data, CozyText_Overlay_Client_data_4bb0a19a, ((Flow.ChunkSize + 2) div 3) * 4);
    Result := Encoding.DecodeStringToBytes(Encoded);
    if (Length(Result) <> Expected) or
      (Encoding.EncodeBytesToString(Result) <> Encoded) then InvalidResponse;
  finally
    Encoding.Free;
    Body.Free;
    Data.Free;
  end;
end;

procedure TOverlayClient.ReportIntegrityCore(
  Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity; const Image: TImageDigest;
  IncludeModules: Boolean; const Cancelled: TModuleInventoryCancelled;
  FailureStatus: TMeasurementStatus; OwnImage: TImageIntegrity;
  const MaintainLease: TProc<Boolean>);
var Code: TCodeIntegrityMeasurement; Snapshot, Payload, Own, CrcLayers, Bundle: TJSONObject;
  CurrentImage: TImageDigest;
  Modules, Value: TJSONValue; Batch: TJSONArray;
  I, Total, BatchIndex, BatchCount, BatchSize, GenerationRetries: Integer;
  Bytes, MetadataBytes, EncodedMetadataBytes, LargestModuleBytes,
    LargestEncodedModuleBytes, SubmitOverhead: Integer;
  CollectionStarted, CollectionNow: UInt64;
  SnapshotID: string; Measured: Boolean; Failure: TMeasurementStatus;
  function EncodedStringBytes(const Text: string): Integer;
  var Encoded: TJSONString;
  begin
    Encoded := TJSONString.Create(Text);
    try Result := TEncoding.UTF8.GetByteCount(Encoded.ToJSON);
    finally Encoded.Free; end;
  end;
  procedure AddAuth(Body: TJSONObject);
  begin
    Body.AddPair(CozyText_Overlay_Client_stage_38592d68, 'O');
    Body.AddPair(CozyText_Overlay_Client_sessionId_3c9f1b20, FSession.SessionID);
    Body.AddPair(CozyText_Overlay_Client_sessionToken_1e6f5a77, FSession.SessionToken);
    Body.AddPair(CozyText_Overlay_Client_machineId_960c6888, Security.MachineID);
  end;
  function SubmitOverheadBytes: Integer;
  var Envelope, Body: TJSONObject;
  begin
    Envelope := TJSONObject.Create;
    try
      Envelope.AddPair(CozyText_Overlay_Client_operation_fc09d2a6, CozyText_Overlay_Client_report_37b1de33);
      Envelope.AddPair(CozyText_Overlay_Client_tlsPinVersion_f3a7b04f, TJSONNumber.Create(1));
      Body := TJSONObject.Create;
      Envelope.AddPair(CozyText_Overlay_Client_body_673c83f5, Body);
      AddAuth(Body);
      Body.AddPair(CozyText_Overlay_Client_action_fbec0782, CozyText_Overlay_Client_submit_ed9fd14f);
      { Reserve protocol maxima, including the envelope's escaped JSON string. }
      Body.AddPair(CozyText_Overlay_Client_reportId_f2dcd992, StringOfChar('X', 160));
      Body.AddPair(CozyText_Overlay_Client_signature_3b2323b0, StringOfChar('X', 1024));
      Body.AddPair(CozyText_Overlay_Client_payload_8e720c22, '');
      Result := TEncoding.UTF8.GetByteCount(Envelope.ToJSON) - 2;
    finally Envelope.Free; end;
  end;
  function ReportPost(Body: TJSONObject; ExactSubmitRetry: Boolean): TJSONObject;
  var Response: TJSONObject; OKValue, DataValue: TJSONValue;
    Attempt, Attempts: Integer; Deadline, NowTick: UInt64;
  begin
    if Assigned(Cancelled) and Cancelled() then
      raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_CLOSING_73a70ed5);
    Response := nil;
    Attempts := 1;
    if ExactSubmitRetry then Attempts := 2;
    Deadline := CozyTick + 15000;
    for Attempt := 1 to Attempts do
    begin
        if Assigned(Cancelled) and Cancelled() then raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_CLOSING_73a70ed5);
      NowTick := CozyTick;
      if NowTick >= Deadline then
        raise EConnectTransport.Create(CozyText_Overlay_Client_CONNECT_TIMEOUT_4fb4b726, CozyText_Overlay_Client_Report_retry_deadline_expired_48dbfd57);
      try
        Response := FTransport.PostJSON(CozyText_Overlay_Client_report_37b1de33, Body, Cardinal(Deadline - NowTick));
        Break;
      except
        on E: EConnectTransport do
          if (Attempt = Attempts) or
            ((E.Code <> CozyText_Overlay_Client_CONNECT_TIMEOUT_4fb4b726) and (E.Code <> CozyText_Overlay_Client_CONNECT_UNAVAILABLE_2477720e) and
             (E.Code <> CozyText_Overlay_Client_CONNECT_SEND_FAILED_8a598241) and (E.Code <> CozyText_Overlay_Client_CONNECT_RECEIVE_FAILED_703bdde2) and
             (E.Code <> CozyText_Overlay_Client_NETWORK_UNAVAILABLE_f4bc46ee)) then raise;
      end;
    end;
    try
      if Assigned(Cancelled) and Cancelled() then raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_CLOSING_73a70ed5);
      if Response = nil then InvalidResponse;
      OKValue := Response.GetValue(CozyText_Overlay_Client_ok_bacb1b07);
      if not (OKValue is TJSONBool) or (OKValue.Value <> CozyText_Overlay_Client_true_5454fec4) then
        raise EBootstrap.Create(CozyText_Overlay_Client_INTEGRITY_REPORT_REJECTED_e57171d8);
      DataValue := Response.GetValue(CozyText_Overlay_Client_data_4bb0a19a);
      if not (DataValue is TJSONObject) then InvalidResponse;
      Result := TJSONObject(DataValue.Clone);
    finally
      Response.Free;
    end;
  end;
  procedure Send(Payload: TJSONObject);
  var ChallengeBody, Challenge, SubmitBody, Reply: TJSONObject;
    Text, Canonical, ReportID, Nonce: string; ExpiresAt: Int64;
  begin
    ChallengeBody := TJSONObject.Create;
    Challenge := nil;
    SubmitBody := nil;
    Reply := nil;
    try
      Payload.AddPair(CozyText_Overlay_Client_hashVersion_45a60e5e, TJSONNumber.Create(3));
      Text := Payload.ToJSON;
      if (TEncoding.UTF8.GetByteCount(Text) > 24576) or
        (Int64(SubmitOverheadBytes) + EncodedStringBytes(Text) > 32768) then
        InvalidResponse;
      AddAuth(ChallengeBody);
      ChallengeBody.AddPair(CozyText_Overlay_Client_action_fbec0782, CozyText_Overlay_Client_challenge_cc85f8ca);
      Challenge := ReportPost(ChallengeBody, False);
      ReportID := BootstrapString(Challenge, CozyText_Overlay_Client_reportId_f2dcd992, 128);
      Nonce := BootstrapString(Challenge, CozyText_Overlay_Client_nonce_62b2c4cb, 256);
      ExpiresAt := BootstrapInteger(Challenge, CozyText_Overlay_Client_expiresAt_9fb7f3ca);
      if (Length(ReportID) < 12) or (Length(Nonce) < 20) or
        (Pos(#10, ReportID) <> 0) or (Pos(#10, Nonce) <> 0) or
        (ExpiresAt <= 0) then InvalidResponse;
      Canonical := CozyText_Overlay_Client_GAME_INTEGRITY_REPORT_V2_2733eed7 + #10 + FSession.SessionID + #10 +
        ReportID + #10 + Nonce + #10 + IntToStr(ExpiresAt) + #10 + IntegritySHA512Text(Text);
      SubmitBody := TJSONObject.Create;
      AddAuth(SubmitBody);
      SubmitBody.AddPair(CozyText_Overlay_Client_action_fbec0782, CozyText_Overlay_Client_submit_ed9fd14f);
      SubmitBody.AddPair(CozyText_Overlay_Client_reportId_f2dcd992, ReportID);
      SubmitBody.AddPair(CozyText_Overlay_Client_payload_8e720c22, Text);
      if Assigned(Cancelled) and Cancelled() then raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_CLOSING_73a70ed5);
      SubmitBody.AddPair(CozyText_Overlay_Client_signature_3b2323b0, Security.Sign(Canonical));
      Reply := ReportPost(SubmitBody, True);
      Value := Reply.GetValue(CozyText_Overlay_Client_accepted_f78c341c);
      if not (Value is TJSONBool) or (Value.Value <> CozyText_Overlay_Client_true_5454fec4) then InvalidResponse;
      Value := Reply.GetValue(CozyText_Overlay_Client_terminate_96263ba0);
      if not (Value is TJSONBool) then InvalidResponse;
      if (Value.Value = CozyText_Overlay_Client_true_5454fec4) or (BootstrapString(Reply, CozyText_Overlay_Client_status_2aa55de1, 32) = CozyText_Overlay_Client_REJECTED_0d7a3a33) then
        raise EBootstrap.Create(CozyText_Overlay_Client_INTEGRITY_REJECTED_72b1574f);
    finally
      WipeText(Text);
      WipeText(Canonical);
      Reply.Free;
      SubmitBody.Free;
      Challenge.Free;
      ChallengeBody.Free;
    end;
  end;
  function CreateModulePayload(Index, Count: Integer): TJSONObject;
  var Body: TJSONObject;
    procedure AddMetadata(const Name: string);
    var Meta: TJSONValue;
    begin
      Meta := Snapshot.GetValue(Name);
      if Meta <> nil then Body.AddPair(Name, TJSONValue(Meta.Clone));
    end;
  begin
    Body := TJSONObject.Create;
    try
      Body.AddPair(CozyText_Overlay_Client_version_2c126698, TJSONNumber.Create(1));
      Body.AddPair(CozyText_Overlay_Client_check_7bd79809, CozyText_Overlay_Client_MODULE_INVENTORY_385271e3);
      Body.AddPair(CozyText_Overlay_Client_reason_f2968643, CozyText_Overlay_Client_PERIODIC_91a94806);
      Body.AddPair(CozyText_Overlay_Client_snapshotId_b5671759, SnapshotID);
      Body.AddPair(CozyText_Overlay_Client_batchIndex_50adf88b, TJSONNumber.Create(Index));
      Body.AddPair(CozyText_Overlay_Client_batchCount_4eb26e22, TJSONNumber.Create(Count));
      AddMetadata(CozyText_Overlay_Client_complete_c18990e8);
      AddMetadata(CozyText_Overlay_Client_truncated_1d67adf4);
      AddMetadata(CozyText_Overlay_Client_totalModules_00df515b);
      AddMetadata(CozyText_Overlay_Client_measuredModules_d1ea70db);
      AddMetadata(CozyText_Overlay_Client_scope_2d284a6b);
      AddMetadata(CozyText_Overlay_Client_trust_c6215f91);
      AddMetadata(CozyText_Overlay_Client_measurementContract_9edd259b);
      AddMetadata(CozyText_Overlay_Client_measurementPlanVersion_3d5bc324);
      AddMetadata(CozyText_Overlay_Client_measurementStartedTick_1f35f3c8);
      AddMetadata(CozyText_Overlay_Client_measurementFinishedTick_d94adb48);
      AddMetadata(CozyText_Overlay_Client_moduleGenerationStable_27ea0db0);
      AddMetadata(CozyText_Overlay_Client_moduleGenerationStatus_8fcdeab0);
      AddMetadata(CozyText_Overlay_Client_threadInventory_c176acf3);
      AddMetadata(CozyText_Overlay_Client_deviceSignals_3d6c4bdb);
      AddMetadata(CozyText_Overlay_Client_coverage_4d40acab);
      Result := Body;
    except Body.Free; raise; end;
  end;
begin
  StartupPhaseCore(CozyText_Overlay_Client_OWN_BEGIN_ef16c759);
  Measured := False;
  CrcLayers := nil; Bundle := nil;
  if OwnImage <> nil then FOwnImage := OwnImage;
  Failure := FailureStatus;
  CurrentImage := Default(TImageDigest); Code := Default(TCodeIntegrityMeasurement);
  if Failure = msMeasured then
  try
    Failure := msNotMeasured;
    Bundle := CollectOwnMeasurement(FOwnImage, CodeIntegrity,
      TMeasurementBudget.Start(128 * 1024 * 1024, 30000,
        function: Boolean
        begin Result := Assigned(Cancelled) and Cancelled(); end),
      CurrentImage, Code, CrcLayers, Failure, OwnRuntime(Security, CodeIntegrity));
    Measured := OwnMeasurementComplete(Bundle, CurrentImage, Code, CrcLayers, Failure);
    if (Failure = msMeasured) and not Measured then
    begin Failure := msCoverageInsufficient; FreeAndNil(Bundle); end;
  except
    on E: Exception do
    begin
      Failure := MeasurementFailureStatus(E);
      FreeAndNil(CrcLayers);
    end;
  end;
  Payload := nil;
  try
    Payload := TJSONObject.Create;
    Payload.AddPair(CozyText_Overlay_Client_version_2c126698, TJSONNumber.Create(1));
    Payload.AddPair(CozyText_Overlay_Client_check_7bd79809, CozyText_Overlay_Client_OWN_IMAGE_c0ac84c6);
    if Measured then Payload.AddPair(CozyText_Overlay_Client_reason_f2968643, CozyText_Overlay_Client_PERIODIC_91a94806)
    else Payload.AddPair(CozyText_Overlay_Client_reason_f2968643, CozyText_Overlay_Client_MEASUREMENT_FAILED_fcfccff5);
    Own := TJSONObject.Create;
    if Measured then
    begin
      Own.AddPair(CozyText_Overlay_Client_status_2aa55de1, CozyText_Overlay_Client_MEASURED_84d598ab);
      Own.AddPair(CozyText_Overlay_Client_fileSha512_92649b28, CurrentImage.SHA512);
      Own.AddPair(CozyText_Overlay_Client_fileCrc64_b9140c0c, CurrentImage.CRC64);
      Own.AddPair(CozyText_Overlay_Client_codeSha512_ec69005b, Code.SHA512);
      Own.AddPair(CozyText_Overlay_Client_codeCrc64_c91b93a5, Code.CRC64);
      Own.AddPair(CozyText_Overlay_Client_fileXxh3_128_e4dfe121, CurrentImage.XXH3_128);
      Own.AddPair(CozyText_Overlay_Client_fileBlake3_93cae382, CurrentImage.Blake3);
      Own.AddPair(CozyText_Overlay_Client_codeXxh3_128_e16e3fad, Code.XXH3_128);
      Own.AddPair(CozyText_Overlay_Client_codeBlake3_c0771ac7, Code.Blake3);
    end
    else Own.AddPair(CozyText_Overlay_Client_status_2aa55de1, MeasurementStatusName(Failure));
    Payload.AddPair(CozyText_Overlay_Client_own_4042deb5, Own);
    if CrcLayers <> nil then
    begin Payload.AddPair(CozyText_Overlay_Client_crcLayers_fac99093, CrcLayers); CrcLayers := nil; end;
    if Bundle <> nil then begin Payload.AddPair(CozyText_Overlay_Client_ownMeasurement_0812a896, Bundle); Bundle := nil; end;
    Send(Payload);
  finally
    Bundle.Free; CrcLayers.Free;
    Payload.Free;
  end;
  if not Measured then raise EBootstrap.Create(CozyText_Overlay_Client_INTEGRITY_MEASUREMENT_FAILED_52cb86cb);
  StartupPhaseCore(CozyText_Overlay_Client_OWN_READY_40561585);
  if not IncludeModules then Exit;
  StartupPhaseCore(CozyText_Overlay_Client_MODULES_BEGIN_fbddfcc4);
  { A periodic scan must not consume an almost-expired O lease. The callback
    performs the ordinary fresh server verification against the PREVIOUS
    complete snapshot. During initial acquisition it is a no-op. No callback
    runs inside a measurement read or an in-flight network operation. }
  if Assigned(MaintainLease) then MaintainLease(True);
  Snapshot := nil;
  CollectionStarted := CozyTick;
  GenerationRetries := 0;
  try
    repeat
      if Assigned(Cancelled) and Cancelled() then
        raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_CLOSING_73a70ed5);
      Snapshot := CollectModuleInventoryJSON(
        function: Boolean
        var At: UInt64;
        begin
          At := CozyTick;
          Result := (Assigned(Cancelled) and Cancelled()) or
            (At < CollectionStarted) or (At - CollectionStarted >= 90000);
        end, FOwnImage, CodeIntegrity);
      if Snapshot = nil then InvalidResponse;
      CollectionNow := CozyTick;
      { O loads GPU/COM modules immediately before this first inventory.
        Retry only a clean loader-generation race, using the same classifier
        as B. Discard the ENTIRE old snapshot before any batch is sent. Real
        mismatches, read failures and exhausted retries are reported unchanged. }
      if not ModuleInventoryGenerationRetryable(Snapshot) or
        (GenerationRetries >= 2) or (CollectionNow < CollectionStarted) or
        (CollectionNow - CollectionStarted >= 90000) then Break;
      Inc(GenerationRetries);
      FreeAndNil(Snapshot);
      if Assigned(MaintainLease) then MaintainLease(False);
    until False;
    Modules := Snapshot.GetValue(CozyText_Overlay_Client_modules_ec49837f);
    if not (Modules is TJSONArray) then InvalidResponse;
    Total := TJSONArray(Modules).Count;
    if Total > 1024 then InvalidResponse;
    SnapshotID := BootstrapRequestID;
    { Use the server's existing 16-row cap only when BOTH payload and escaped
      request envelope fit. This avoids unnecessary signed round trips before
      the first visible frame without changing any lease or evidence rule. }
    Payload := CreateModulePayload(255, 256);
    try
      Payload.AddPair(CozyText_Overlay_Client_hashVersion_45a60e5e, TJSONNumber.Create(3));
      Payload.AddPair(CozyText_Overlay_Client_modules_ec49837f, TJSONArray.Create);
      MetadataBytes := TEncoding.UTF8.GetByteCount(Payload.ToJSON);
      EncodedMetadataBytes := EncodedStringBytes(Payload.ToJSON);
    finally Payload.Free; end;
    SubmitOverhead := SubmitOverheadBytes;
    LargestModuleBytes := 0; LargestEncodedModuleBytes := 0;
    for I := 0 to Total - 1 do
    begin
      Bytes := TEncoding.UTF8.GetByteCount(TJSONArray(Modules).Items[I].ToJSON);
      if Bytes > LargestModuleBytes then LargestModuleBytes := Bytes;
      Bytes := EncodedStringBytes(TJSONArray(Modules).Items[I].ToJSON) - 2;
      if Bytes > LargestEncodedModuleBytes then LargestEncodedModuleBytes := Bytes;
    end;
    BatchSize := 16;
    while (BatchSize > 0) and
      ((Int64(MetadataBytes) + Int64(LargestModuleBytes + 1) * BatchSize > 24576) or
       (Int64(SubmitOverhead) + EncodedMetadataBytes +
        Int64(LargestEncodedModuleBytes + 1) * BatchSize > 32768)) do
      Dec(BatchSize);
    if BatchSize < 1 then InvalidResponse;
    BatchCount := (Total + BatchSize - 1) div BatchSize;
    if BatchCount = 0 then BatchCount := 1;
    if BatchCount > 256 then InvalidResponse;
    I := 0;
    BatchIndex := 0;
    repeat
      { The snapshot object/ID/generation remain immutable for all batches.
        Renewals here contain NEW own-image evidence and use only the last
        complete server-accepted snapshot, never this partial batch set. }
      if Assigned(MaintainLease) then MaintainLease(False);
      Payload := CreateModulePayload(BatchIndex, BatchCount);
      try
        Batch := TJSONArray.Create;
        Payload.AddPair(CozyText_Overlay_Client_modules_ec49837f, Batch);
        while (I < Total) and (Batch.Count < BatchSize) do
        begin
          Batch.AddElement(TJSONValue(TJSONArray(Modules).Items[I].Clone));
          Inc(I);
        end;
        Send(Payload);
      finally
        Payload.Free;
      end;
      Inc(BatchIndex);
    until BatchIndex >= BatchCount;
    StartupPhaseCore(CozyText_Overlay_Client_MODULES_READY_f56be747);
  finally
    Snapshot.Free;
  end;
end;

procedure TOverlayClient.CloseCore;
var Body, Data, Diagnostic: TJSONObject;
  Elapsed: UInt64;
begin
  if FSession.SessionID = '' then begin FClosed := True; Exit; end;
  Body := TJSONObject.Create;
  Data := nil;
  try
    Body.AddPair(CozyText_Overlay_Client_sessionId_3c9f1b20, FSession.SessionID);
    Body.AddPair(CozyText_Overlay_Client_sessionToken_1e6f5a77, FSession.SessionToken);
    if FShutdownDiagnostics then
    begin
      Diagnostic := TJSONObject.Create;
      Diagnostic.AddPair(CozyText_Overlay_Client_version_2c126698,TJSONNumber.Create(1));
      Elapsed := FShutdownJoinElapsed; if Elapsed > 86400000 then Elapsed := 86400000;
      Diagnostic.AddPair(CozyText_Overlay_Client_joinElapsedMs_7818e468,TJSONNumber.Create(Int64(Elapsed)));
      Diagnostic.AddPair(CozyText_Overlay_Client_joinBudgetMissed_ca168f43,TJSONBool.Create(FShutdownJoinMissed));
      Diagnostic.AddPair(CozyText_Overlay_Client_durationTruncated_23f20bf0,TJSONBool.Create(FShutdownJoinElapsed > 86400000));
      Body.AddPair(CozyText_Overlay_Client_shutdown_047f427e,Diagnostic);
    end;
    try
      Data := Post(CozyText_Overlay_Client_overlayClose_3d24a01b, Body);
      if FLifecycle <> nil then FLifecycle.Note('O', CozyText_Overlay_Client_CLOSE_RESPONSE_c6161a8f, CozyText_Overlay_Client_ACKNOWLEDGED_b5d74cb8);
    except
      if FLifecycle <> nil then FLifecycle.Note('O', CozyText_Overlay_Client_CLOSE_RESPONSE_c6161a8f, CozyText_Overlay_Client_FAILED_ece75a5e);
      raise;
    end;
  finally
    Data.Free;
    Body.Free;
    FClosed := True;
    FSession.SessionID := '';
    FSession.ClearSecrets;
    FSession.ExpiresAt := 0;
  end;
end;

function TOverlayClient.GetSessionCore: TBootstrapSession;
begin Result := FSession; end;

function TOverlayClient.GetTransferConfirmedCore: Boolean;
begin Result := FTransferConfirmed; end;

function TOverlayClient.Chunk(const Flow: TBootstrapFlow; Offset: Int64;
  RequestDeadlineTick: UInt64): TBytes;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Overlay_Client_CLIENT_CLOSED_ee7ae48d);
      Result := ChunkCore(Flow, Offset, RequestDeadlineTick);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

procedure TOverlayClient.StartupPhaseCore(const Phase: string;
  const FailureStage: string; FailureCode: Integer);
var Body, Reply, Failure: TJSONObject; Elapsed: UInt64;
  Canonical: string; PhaseCode: Cardinal; HasFailure: Boolean;
begin
  if FStartupDone or (FStartupSecurity = nil) or (FSession.SessionID = '') then Exit;
  HasFailure := FailureStage <> '';
  if HasFailure then
  begin
    if (Phase <> CozyText_Overlay_Client_FAILED_ece75a5e) or
      not ((FailureStage = CozyText_Overlay_Client_BINDING_360381cc) or (FailureStage = CozyText_Overlay_Client_FONT_READ_ae97fa46) or
        (FailureStage = CozyText_Overlay_Client_FONT_DATA_859cacbb) or (FailureStage = CozyText_Overlay_Client_CREATE_5bc855d8) or
        (FailureStage = CozyText_Overlay_Client_RESIZE_858df53e) or
        (FailureStage = CozyText_Overlay_Client_GPU_IDENTITY_61356ab0) or (FailureStage = CozyText_Overlay_Client_FLOATING_POINT_c95c6bd8) or
        (FailureStage = CozyText_Overlay_Client_UNKNOWN_6656f228)) then Exit;
  end
  else if FailureCode <> 0 then Exit;
  PhaseCode := 0;
  if Phase = CozyText_Overlay_Client_CLAIMED_a85fc867 then PhaseCode := 1
  else if Phase = CozyText_Overlay_Client_IMAGE_BOUND_b1473d0e then PhaseCode := 2
  else if Phase = CozyText_Overlay_Client_GPU_BEGIN_eaf6e620 then PhaseCode := 3
  else if Phase = CozyText_Overlay_Client_GPU_READY_ffa1d4d4 then PhaseCode := 4
  else if Phase = CozyText_Overlay_Client_OWN_BEGIN_ef16c759 then PhaseCode := 5
  else if Phase = CozyText_Overlay_Client_OWN_READY_40561585 then PhaseCode := 6
  else if Phase = CozyText_Overlay_Client_MODULES_BEGIN_fbddfcc4 then PhaseCode := 7
  else if Phase = CozyText_Overlay_Client_MODULES_READY_f56be747 then PhaseCode := 8
  else if Phase = CozyText_Overlay_Client_AUTHORITY_BEGIN_5dd129b6 then PhaseCode := 9
  else if Phase = CozyText_Overlay_Client_AUTHORIZED_c6818a7e then PhaseCode := 10
  else if Phase = CozyText_Overlay_Client_VISIBLE_d861cf63 then PhaseCode := 11
  else if Phase = CozyText_Overlay_Client_FAILED_ece75a5e then PhaseCode := 12;
  if (PhaseCode = 0) or (PhaseCode <= FStartupPhaseCode) then Exit;
  FStartupPhaseCode := PhaseCode;
  if FStartupSequence >= 16 then Exit;
  Elapsed := CozyTick - FStartupTick;
  if Elapsed > 180000 then Exit;
  Inc(FStartupSequence);
  if (Phase = CozyText_Overlay_Client_VISIBLE_d861cf63) or (Phase = CozyText_Overlay_Client_FAILED_ece75a5e) then FStartupDone := True;
  Body := nil; Reply := nil; Failure := nil;
  try
    try
      Body := TJSONObject.Create;
      Body.AddPair(CozyText_Overlay_Client_action_fbec0782, CozyText_Overlay_Client_overlayProgress_578192c0);
      Body.AddPair(CozyText_Overlay_Client_sessionId_3c9f1b20, FSession.SessionID);
      Body.AddPair(CozyText_Overlay_Client_sessionToken_1e6f5a77, FSession.SessionToken);
      Body.AddPair(CozyText_Overlay_Client_sequence_391623a6, TJSONNumber.Create(FStartupSequence));
      Body.AddPair(CozyText_Overlay_Client_phase_751bac01, Phase);
      Body.AddPair(CozyText_Overlay_Client_elapsedMs_b7905f3d, TJSONNumber.Create(Int64(Elapsed)));
      if HasFailure then
      begin
        Failure := TJSONObject.Create;
        Failure.AddPair(CozyText_Overlay_Client_version_2c126698, TJSONNumber.Create(1));
        Failure.AddPair(CozyText_Overlay_Client_stage_38592d68, FailureStage);
        Failure.AddPair(CozyText_Overlay_Client_code_33e86e07, TJSONNumber.Create(FailureCode));
        Body.AddPair(CozyText_Overlay_Client_failure_9006e0de, Failure); Failure := nil;
        Canonical := CozyText_Overlay_Client_GAME_OVERLAY_PROGRESS_V2_4766a375 + #10 + FSession.SessionID + #10 +
          IntToStr(FStartupSequence) + #10 + Phase + #10 + IntToStr(Elapsed) + #10 +
          '1' + #10 + FailureStage + #10 + IntToStr(FailureCode);
      end
      else
        Canonical := CozyText_Overlay_Client_GAME_OVERLAY_PROGRESS_V1_cb1773a3 + #10 + FSession.SessionID + #10 +
          IntToStr(FStartupSequence) + #10 + Phase + #10 + IntToStr(Elapsed);
      Body.AddPair(CozyText_Overlay_Client_signature_3b2323b0, FStartupSecurity.Sign(Canonical));
      Reply := FTransport.PostJSON(CozyText_Overlay_Client_bootstrap_a83d45a9, Body, 1000);
    except
      { Best effort: no local token/log file; telemetry never grants a lease. }
    end;
  finally Failure.Free; Body.Free; Reply.Free; WipeText(Canonical); end;
end;

procedure TOverlayClient.StartupPhase(const Phase: string);
begin
  try
    FGate.Enter;
    try
      TMonitor.Enter(FLock);
      try if not FClosed then StartupPhaseCore(Phase);
      finally TMonitor.Exit(FLock); end;
    finally FGate.Leave; end;
  except
    { Failure to record diagnostics does not replace the original outcome. }
  end;
end;

procedure TOverlayClient.StartupFailure(const Stage: string; NativeCode: Integer);
begin
  try
    FGate.Enter;
    try
      TMonitor.Enter(FLock);
      try
        if not FClosed then
          StartupPhaseCore(CozyText_Overlay_Client_FAILED_ece75a5e, Stage, NativeCode);
      finally TMonitor.Exit(FLock); end;
    finally FGate.Leave; end;
  except
    { Diagnostics never authorize execution or replace the original failure. }
  end;
end;

function TOverlayClient.GetLeaseSnapshotLimited: Boolean;
begin
  TMonitor.Enter(FLock);
  try Result := FLeaseSnapshotLimited;
  finally TMonitor.Exit(FLock); end;
end;
function TOverlayClient.GetSnapshotDeadlineTick: UInt64;
begin
  TMonitor.Enter(FLock);
  try Result := FSnapshotDeadlineTick;
  finally TMonitor.Exit(FLock); end;
end;
procedure TOverlayClient.PrepareLifecycle(DeadlineTick: UInt64);
var Limit, At: UInt64;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed or (FLifecycle = nil) then Exit;
      { Each channel gets its own bounded window. An optional O call cannot
        consume all time available to obtain B's cleanup-only permit. }
      At := CozyTick; Limit := At + 1500;
      if DeadlineTick < Limit then Limit := DeadlineTick;
      FLifecycle.Prepare('B', FSession.SessionID, FSession.SessionToken, Limit);
      At := CozyTick; Limit := At + 1500;
      if DeadlineTick < Limit then Limit := DeadlineTick;
      FLifecycle.Prepare('O', FSession.SessionID, FSession.SessionToken, Limit);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TOverlayClient.GetLeaseDeadlineTick: UInt64;
begin
  TMonitor.Enter(FLock);
  try Result := FLeaseDeadlineTick;
  finally TMonitor.Exit(FLock); end;
end;

function TOverlayClient.GetLeaseRequestTick: UInt64;
begin
  TMonitor.Enter(FLock);
  try Result := FLeaseRequestTick;
  finally TMonitor.Exit(FLock); end;
end;

function TOverlayClient.Claim(const OverlayID, Ticket, Canonical: string;
      Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity): TBootstrapSession;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Overlay_Client_CLIENT_CLOSED_ee7ae48d);
      Result := ClaimCore(OverlayID, Ticket, Canonical, Security, CodeIntegrity);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

procedure TOverlayClient.ReportIntegrity(Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
      const Image: TImageDigest; IncludeModules: Boolean;
      const Cancelled: TModuleInventoryCancelled; FailureStatus: TMeasurementStatus; OwnImage: TImageIntegrity;
      const MaintainLease: TProc<Boolean>);
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Overlay_Client_CLIENT_CLOSED_ee7ae48d);
      ReportIntegrityCore(Security, CodeIntegrity, Image, IncludeModules, Cancelled, FailureStatus, OwnImage, MaintainLease);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TOverlayClient.Verify(Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
      const Image: TImageDigest;
      const Cancelled: TModuleInventoryCancelled): Int64;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Overlay_Client_CLIENT_CLOSED_ee7ae48d);
      Result := VerifyCore(Security, CodeIntegrity, Image, Cancelled);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

procedure TOverlayClient.ReadProductScope(Reply: TJSONObject);
var Value: TJSONValue; Product: string;
begin
  if BootstrapInteger(Reply, CozyText_Overlay_Client_productScopeVersion_86736c8d) <> 1 then InvalidResponse;
  Value := Reply.GetValue(CozyText_Overlay_Client_productId_5733207c);
  if not (Value is TJSONString) then InvalidResponse;
  Product := Value.Value;
  if (Product <> '') and (OverlayProductCard(Product) < 0) then InvalidResponse;
  { A claimed license cannot silently change products during renewal. }
  if FProductScopeKnown and (Product <> FProductID) then InvalidResponse;
  FProductID := Product; FProductScopeKnown := True;
end;

function TOverlayClient.GetProductCard: Integer;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      Result := -1;
      if not FClosed then Result := OverlayProductCard(FProductID);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TOverlayClient.AuthorizeProductStart(Security: TDeviceSecurity;
  Card: Integer; const Cancelled: TModuleInventoryCancelled): UInt64;
var Body, Reply: TJSONObject; RequestID, Canonical, Product: string;
  Started, GrantDeadline: UInt64; ServerTime, ExpiresAt, Remaining: Int64;
  procedure RequireCurrent;
  begin
    if FClosed or FGate.IsClosing or (Assigned(Cancelled) and Cancelled()) then
      raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_START_CANCELLED_f23bf6b7);
    if not FTransferConfirmed or (FLeaseDeadlineTick <= CozyTick) or
      not OverlayProductCanStart(OverlayProductCard(FProductID), Card) then
      raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_PRODUCT_NOT_LICENSED_2a1df234);
  end;
begin
  Body := nil; Reply := nil;
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      RequireCurrent;
      if FStartSequence = High(Integer) then
        raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_START_SEQUENCE_EXHAUSTED_2289569a);
      Inc(FStartSequence); { monotonic; skipped requests cannot revive old grants }
      Product := OverlayProductID(Card);
      RequestID := BootstrapRequestID;
      Canonical := CozyText_Overlay_Client_COZY_OVERLAY_START_V1_6238ee97 + #10 + FSession.SessionID + #10 +
        Product + #10 + RequestID + #10 + IntToStr(FStartSequence);
      Body := TJSONObject.Create;
      Body.AddPair(CozyText_Overlay_Client_sessionId_3c9f1b20, FSession.SessionID);
      Body.AddPair(CozyText_Overlay_Client_sessionToken_1e6f5a77, FSession.SessionToken);
      Body.AddPair(CozyText_Overlay_Client_productId_5733207c, Product);
      Body.AddPair(CozyText_Overlay_Client_requestId_6bd4037d, RequestID);
      Body.AddPair(CozyText_Overlay_Client_sequence_391623a6, TJSONNumber.Create(FStartSequence));
      Body.AddPair(CozyText_Overlay_Client_signature_3b2323b0, Security.Sign(Canonical));
      Started := CozyTick;
      Reply := Post(CozyText_Overlay_Client_overlayStart_27f8a946, Body, FLeaseDeadlineTick);
      RequireCurrent;
      BootstrapValidateObject(Reply,
        CozyText_Overlay_Client_version_sessionId_productId_requestId_sequence_s_a200ebb0, 9);
      if (BootstrapInteger(Reply, CozyText_Overlay_Client_version_2c126698) <> 1) or
        (BootstrapString(Reply, CozyText_Overlay_Client_sessionId_3c9f1b20, 24) <> FSession.SessionID) or
        (BootstrapString(Reply, CozyText_Overlay_Client_productId_5733207c, 64) <> Product) or
        (BootstrapString(Reply, CozyText_Overlay_Client_requestId_6bd4037d, 80) <> RequestID) or
        (BootstrapInteger(Reply, CozyText_Overlay_Client_sequence_391623a6) <> FStartSequence) or
        (BootstrapString(Reply, CozyText_Overlay_Client_status_2aa55de1, 16) <> CozyText_Overlay_Client_AUTHORIZED_c6818a7e) or
        (BootstrapInteger(Reply, CozyText_Overlay_Client_durationMs_1466259b) <> 5000) then InvalidResponse;
      ServerTime := BootstrapInteger(Reply, CozyText_Overlay_Client_serverTime_64c90dcb);
      ExpiresAt := BootstrapInteger(Reply, CozyText_Overlay_Client_expiresAt_9fb7f3ca);
      Remaining := ExpiresAt - ServerTime;
      if (Remaining <= 0) or (Remaining > 30000) or
        (Started > High(UInt64) - UInt64(Remaining)) then InvalidResponse;
      GrantDeadline := Started + UInt64(Remaining);
      if FLeaseDeadlineTick < GrantDeadline then GrantDeadline := FLeaseDeadlineTick;
      if GrantDeadline <= CozyTick then
        raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_START_AUTHORIZATION_EXPIRED_9770346b);
      Result := GrantDeadline;
    finally
      Reply.Free; Body.Free;
      WipeText(Canonical);
      TMonitor.Exit(FLock);
    end;
  finally FGate.Leave; end;
end;

function TOverlayClient.InvokeServerPolicy(Security: TDeviceSecurity;
  CodeIntegrity: TCodeIntegrity; const Image: TImageDigest; FunctionID: Word;
  const Args: array of Integer; const Cancelled: TModuleInventoryCancelled): Integer;
var LocalArgs: TArray<Integer>; OperationCancelled: TModuleInventoryCancelled;
  Value: Integer;
  procedure RequirePolicyContext;
  begin
    if FClosed or FGate.IsClosing then raise EBootstrap.Create(CozyText_Overlay_Client_CLIENT_CLOSED_ee7ae48d);
    if Assigned(Cancelled) and Cancelled() then
      raise EBootstrap.Create(CozyText_Overlay_Client_COZY_SERVER_OPERATION_CANCELLED_cd7e204c);
    if (FSession.SessionID = '') or (FLeaseDeadlineTick <= CozyTick) then
      raise EBootstrap.Create(CozyText_Overlay_Client_OVERLAY_LEASE_EXPIRED_9b53a056);
  end;
begin
  LocalArgs := SnapshotServerOperationArgs(FunctionID, Args);
  try
    FGate.Enter;
    try
      TMonitor.Enter(FLock);
      try
        RequirePolicyContext;
        if FOwnImage = nil then raise EBootstrap.Create(CozyText_Overlay_Client_COZY_SERVER_OPERATION_IMAGE_REQUIRED_f816debd);
        OperationCancelled :=
          function: Boolean
          begin
            Result := FGate.IsClosing or (FLeaseDeadlineTick <= CozyTick) or
              (Assigned(Cancelled) and Cancelled());
          end;
        ReportIntegrityCore(Security, CodeIntegrity, Image, False,
          OperationCancelled, msMeasured, FOwnImage);
        RequirePolicyContext;
        Value := InvokeCozyServerOperation(FTransport, Security, CodeIntegrity, 'O',
          FSession.SessionID, FSession.SessionToken, Image.SHA512, Image.CRC64,
          FunctionID, LocalArgs,
          function: Boolean
          begin Result := OperationCancelled(); end, FOwnImage, OwnRuntime(Security, CodeIntegrity));
        RequirePolicyContext;
        Result := Value;
      finally TMonitor.Exit(FLock); end;
    finally FGate.Leave; end;
  finally
    OperationCancelled := nil;
    ClearServerOperationArgs(LocalArgs);
  end;
end;

procedure TOverlayClient.CancelPending;
begin
  if FTransport <> nil then FTransport.CancelPending;
end;
class procedure TOverlayClient.CloseSessionSnapshot(Profile: TConnectServerProfile;
  const Session: TBootstrapSession; DeadlineTick, JoinElapsedMs: UInt64);
var Closing: TOverlayClient;
begin
  { A blocked worker may own its client's lock/transport. Use a separate
    bounded transport and the already-claimed session, never free or enter
    worker-owned objects. Server Close revokes further renewals atomically. }
  if Session.SessionID = '' then Exit;
  Closing := TOverlayClient.Create(Profile);
  try
    Closing.FSession := Session;
    Closing.FCloseDeadline := DeadlineTick;
    Closing.FShutdownDiagnostics := True;
    Closing.FShutdownJoinElapsed := JoinElapsedMs;
    Closing.FShutdownJoinMissed := True;
    Closing.CloseCore;
  finally Closing.Free; end;
end;

procedure TOverlayClient.RetireOwnImageForShutdown;
begin
  FGate.CloseAndWait;
  try
    if FRuntimeGraph <> nil then FRuntimeGraph.RetireDependency(5);
  finally FOwnImage := nil; end;
end;

procedure TOverlayClient.ShutdownClose(DeadlineTick: UInt64; JoinElapsedMs: UInt64; JoinBudgetMissed: Boolean);
begin
  { Caller has joined its worker. Closing admission prevents a new operation
    while this last server Close spends only the remainder of the same budget. }
  FGate.CloseAndWait;
  if FClosed then Exit;
  FCloseDeadline := DeadlineTick;
  FShutdownDiagnostics := True; FShutdownJoinElapsed := JoinElapsedMs;
  FShutdownJoinMissed := JoinBudgetMissed;
  FTransport.ResetCancellationAfterJoin;
  CloseCore;
end;

procedure TOverlayClient.Close;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then Exit;
      CloseCore;
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

procedure TOverlayClient.CommitTransfer(Security: TDeviceSecurity;
      const ParentSessionID, ParentSessionToken, OverlayID: string);
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Overlay_Client_CLIENT_CLOSED_ee7ae48d);
      CommitTransferCore(Security, ParentSessionID, ParentSessionToken, OverlayID);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TOverlayClient.AbortChild(Security: TDeviceSecurity; const ParentSessionID,
      ParentSessionToken, OverlayID, PrepareRequestID: string; SecurityStop: Boolean): Boolean;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Overlay_Client_CLIENT_CLOSED_ee7ae48d);
      Result := AbortChildCore(Security, ParentSessionID, ParentSessionToken, OverlayID, PrepareRequestID, SecurityStop);
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TOverlayClient.GetSession: TBootstrapSession;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Overlay_Client_CLIENT_CLOSED_ee7ae48d);
      Result := GetSessionCore;
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TOverlayClient.GetTransferConfirmed: Boolean;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Overlay_Client_CLIENT_CLOSED_ee7ae48d);
      Result := GetTransferConfirmedCore;
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

function TOverlayClient.GetCapturePrivacy: Boolean;
begin
  FGate.Enter;
  try
    TMonitor.Enter(FLock);
    try
      if FClosed then raise EBootstrap.Create(CozyText_Overlay_Client_CLIENT_CLOSED_ee7ae48d);
      Result := FCapturePrivacy;
    finally TMonitor.Exit(FLock); end;
  finally FGate.Leave; end;
end;

initialization
  { API binding only; original startup actions follow unchanged. }

  BindApiPointer(ApiSlot_CloseHandle, RequireProcAddressHash64(CozyText_Overlay_Client_kernel32_dll_2a5268a1, HASH_CloseHandle));
  BindApiPointer(ApiSlot_CreateFileW, RequireProcAddressHash64(CozyText_Overlay_Client_kernel32_dll_2a5268a1, HASH_CreateFileW));
  BindApiPointer(ApiSlot_GetFileInformationByHandle, RequireProcAddressHash64(CozyText_Overlay_Client_kernel32_dll_2a5268a1, HASH_GetFileInformationByHandle));
  BindApiPointer(ApiSlot_GetFileType, RequireProcAddressHash64(CozyText_Overlay_Client_kernel32_dll_2a5268a1, HASH_GetFileType));
  BindApiPointer(ApiSlot_WriteFile, RequireProcAddressHash64(CozyText_Overlay_Client_kernel32_dll_2a5268a1, HASH_WriteFile));
  BindApiPointer(ApiSlot_FlushFileBuffers, RequireProcAddressHash64(CozyText_Overlay_Client_kernel32_dll_2a5268a1, HASH_FlushFileBuffers));
  BindApiPointer(ApiSlot_LauncherSetFileInformationByHandle, RequireProcAddressHash64(CozyText_Overlay_Client_kernel32_dll_2a5268a1, HASH_SetFileInformationByHandle));

end.
