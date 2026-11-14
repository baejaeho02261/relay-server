unit Cozy.Handoff;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Handoff,
{$IF (Defined(GAME_HANDOFF_CONTRACT_TESTS))}
  Cozy.Strings.TestsHandoff,
{$ENDIF}

  Winapi.Windows, System.SysUtils, Cozy.Security, Cozy.Lifetime,
  Cozy.Server.Profile, Cozy.Integrity, Cozy.CodeIntegrity;

type
  EHandoff = class(Exception);
  { O-only opt-in privilege reduction. Default remains compatibility mode. }
  THandoffLaunchProfile = (hlpInherit, hlpOverlayRestricted);
  THandoffCleanupObservation = record
    ProcessID, Win32Error: Cardinal;
    ExitObserved, ExitTimedOut, CleanupAttempted,
      DispositionAccepted, FileRemoved: Boolean;
  end;

  { Owns Profile and Security until the caller explicitly transfers them by
    assigning nil. Only the numeric pipe handle goes in argv. Public hello
    travels over a second restricted inherited pipe; the grant and context
    use one-use AES-GCM with a fresh child RSA-OAEP wrapping key. }
  THandoffContext = class
  private
    FGate: TGameCallGate;
    FOverlay: Boolean;
    FReadyEvent: THandle;
    FParentProcess: THandle;
    FParentID: DWORD;
    FParentImage: THandle;
    FParentPins: TArray<THandle>;
    FParentRetired: Boolean;
    FLauncherPath: string;
    FBinaryPath: string;
    FLauncherVolume: DWORD;
    FLauncherIndexHigh: DWORD;
    FLauncherIndexLow: DWORD;
    FCompleted: Boolean;
    FBinaryCleanupFile: THandle;
    FBinaryCleanupInfo: TByHandleFileInformation;
    FBinaryCleanupAttempted: Boolean;
    FImageIntegrity: TImageIntegrity;
    FParentObservation, FOwnObservation: THandoffCleanupObservation;
    class function ReceiveRole(OverlayRole: Boolean): THandoffContext; static;
    procedure CompleteOverlayClaimCore(const ExpectedCRC64: string);
    procedure ConfirmOverlayReadyCore;
    procedure CleanupTransferredParentCore;
    function ParentIsAliveCore: Boolean;
    procedure CompleteClaimAndCleanupCore(const ExpectedCRC64: string);
    procedure CleanupBinaryAfterLicenseCore;
    function TakeImageIntegrityCore: TImageIntegrity;
  public
    { Console/Overlay owners stop and join their worker before Free. Public
      ownership-transfer fields are main-owner only; admitted methods drain
      before handles/keys are freed. This cannot validate freed pointers. }
    Profile: TConnectServerProfile;
    Security: TDeviceSecurity;
    CodeIntegrity: TCodeIntegrity;
    FlowID: string;
    HandoffToken: string;
    ClaimCanonical: string;
    LauncherSHA512: string;
    BinarySHA512: string;
    { Derived from the held, verified parent image and process creation time. }
    ParentIdentity: string;
    constructor Create;
    class function ReceiveFromCommandLine: THandoffContext; static;
    class function ReceiveOverlayFromCommandLine: THandoffContext; static;
    procedure CompleteOverlayClaim(const ExpectedCRC64: string);
    procedure ConfirmOverlayReady;
    { Call only after O has independently confirmed server ownership transfer. }
    procedure CleanupTransferredParent;
    function ParentIsAlive: Boolean;
    { The caller MUST first finish the authenticated, one-use server claim.
      Returning means A exit was observed and its delete disposition accepted.
      ParentCleanupObservation.FileRemoved separately records observed removal.
      B integrity was verified; B remains on disk while the user enters a KEY. }
    procedure CompleteClaimAndCleanup(const ExpectedCRC64: string);
    { Call only after successful KEY redemption with a live server lease, on
      the same worker that owns API/held-image reads. OS refusal is nonfatal. }
    procedure CleanupBinaryAfterLicense;
    function TakeImageIntegrity: TImageIntegrity;
    function ParentCleanupObservation: THandoffCleanupObservation;
    function OwnCleanupObservation: THandoffCleanupObservation;
    { Owner-only after joining workers and releasing integrity readers. }
    procedure CleanupOwnImageForShutdown;
    destructor Destroy; override;
  end;

{ Removes only this process's verified image. Requires a regular, single-link
  file, unchanged SHA-512, and pinned non-reparse ancestors. Windows or the
  filesystem may refuse active-image POSIX deletion; callers fail closed. }
procedure RemoveOwnImage(const ExpectedSHA512: string;
  const ExpectedInfo: TByHandleFileInformation);

{$IFDEF GAME_HANDOFF_CONTRACT_TESTS}
function RunHandoffPipeContracts: Integer;
function RunHandoffProcessContracts: Integer;
function TryRunHandoffProcessChild: Boolean;
{$ENDIF}

function IsHandoffCommandLine: Boolean;
function LaunchWithHandoff(const BinaryPath: string;
  Profile: TConnectServerProfile; Security: TDeviceSecurity;
  const FlowID, HandoffToken, ClaimCanonical, LauncherSHA512,
  BinarySHA512: string; PreserveParent: Boolean = False;
  LaunchProfile: THandoffLaunchProfile = hlpInherit;
  const MaintainParent: TProc = nil): Boolean;

implementation

uses Cozy.Clock,
  System.Classes,
  Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer, Cozy.Api.Contracts,
  Cozy.Handoff.Crypto, Cozy.Handoff.Restricted, Cozy.NHW.Context
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
  , Cozy.ProductFaults
{$ENDIF}
  ;

{ Private API pointers: initialized before application code starts. }
var

  ApiSlot_GetCurrentProcessId: TEncodedApiPointer;
  ApiSlot_GetLastError: TEncodedApiPointer;
  ApiSlot_CloseHandle: TEncodedApiPointer;
  ApiSlot_CreateEventW: TEncodedApiPointer;
  ApiSlot_SetEvent: TEncodedApiPointer;
  ApiSlot_WaitForSingleObject: TEncodedApiPointer;
  ApiSlot_WaitForMultipleObjects: TEncodedApiPointer;

  ApiSlot_CreateFileW: TEncodedApiPointer;
  ApiSlot_GetFileInformationByHandle: TEncodedApiPointer;
  ApiSlot_GetFileType: TEncodedApiPointer;
  ApiSlot_GetFileAttributesW: TEncodedApiPointer;
  ApiSlot_GetFullPathNameW: TEncodedApiPointer;
  ApiSlot_ReadFile: TEncodedApiPointer;
  ApiSlot_WriteFile: TEncodedApiPointer;
  ApiSlot_CreatePipe: TEncodedApiPointer;
  ApiSlot_PeekNamedPipe: TEncodedApiPointer;
  ApiSlot_GetHandleInformation: TEncodedApiPointer;
  ApiSlot_SetHandleInformation: TEncodedApiPointer;
  ApiSlot_DuplicateHandle: TEncodedApiPointer;
  ApiSlot_CreateProcessW: TEncodedApiPointer;
  ApiSlot_GetProcessId: TEncodedApiPointer;
  ApiSlot_GetExitCodeThread: TEncodedApiPointer;
  ApiSlot_TerminateProcess: TEncodedApiPointer;
  ApiSlot_MultiByteToWideChar: TEncodedApiPointer;


type
  TResolved_GetEnvironmentVariableW = function(Name, Buffer: PWideChar;
    Size: DWORD): DWORD; stdcall;
var
  ApiSlot_GetEnvironmentVariableW: TEncodedApiPointer;

{$ALIGN 8}
{$B-}

const
  { Windows SDK FILE_FLAG_OPEN_REPARSE_POINT; preserve no-follow validation. }
  OpenReparsePointFlag: DWORD = $00200000;
  MaxHandoffBytes = 65536;
  HandoffTimeoutMS = 45000;
  { O initializes a hidden GPU device, measures modules and obtains its own
    server authorization. This bounds only the parent's readiness wait;
    server session/license expiry and all child checks remain independent. }
  OverlayReadyTimeoutMS = 110000;
  PipeWriteTimeoutMS = 10000;
  ParentExitTimeoutMS = 10000;
  HandoffMagic: UInt64 = $31464F444E41484D;
  HandoffVersion = 3;
  HandshakeMagic: UInt64 = $335348444E414847;
  HelloMagic: UInt64 = $334F4C4C4548474D;
  UnicodeEnvironmentFlag = $00000400;
  AttributeHandleList = $00020002;
  ExtendedStartupInfoPresent = $00080000;
  ProcessQueryLimitedInformation = $00001000;
  DeleteAccess = $00010000;
  FileDispositionInfoClass = 4;
  FileDispositionInfoExClass = 21;
  FileDispositionDelete: DWORD = $00000001;
  FileDispositionPOSIXSemantics: DWORD = $00000002;
  FieldCount = 11;
  FieldProfile = 0;
  FieldFlow = 1;
  FieldToken = 2;
  FieldClaim = 3;
  FieldLauncherHash = 4;
  FieldBinaryHash = 5;
  FieldLauncherPath = 6;
  FieldBinaryPath = 7;
  FieldParentDeviceID = 8;
  FieldChildNonce = 9;
  FieldDelegation = 10;

type
  THandleArray = TArray<THandle>;
  TWireHeader = packed record
    Magic: UInt64;
    Version: DWORD;
    TotalBytes: DWORD;
    ComponentRole: DWORD;
    ReadyEvent: UInt64;
    ParentProcess: UInt64;
    ParentID: DWORD;
    LauncherVolume: DWORD;
    LauncherIndexHigh: DWORD;
    LauncherIndexLow: DWORD;
    Sizes: array[0..FieldCount - 1] of DWORD;
  end;
  TStartupInfoExLocal = TGameStartupInfoEx;
  THandshakeHeader = packed record
    Magic: UInt64;
    Version, ComponentRole: DWORD;
    ReplyPipe: UInt64;
  end;
  TChildHelloHeader = packed record
    Magic: UInt64;
    Version, ComponentRole, SigningBytes, WrappingBytes: DWORD;
    Nonce: array[0..63] of Byte;
  end;
  { FILE_DISPOSITION_INFO has one BOOLEAN (one byte), not a Win32 BOOL. }
  TFileDispositionInfoLocal = TGameFileDispositionInfo;
  TFileDispositionInfoExLocal = TGameFileDispositionInfoEx;
  TPipeWriter = class
    Pipe: THandle;
    CancelEvent: THandle;
    Bytes: TBytes;
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
    FaultStage: string;
    ChildPID: DWORD;
{$ENDIF}
    destructor Destroy; override;
  end;

type
  TResolved_InitializeAttributeList = function(List: Pointer; Count, Flags: DWORD;
  var Size: NativeUInt): BOOL; stdcall;
var
  ApiSlot_InitializeAttributeList: TEncodedApiPointer;
type
  TResolved_UpdateAttribute = function(List: Pointer; Flags: DWORD; Attribute: NativeUInt;
  Value: Pointer; Size: NativeUInt; Previous: Pointer;
  ReturnSize: Pointer): BOOL; stdcall;
var
  ApiSlot_UpdateAttribute: TEncodedApiPointer;
type
  TResolved_DeleteAttributeList = procedure(List: Pointer); stdcall;
var
  ApiSlot_DeleteAttributeList: TEncodedApiPointer;
type
  TResolved_QueryImagePath = function(Process: THandle; Flags: DWORD; Path: PWideChar;
  var Size: DWORD): BOOL; stdcall;
var
  ApiSlot_QueryImagePath: TEncodedApiPointer;
type
  TResolved_FinalPathByHandle = function(FileHandle: THandle; Path: PWideChar;
  Size, Flags: DWORD): DWORD; stdcall;
var
  ApiSlot_FinalPathByHandle: TEncodedApiPointer;
type
  TResolved_SetFileInfo = function(FileHandle: THandle; InfoClass: Integer;
  Info: Pointer; Size: DWORD): BOOL; stdcall;
var
  ApiSlot_SetFileInfo: TEncodedApiPointer;
type
  TResolved_CancelThreadIO = function(Thread: THandle): BOOL; stdcall;
var
  ApiSlot_CancelThreadIO: TEncodedApiPointer;

{ POINTER WRAPPERS 1 BEGIN }

function GetCurrentProcess: THandle; stdcall;
begin
  { Documented Windows current-process pseudo-handle. No lookup, syscall,
    foreign-process access or dependency on undocumented TEB offsets. }
  Result := THandle(NativeInt(-1));
end;

function GetCurrentProcessId: DWORD; stdcall;
var
  ApiTarget: TApiGetCurrentProcessId;
begin
  ApiTarget := TApiGetCurrentProcessId(DecodeApiPointer(ApiSlot_GetCurrentProcessId));
  Result := ApiTarget();
end;

function GetLastError: DWORD; stdcall;
var
  ApiTarget: TApiGetLastError;
begin
  ApiTarget := TApiGetLastError(DecodeApiPointer(ApiSlot_GetLastError));
  Result := ApiTarget();
end;

function CloseHandle(Handle: THandle): BOOL; stdcall;
var
  ApiTarget: TApiCloseHandle;
begin
  ApiTarget := TApiCloseHandle(DecodeApiPointer(ApiSlot_CloseHandle));
  Result := ApiTarget(Handle);
end;

function CreateEventW(Attributes: PSecurityAttributes; ManualReset, InitialState: BOOL;
    Name: PWideChar): THandle; stdcall;
var
  ApiTarget: TApiCreateEventW;
begin
  ApiTarget := TApiCreateEventW(DecodeApiPointer(ApiSlot_CreateEventW));
  Result := ApiTarget(Attributes, ManualReset, InitialState, Name);
end;

function SetEvent(Event: THandle): BOOL; stdcall;
var
  ApiTarget: TApiSetEvent;
begin
  ApiTarget := TApiSetEvent(DecodeApiPointer(ApiSlot_SetEvent));
  Result := ApiTarget(Event);
end;

function WaitForSingleObject(Handle: THandle; Milliseconds: DWORD): DWORD; stdcall;
var
  ApiTarget: TApiWaitForSingleObject;
begin
  ApiTarget := TApiWaitForSingleObject(DecodeApiPointer(ApiSlot_WaitForSingleObject));
  Result := ApiTarget(Handle, Milliseconds);
end;

function WaitForMultipleObjects(Count: DWORD; Handles: Pointer; WaitAll: BOOL;
    Milliseconds: DWORD): DWORD; stdcall;
var
  ApiTarget: TApiWaitForMultipleObjects;
begin
  ApiTarget := TApiWaitForMultipleObjects(DecodeApiPointer(ApiSlot_WaitForMultipleObjects));
  Result := ApiTarget(Count, Handles, WaitAll, Milliseconds);
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

function GetFileAttributesW(FileName: PWideChar): DWORD; stdcall;
var
  ApiTarget: TApiGetFileAttributesW;
begin
  ApiTarget := TApiGetFileAttributesW(DecodeApiPointer(ApiSlot_GetFileAttributesW));
  Result := ApiTarget(FileName);
end;

function GetFullPathNameW(FileName: PWideChar; BufferLength: DWORD; Buffer: PWideChar;
    var FilePart: PWideChar): DWORD; stdcall;
var
  ApiTarget: TApiGetFullPathNameW;
begin
  ApiTarget := TApiGetFullPathNameW(DecodeApiPointer(ApiSlot_GetFullPathNameW));
  Result := ApiTarget(FileName, BufferLength, Buffer, FilePart);
end;

function ReadFile(Handle: THandle; var Buffer; Count: DWORD; var BytesRead: DWORD;
    Overlapped: POverlapped): BOOL; stdcall;
var
  ApiTarget: TApiReadFile;
begin
  ApiTarget := TApiReadFile(DecodeApiPointer(ApiSlot_ReadFile));
  Result := ApiTarget(Handle, Buffer, Count, BytesRead, Overlapped);
end;

function WriteFile(Handle: THandle; const Buffer; Count: DWORD; var BytesWritten: DWORD;
    Overlapped: POverlapped): BOOL; stdcall;
var
  ApiTarget: TApiWriteFile;
begin
  ApiTarget := TApiWriteFile(DecodeApiPointer(ApiSlot_WriteFile));
  Result := ApiTarget(Handle, Buffer, Count, BytesWritten, Overlapped);
end;

function CreatePipe(var ReadPipe, WritePipe: THandle; Attributes: PSecurityAttributes;
    Size: DWORD): BOOL; stdcall;
var
  ApiTarget: TApiCreatePipe;
begin
  ApiTarget := TApiCreatePipe(DecodeApiPointer(ApiSlot_CreatePipe));
  Result := ApiTarget(ReadPipe, WritePipe, Attributes, Size);
end;

function PeekNamedPipe(Pipe: THandle; Buffer: Pointer; BufferSize: DWORD;
    BytesRead, TotalAvailable, BytesLeft: PDWORD): BOOL; stdcall;
var
  ApiTarget: TApiPeekNamedPipe;
begin
  ApiTarget := TApiPeekNamedPipe(DecodeApiPointer(ApiSlot_PeekNamedPipe));
  Result := ApiTarget(Pipe, Buffer, BufferSize, BytesRead, TotalAvailable, BytesLeft);
end;

function GetHandleInformation(Handle: THandle; var Flags: DWORD): BOOL; stdcall;
var
  ApiTarget: TApiGetHandleInformation;
begin
  ApiTarget := TApiGetHandleInformation(DecodeApiPointer(ApiSlot_GetHandleInformation));
  Result := ApiTarget(Handle, Flags);
end;

function SetHandleInformation(Handle: THandle; Mask, Flags: DWORD): BOOL; stdcall;
var
  ApiTarget: TApiSetHandleInformation;
begin
  ApiTarget := TApiSetHandleInformation(DecodeApiPointer(ApiSlot_SetHandleInformation));
  Result := ApiTarget(Handle, Mask, Flags);
end;

function DuplicateHandle(SourceProcess, SourceHandle, TargetProcess: THandle; TargetHandle: PHandle;
    DesiredAccess: DWORD; InheritHandle: BOOL; Options: DWORD): BOOL; stdcall;
var
  ApiTarget: TApiDuplicateHandle;
begin
  ApiTarget := TApiDuplicateHandle(DecodeApiPointer(ApiSlot_DuplicateHandle));
  Result := ApiTarget(SourceProcess, SourceHandle, TargetProcess, TargetHandle, DesiredAccess, InheritHandle, Options);
end;

function CreateProcessW(ApplicationName, CommandLine: PWideChar;
    ProcessAttributes, ThreadAttributes: PSecurityAttributes; InheritHandles: BOOL; CreationFlags: DWORD;
    Environment: Pointer; CurrentDirectory: PWideChar; var StartupInfo: TStartupInfo;
    var ProcessInformation: TProcessInformation): BOOL; stdcall;
var
  ApiTarget: TApiCreateProcessW;
begin
  ApiTarget := TApiCreateProcessW(DecodeApiPointer(ApiSlot_CreateProcessW));
  Result := ApiTarget(ApplicationName, CommandLine, ProcessAttributes, ThreadAttributes, InheritHandles, CreationFlags, Environment, CurrentDirectory, StartupInfo, ProcessInformation);
end;

function GetProcessId(Process: THandle): DWORD; stdcall;
var
  ApiTarget: TApiGetProcessId;
begin
  ApiTarget := TApiGetProcessId(DecodeApiPointer(ApiSlot_GetProcessId));
  Result := ApiTarget(Process);
end;

function GetExitCodeThread(Thread: THandle; var ExitCode: DWORD): BOOL; stdcall;
var
  ApiTarget: TApiGetExitCodeThread;
begin
  ApiTarget := TApiGetExitCodeThread(DecodeApiPointer(ApiSlot_GetExitCodeThread));
  Result := ApiTarget(Thread, ExitCode);
end;

function TerminateProcess(Process: THandle; ExitCode: UINT): BOOL; stdcall;
var
  ApiTarget: TApiTerminateProcess;
begin
  ApiTarget := TApiTerminateProcess(DecodeApiPointer(ApiSlot_TerminateProcess));
  Result := ApiTarget(Process, ExitCode);
end;

function MultiByteToWideChar(CodePage: UINT; Flags: DWORD; Input: PAnsiChar; InputLength: Integer;
    Output: PWideChar; OutputLength: Integer): Integer; stdcall;
var
  ApiTarget: TApiMultiByteToWideChar;
begin
  ApiTarget := TApiMultiByteToWideChar(DecodeApiPointer(ApiSlot_MultiByteToWideChar));
  Result := ApiTarget(CodePage, Flags, Input, InputLength, Output, OutputLength);
end;

function InitializeAttributeList(List: Pointer; Count, Flags: DWORD;
  var Size: NativeUInt): BOOL; stdcall;
var
  ApiTarget: TResolved_InitializeAttributeList;
begin
  ApiTarget := TResolved_InitializeAttributeList(DecodeApiPointer(ApiSlot_InitializeAttributeList));
  Result := ApiTarget(List, Count, Flags, Size);
end;

function UpdateAttribute(List: Pointer; Flags: DWORD; Attribute: NativeUInt;
  Value: Pointer; Size: NativeUInt; Previous: Pointer;
  ReturnSize: Pointer): BOOL; stdcall;
var
  ApiTarget: TResolved_UpdateAttribute;
begin
  ApiTarget := TResolved_UpdateAttribute(DecodeApiPointer(ApiSlot_UpdateAttribute));
  Result := ApiTarget(List, Flags, Attribute, Value, Size, Previous, ReturnSize);
end;

procedure DeleteAttributeList(List: Pointer); stdcall;
var
  ApiTarget: TResolved_DeleteAttributeList;
begin
  ApiTarget := TResolved_DeleteAttributeList(DecodeApiPointer(ApiSlot_DeleteAttributeList));
  ApiTarget(List);
end;

function QueryImagePath(Process: THandle; Flags: DWORD; Path: PWideChar;
  var Size: DWORD): BOOL; stdcall;
var
  ApiTarget: TResolved_QueryImagePath;
begin
  ApiTarget := TResolved_QueryImagePath(DecodeApiPointer(ApiSlot_QueryImagePath));
  Result := ApiTarget(Process, Flags, Path, Size);
end;

function FinalPathByHandle(FileHandle: THandle; Path: PWideChar;
  Size, Flags: DWORD): DWORD; stdcall;
var
  ApiTarget: TResolved_FinalPathByHandle;
begin
  ApiTarget := TResolved_FinalPathByHandle(DecodeApiPointer(ApiSlot_FinalPathByHandle));
  Result := ApiTarget(FileHandle, Path, Size, Flags);
end;

function SetFileInfo(FileHandle: THandle; InfoClass: Integer;
  Info: Pointer; Size: DWORD): BOOL; stdcall;
var
  ApiTarget: TResolved_SetFileInfo;
begin
  ApiTarget := TResolved_SetFileInfo(DecodeApiPointer(ApiSlot_SetFileInfo));
  Result := ApiTarget(FileHandle, InfoClass, Info, Size);
end;

function CancelThreadIO(Thread: THandle): BOOL; stdcall;
var
  ApiTarget: TResolved_CancelThreadIO;
begin
  ApiTarget := TResolved_CancelThreadIO(DecodeApiPointer(ApiSlot_CancelThreadIO));
  Result := ApiTarget(Thread);
end;
{ POINTER WRAPPERS 1 END }

procedure Fail(const MessageText: string);
begin
  raise EHandoff.Create(MessageText);
end;

procedure Check(Success: Boolean; const MessageText: string);
begin
  if not Success then
    Fail(MessageText);
end;

procedure CheckABI;
var
  Startup: TStartupInfoExLocal;
begin
  Check((SizeOf(Pointer) = 8) and (SizeOf(TStartupInfo) = 104) and
    (SizeOf(TStartupInfoExLocal) = 112) and
    (NativeUInt(@Startup.AttributeList) - NativeUInt(@Startup) = 104) and
    (SizeOf(TWireHeader) = 96) and
    (SizeOf(THandshakeHeader) = 24) and (SizeOf(TChildHelloHeader) = 88) and (SizeOf(TFileDispositionInfoLocal) = 1) and
    (SizeOf(TFileDispositionInfoExLocal) = 4),
    CozyText_Handoff_Windows_64_9f8cb582);
end;

procedure Close(var Handle: THandle);
begin
  if (Handle <> 0) and (Handle <> INVALID_HANDLE_VALUE) then
    CloseHandle(Handle);
  Handle := 0;
end;

procedure CloseAll(var Handles: THandleArray);
var
  I: Integer;
begin
  for I := High(Handles) downto 0 do
    Close(Handles[I]);
  Handles := nil;
end;

function Remaining(Deadline: UInt64): DWORD;
var
  NowTick: UInt64;
begin
  NowTick := CozyTick;
  if NowTick >= Deadline then
    Result := 0
  else
    Result := DWORD(Deadline - NowTick);
end;

function ImagePath(Process: THandle): string;
var
  Count: DWORD;
begin
  Count := 32768;
  SetLength(Result, Count);
  Check(QueryImagePath(Process, 0, PWideChar(Result), Count),
    CozyText_Handoff_Text_f2c2b692);
  Check((Count > 0) and (Count < 32768), CozyText_Handoff_Text_0790dacf);
  SetLength(Result, Count);
end;

procedure ValidatePathText(const Path: string);
var
  I, Start: Integer;
  Part, FullPath: string;
  FilePart: PWideChar;
  Count: DWORD;
begin
  { Deliberately reject UNC, device namespaces, ADS, dot segments, and Win32
    trailing-dot/space aliases. Directory handles below reject reparse points. }
  Check((Length(Path) >= 4) and (Length(Path) < 32760),
    CozyText_Handoff_Text_0790dacf);
  Check(CharInSet(Path[1], ['A'..'Z', 'a'..'z']) and
    (Path[2] = ':') and (Path[3] = '\'),
    CozyText_Handoff_Text_2119f2e8);
  Start := 4;
  for I := 4 to Length(Path) + 1 do
  begin
    if (I <= Length(Path)) and (Path[I] <> '\') then
    begin
      Check((Ord(Path[I]) >= 32) and
        not CharInSet(Path[I], [':', '/', '"', '<', '>', '|', '?', '*']),
        CozyText_Handoff_Text_70b64acc);
      Continue;
    end;
    Part := Copy(Path, Start, I - Start);
    Check((Part <> '') and (Part <> '.') and (Part <> CozyText_Handoff_Text_4edbaa9f),
      CozyText_Handoff_Text_81460d90);
    Check(not CharInSet(Part[Length(Part)], ['.', ' ']),
      CozyText_Handoff_Text_81460d90);
    Start := I + 1;
  end;
  SetLength(FullPath, 32768);
  FilePart := nil;
  Count := GetFullPathNameW(PWideChar(Path), DWORD(Length(FullPath)),
    PWideChar(FullPath), FilePart);
  Check((Count > 0) and (Count < DWORD(Length(FullPath))),
    CozyText_Handoff_Text_c6191033);
  SetLength(FullPath, Count);
  Check(SameText(FullPath, Path), CozyText_Handoff_Text_ebbcdf1a);
end;

function HandlePath(Handle: THandle): string;
var
  Count: DWORD;
begin
  SetLength(Result, 32768);
  Count := FinalPathByHandle(Handle, PWideChar(Result), Length(Result), 0);
  Check((Count > 0) and (Count < DWORD(Length(Result))),
    CozyText_Handoff_Text_b54b72de);
  SetLength(Result, Count);
  if Copy(Result, 1, 4) = CozyText_Handoff_Text_a65e9fc3 then
    Delete(Result, 1, 4);
end;

procedure PinDirectories(const Path: string; var Pins: THandleArray);
var
  I, N: Integer;
  Directory: string;
  Handle: THandle;
  Info: TByHandleFileInformation;
begin
  ValidatePathText(Path);
  for I := 3 to Length(Path) do
  begin
    if Path[I] <> '\' then
      Continue;
    Directory := Copy(Path, 1, I);
    if I > 3 then
      SetLength(Directory, I - 1);
    { Denying write/delete sharing pins every ancestor against metadata,
      reparse, and rename changes for verification and deletion. }
    Handle := CreateFileW(PWideChar(Directory), FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ, nil, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS or OpenReparsePointFlag, 0);
    Check(Handle <> INVALID_HANDLE_VALUE, CozyText_Handoff_Text_979346f7);
    try
      Check(GetFileInformationByHandle(Handle, Info),
        CozyText_Handoff_Text_4bf4af98);
      Check(((Info.dwFileAttributes and FILE_ATTRIBUTE_REPARSE_POINT) = 0) and
        ((Info.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) <> 0),
        CozyText_Handoff_Text_bfe20937);
      Check(SameText(ExcludeTrailingPathDelimiter(HandlePath(Handle)),
        ExcludeTrailingPathDelimiter(Directory)),
        CozyText_Handoff_Text_8950df3f);
      N := Length(Pins);
      SetLength(Pins, N + 1);
      Pins[N] := Handle;
      Handle := 0;
    finally
      Close(Handle);
    end;
  end;
end;

function OpenSafeImage(const Path: string; DeletePermission: Boolean;
  out Info: TByHandleFileInformation; AllowReadFallback: Boolean = False;
  AllowPinnedDeleteRead: Boolean = False; NativeError: PCardinal = nil): THandle;
var
  Access, ShareMode: DWORD;
begin
  Check(not (DeletePermission and AllowPinnedDeleteRead),
    CozyText_Handoff_Pinned_image_sharing_is_read_only_dde66996);
  Access := GENERIC_READ;
  ShareMode := FILE_SHARE_READ;
  { B holds its exact image with DELETE access for license cleanup. Its
    independent integrity reader and O parent reads must coexist with that pin.
    The original handle still denies new DELETE/write opens and replacement. }
  if AllowPinnedDeleteRead then ShareMode := ShareMode or FILE_SHARE_DELETE;
  if DeletePermission then
    Access := Access or DeleteAccess;
  Result := CreateFileW(PWideChar(Path), Access, ShareMode,
    nil, OPEN_EXISTING, OpenReparsePointFlag or FILE_FLAG_SEQUENTIAL_SCAN, 0);
  { Active-image DELETE access is not available on every Windows/filesystem.
    Read fallback is opt-in for the already authenticated B only. It still
    passes every identity, path, link, and hash check before console startup. }
  if (Result = INVALID_HANDLE_VALUE) and DeletePermission and AllowReadFallback then
    Result := CreateFileW(PWideChar(Path), GENERIC_READ, ShareMode,
      nil, OPEN_EXISTING, OpenReparsePointFlag or FILE_FLAG_SEQUENTIAL_SCAN, 0);
  if (Result = INVALID_HANDLE_VALUE) and (NativeError <> nil) then NativeError^ := GetLastError;
  Check(Result <> INVALID_HANDLE_VALUE, CozyText_Handoff_Text_5a82a889);
  try
    Check(GetFileType(Result) = FILE_TYPE_DISK, CozyText_Handoff_Text_65a263d5);
    Check(GetFileInformationByHandle(Result, Info), CozyText_Handoff_Text_94669c37);
    Check((Info.dwFileAttributes and
      (FILE_ATTRIBUTE_REPARSE_POINT or FILE_ATTRIBUTE_DIRECTORY)) = 0,
      CozyText_Handoff_Text_1908b783);
    Check((Info.nNumberOfLinks = 1) and
      ((Info.nFileIndexHigh <> 0) or (Info.nFileIndexLow <> 0)),
      CozyText_Handoff_Text_9ceaeb61);
    Check(SameText(HandlePath(Result), Path), CozyText_Handoff_Text_0e151eab);
  except
    Close(Result);
    raise;
  end;
end;

function SameIdentity(const A, B: TByHandleFileInformation): Boolean;
begin
  Result := (A.dwVolumeSerialNumber = B.dwVolumeSerialNumber) and
    (A.nFileIndexHigh = B.nFileIndexHigh) and (A.nFileIndexLow = B.nFileIndexLow);
end;

function HashHandle(Handle: THandle): string;
var Digest: TImageDigest;
begin
  Digest := IntegrityHashHandle(Handle);
  Result := Digest.SHA512;
end;

procedure ValidateHash(const Value: string);
var
  C: Char;
begin
  Check(Length(Value) = 128, CozyText_Handoff_Text_e5593090);
  for C in Value do
    Check(CharInSet(C, ['0'..'9', 'a'..'f', 'A'..'F']),
      CozyText_Handoff_Text_e5593090);
end;

function UnlinkVerifiedOwnImage(var Handle: THandle; const Path,
  ExpectedSHA512: string; const ExpectedInfo: TByHandleFileInformation;
  RequireRemoval: Boolean = True; NativeError: PCardinal = nil): Boolean;
var
  Info: TByHandleFileInformation;
  Disposition: TFileDispositionInfoExLocal;
  Attributes, Error: DWORD;
begin
  Result := False;
  if NativeError <> nil then NativeError^ := 0;
  Check(SameText(ImagePath(GetCurrentProcess), Path),
    CozyText_Handoff_Text_1bfbe90b);
  Check(GetFileInformationByHandle(Handle, Info) and
    SameIdentity(Info, ExpectedInfo) and (Info.nNumberOfLinks = 1) and
    SameText(HandlePath(Handle), Path) and
    SameText(HashHandle(Handle), ExpectedSHA512),
    CozyText_Handoff_Text_124d511d);
  { Documented Win32 FileDispositionInfoEx: remove this image's directory
    entry while the existing image section remains valid for this process.
    No readonly override, alternate streams, delayed task, or helper process. }
  Disposition.Flags := FileDispositionDelete or FileDispositionPOSIXSemantics;
  if not SetFileInfo(Handle, FileDispositionInfoExClass, @Disposition,
    SizeOf(Disposition)) then
  begin
    Error := GetLastError;
    if NativeError <> nil then NativeError^ := Error;
    if RequireRemoval then Fail(CozyText_Handoff_Text_bc0ad16e);
    Exit;
  end;
  Result := True; { disposition accepted; path absence is checked independently }
  Close(Handle);
  Attributes := GetFileAttributesW(PWideChar(Path));
  Error := GetLastError;
  if NativeError <> nil then
    if (Attributes <> INVALID_FILE_ATTRIBUTES) or (Error = ERROR_FILE_NOT_FOUND) then
      NativeError^ := 0
    else NativeError^ := Error;
  if RequireRemoval then
    Check((Attributes = INVALID_FILE_ATTRIBUTES) and
      (Error = ERROR_FILE_NOT_FOUND), CozyText_Handoff_Text_a531ea32);
end;

procedure RemoveOwnImage(const ExpectedSHA512: string;
  const ExpectedInfo: TByHandleFileInformation);
var
  Path: string;
  Handle: THandle;
  Info: TByHandleFileInformation;
  Pins: THandleArray;
begin
  Handle := 0;
  ValidateHash(ExpectedSHA512);
  Path := ImagePath(GetCurrentProcess);
  try
    PinDirectories(Path, Pins);
    Handle := OpenSafeImage(Path, True, Info);
    Check(SameIdentity(Info, ExpectedInfo),
      CozyText_Handoff_Text_342e0cc0);
    UnlinkVerifiedOwnImage(Handle, Path, ExpectedSHA512, ExpectedInfo);
  finally
    Close(Handle);
    CloseAll(Pins);
  end;
end;

function ParseHandle(const Value: string): THandle;
var
  Number: UInt64;
  C: Char;
begin
  Check((Value <> '') and (Length(Value) <= 20), CozyText_Handoff_Text_07314e95);
  for C in Value do
    Check(CharInSet(C, ['0'..'9']), CozyText_Handoff_Text_07314e95);
  Check(TryStrToUInt64(Value, Number) and (Number > 0) and
    (Number < UInt64(High(NativeUInt))) and (UIntToStr(Number) = Value),
    CozyText_Handoff_Text_07314e95);
  Result := THandle(Number);
end;

procedure ValidateInherited(Handle: THandle);
var
  Flags: DWORD;
begin
  Check((Handle <> 0) and (Handle <> INVALID_HANDLE_VALUE),
    CozyText_Handoff_Text_004d804d);
  Check(GetHandleInformation(Handle, Flags) and
    ((Flags and HANDLE_FLAG_INHERIT) <> 0), CozyText_Handoff_Text_a613a0fb);
  Check(SetHandleInformation(Handle, HANDLE_FLAG_INHERIT, 0),
    CozyText_Handoff_Text_7efa7748);
end;

function IsHandoffCommandLine: Boolean;
begin
  Result := (ParamCount > 0) and SameText(ParamStr(1), CozyText_Handoff_game_handoff_43b89bd7);
end;

procedure ReadExact(Pipe: THandle; var Bytes: TBytes; Offset, Count: Integer;
  Deadline: UInt64);
var
  Available, ReadCount, Take: DWORD;
begin
  Check((Offset >= 0) and (Count >= 0) and (Offset <= Length(Bytes)) and
    (Count <= Length(Bytes) - Offset), CozyText_Handoff_HANDOFF_READ_RANGE_INVALID_2ce37b3a);
  while Count > 0 do
  begin
    Check(Remaining(Deadline) > 0, CozyText_Handoff_Text_5c2f7171);
    Check(PeekNamedPipe(Pipe, nil, 0, nil, @Available, nil),
      CozyText_Handoff_Text_2669e92a);
    if Available = 0 then
    begin
      CozyPause(10);
      Continue;
    end;
    Take := DWORD(Count);
    if Take > Available then Take := Available;
    Check(ReadFile(Pipe, Bytes[Offset], Take, ReadCount, nil) and
      (ReadCount > 0) and (ReadCount <= Take), CozyText_Handoff_Text_c4279bb6);
    { The final read must not publish success after a scheduling delay has
      exhausted the same absolute budget. The caller owns partial-buffer wipe. }
    Check(Remaining(Deadline) > 0, CozyText_Handoff_Text_5c2f7171);
    Inc(Offset, Integer(ReadCount));
    Dec(Count, Integer(ReadCount));
  end;
end;

procedure RequirePipeEnd(Pipe: THandle; Deadline: UInt64);
var
  Available, ErrorCode: DWORD;
begin
  repeat
    Check(Remaining(Deadline) > 0, CozyText_Handoff_Text_f9b96a69);
    if not PeekNamedPipe(Pipe, nil, 0, nil, @Available, nil) then
    begin
      ErrorCode := GetLastError;
      Check(ErrorCode = ERROR_BROKEN_PIPE, CozyText_Handoff_Text_0cfe59f1);
      { A late close is not permission to finish an expired frame. }
      Check(Remaining(Deadline) > 0, CozyText_Handoff_Text_f9b96a69);
      Exit;
    end;
    Check(Available = 0, CozyText_Handoff_Text_873ccf4f);
    Check(Remaining(Deadline) > 0, CozyText_Handoff_Text_f9b96a69);
    CozyPause(10);
  until False;
end;

function DecodeField(const Bytes: TBytes; var Offset: Integer;
  Count: DWORD): string;
var
  Chars: Integer;
begin
  Check((Offset >= 0) and (Offset <= Length(Bytes)) and
    (Count > 0) and (Count <= DWORD(Length(Bytes) - Offset)),
    CozyText_Handoff_Text_28293dcb);
  Chars := MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
    PAnsiChar(@Bytes[Offset]), Integer(Count), nil, 0);
  Check(Chars > 0, CozyText_Handoff_Text_997ae802);
  SetLength(Result, Chars);
  Check(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
    PAnsiChar(@Bytes[Offset]), Integer(Count), PWideChar(Result), Chars) = Chars,
    CozyText_Handoff_Text_c6124ad9);
  Check(Pos(#0, Result) = 0, CozyText_Handoff_NUL_129b6eb6);
  Inc(Offset, Integer(Count));
end;

function ChildEnvironment: string;
const
  { Compatibility allowlist: Windows paths, user profile, locale/process
    basics. Never inherit arbitrary application credentials or debug config. }
  Names: array[0..18] of string = (CozyText_Handoff_APPDATA_e18f8cd9, CozyText_Handoff_CommonProgramFiles_4ea68291,
    CozyText_Handoff_CommonProgramFiles_x86_83122864, CozyText_Handoff_COMPUTERNAME_c705651c, CozyText_Handoff_LOCALAPPDATA_811c5840,
    CozyText_Handoff_NUMBER_OF_PROCESSORS_dc92622b, CozyText_Handoff_OS_a4cb0728, CozyText_Handoff_PROCESSOR_ARCHITECTURE_e086747d, CozyText_Handoff_ProgramData_3131e9cd,
    CozyText_Handoff_ProgramFiles_5920380c, CozyText_Handoff_ProgramFiles_x86_30fc5f6e, CozyText_Handoff_SESSIONNAME_2b72395f, CozyText_Handoff_SystemDrive_e676e146,
    CozyText_Handoff_SystemRoot_2a19f8f4, CozyText_Handoff_TEMP_0e40382f, CozyText_Handoff_TMP_61eb352a, CozyText_Handoff_USERDOMAIN_ffb263cc, CozyText_Handoff_USERNAME_f9d6a799, CozyText_Handoff_USERPROFILE_27d9a131);
var
  ApiTarget: TResolved_GetEnvironmentVariableW;
  Entries: TArray<string>;
  Needed, Actual: DWORD;
  I, J, Count: Integer;
  Value, Root, Entry: string;
begin
  ApiTarget := TResolved_GetEnvironmentVariableW(DecodeApiPointer(ApiSlot_GetEnvironmentVariableW));
  SetLength(Entries, Length(Names) + 3); Count := 0;
  try
    for I := 0 to High(Names) do
    begin
      Needed := ApiTarget(PWideChar(Names[I]), nil, 0);
      if Needed = 0 then Continue;
      Check(Needed <= 32767, CozyText_Handoff_HANDOFF_ENVIRONMENT_INVALID_c015f407);
      SetLength(Value, Needed);
      Actual := ApiTarget(PWideChar(Names[I]), PWideChar(Value), Needed);
      Check((Actual > 0) and (Actual < Needed), CozyText_Handoff_HANDOFF_ENVIRONMENT_CHANGED_b33d1f33);
      SetLength(Value, Actual);
      Check(Pos(#0, Value) = 0, CozyText_Handoff_HANDOFF_ENVIRONMENT_INVALID_c015f407);
      if Names[I] = CozyText_Handoff_SystemRoot_2a19f8f4 then Root := Value;
      Entries[Count] := Names[I] + '=' + Value; Inc(Count);
      WipeText(Value);
    end;
    Check((Root <> '') and (Pos(';', Root) = 0), CozyText_Handoff_HANDOFF_SYSTEM_ROOT_REQUIRED_11654d87);
    Entries[Count] := CozyText_Handoff_PATH_d58a596b + IncludeTrailingPathDelimiter(Root) + CozyText_Handoff_System32_680269e8 + Root;
    Inc(Count);
    Entries[Count] := CozyText_Handoff_windir_105c0036 + Root; Inc(Count);
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
    Entries[Count] := CozyText_Handoff_GAME_PRODUCT_FAULT_ROOT_53ff6984 + ProductFaultRoot; Inc(Count);
{$ENDIF}
    { Windows expects a case-insensitively sorted Unicode environment block. }
    for I := 1 to Count - 1 do
    begin
      Entry := Entries[I]; J := I - 1;
      while (J >= 0) and (CompareText(Entries[J], Entry) > 0) do
      begin Entries[J + 1] := Entries[J]; Dec(J); end;
      Entries[J + 1] := Entry;
    end;
    Result := '';
    for I := 0 to Count - 1 do Result := Result + Entries[I] + #0;
    Result := Result + #0;
    Check(Length(Result) <= 32767, CozyText_Handoff_HANDOFF_ENVIRONMENT_TOO_LARGE_8d09471d);
  finally
    for I := 0 to High(Entries) do WipeText(Entries[I]);
    WipeText(Value); WipeText(Root); WipeText(Entry);
  end;
end;

function HandoffRoleName(OverlayRole: Boolean): string;
begin
  if OverlayRole then Result := 'O' else Result := 'B';
end;

procedure WritePublicFrame(Pipe: THandle; const Bytes: TBytes);
var Written: DWORD;
begin
  { Public hello/bootstrap fits into the 64-KiB pipe buffer created by our
    parent. The private payload retains the cancellable writer path below. }
  Check((Length(Bytes) > 0) and (Length(Bytes) <= 4096), CozyText_Handoff_HANDOFF_HELLO_SIZE_1e8c0f1e);
  Check(WriteFile(Pipe, Bytes[0], Length(Bytes), Written, nil) and
    (Written = DWORD(Length(Bytes))), CozyText_Handoff_HANDOFF_HELLO_WRITE_c5ca140e);
end;

function BuildHello(Role: DWORD; Security: TDeviceSecurity;
  Cipher: THandoffCipher; out Nonce: string): TBytes;
var Header: TChildHelloHeader; Signing, Wrapping: TBytes; I: Integer;
begin
  FillChar(Header, SizeOf(Header), 0);
  Nonce := HandoffRandomNonce;
  try
    Signing := TEncoding.UTF8.GetBytes(Security.PublicKeyBlob);
    Wrapping := Cipher.PublicBlob;
    Header.Magic := HelloMagic; Header.Version := HandoffVersion;
    Header.ComponentRole := Role;
    Header.SigningBytes := Length(Signing); Header.WrappingBytes := Length(Wrapping);
    for I := 0 to 63 do Header.Nonce[I] := Ord(Nonce[I + 1]);
    SetLength(Result, SizeOf(Header) + Length(Signing) + Length(Wrapping));
    Move(Header, Result[0], SizeOf(Header));
    Move(Signing[0], Result[SizeOf(Header)], Length(Signing));
    Move(Wrapping[0], Result[SizeOf(Header) + Length(Signing)], Length(Wrapping));
  finally
    WipeBytes(Signing); WipeBytes(Wrapping);
  end;
end;

function ReadHello(Pipe: THandle; Role: DWORD; Deadline: UInt64;
  out ChildKeyID, Nonce: string; out Wrapping: TBytes): TBytes;
var Header: TChildHelloHeader; Offset, I: Integer;
  Signing, CandidateKeyID, CandidateNonce: string; CandidateWrapping: TBytes;
begin
  Result := nil; ChildKeyID := ''; Nonce := ''; Wrapping := nil;
  CandidateWrapping := nil;
  try
    try
      SetLength(Result, SizeOf(Header));
      ReadExact(Pipe, Result, 0, Length(Result), Deadline);
      Move(Result[0], Header, SizeOf(Header));
      Check((Header.Magic = HelloMagic) and (Header.Version = HandoffVersion) and
        (Header.ComponentRole = Role) and (Header.SigningBytes >= 376) and
        (Header.SigningBytes <= 384) and (Header.WrappingBytes >= 281) and
        (Header.WrappingBytes <= 288), CozyText_Handoff_HANDOFF_HELLO_INVALID_3bd73add);
      SetLength(Result, SizeOf(Header) + Header.SigningBytes + Header.WrappingBytes);
      ReadExact(Pipe, Result, SizeOf(Header), Length(Result) - SizeOf(Header), Deadline);
      RequirePipeEnd(Pipe, Deadline);
      SetLength(CandidateNonce, 64);
      for I := 0 to 63 do
      begin
        Check(CharInSet(Char(Header.Nonce[I]), ['0'..'9', 'A'..'F']), CozyText_Handoff_HANDOFF_NONCE_INVALID_f3730e62);
        CandidateNonce[I + 1] := Char(Header.Nonce[I]);
      end;
      Offset := SizeOf(Header);
      Signing := DecodeField(Result, Offset, Header.SigningBytes);
      CandidateKeyID := DevicePublicKeyID(Signing);
      SetLength(CandidateWrapping, Header.WrappingBytes);
      Move(Result[Offset], CandidateWrapping[0], Length(CandidateWrapping));
      Check(Remaining(Deadline) > 0, CozyText_Handoff_Text_5c2f7171);
      { Publish every output only after the complete bounded hello and EOF
        have passed. No partial nonce/key/blob escapes an exception. }
      ChildKeyID := CandidateKeyID; CandidateKeyID := '';
      Nonce := CandidateNonce; CandidateNonce := '';
      Wrapping := CandidateWrapping; CandidateWrapping := nil;
    except
      WipeBytes(Result); WipeBytes(Wrapping);
      WipeText(ChildKeyID); WipeText(Nonce);
      raise;
    end;
  finally
    WipeText(Signing); WipeText(CandidateKeyID); WipeText(CandidateNonce);
    WipeBytes(CandidateWrapping);
    FillChar(Header, SizeOf(Header), 0);
  end;
end;

function Transcript(const Bootstrap, Hello: TBytes): TBytes;
begin
  Check((Length(Bootstrap) = SizeOf(THandshakeHeader)) and
    (Length(Hello) >= SizeOf(TChildHelloHeader)) and (Length(Hello) <= 4096),
    CozyText_Handoff_HANDOFF_TRANSCRIPT_INVALID_575081d0);
  SetLength(Result, Length(Bootstrap) + Length(Hello));
  Move(Bootstrap[0], Result[0], Length(Bootstrap));
  Move(Hello[0], Result[Length(Bootstrap)], Length(Hello));
end;

class function THandoffContext.ReceiveFromCommandLine: THandoffContext;
begin
  Result := ReceiveRole(False);
end;

class function THandoffContext.ReceiveOverlayFromCommandLine: THandoffContext;
begin
  Result := ReceiveRole(True);
end;

class function THandoffContext.ReceiveRole(OverlayRole: Boolean): THandoffContext;
var
  Pipe, ReplyPipe, ImageFile: THandle;
  Header: TWireHeader;
  BootstrapHeader: THandshakeHeader;
  Payload, PublicBootstrap, Hello, AAD, Envelope, FrameSizeBytes: TBytes;
  ChildSecurity: TDeviceSecurity;
  Cipher: THandoffCipher;
  FrameSize: DWORD;
  Deadline, Total: UInt64;
  I, Offset: Integer;
  ProfileText, Nonce, ParentID, PayloadNonce, Delegation: string;
  Pins: THandleArray;
  Info: TByHandleFileInformation;
begin
  Result := nil;
  Pipe := 0; ReplyPipe := 0;
  ChildSecurity := nil; Cipher := nil;
  ImageFile := 0;
  CheckABI;
  Check((ParamCount = 2) and
    (((not OverlayRole) and (ParamStr(1) = CozyText_Handoff_game_handoff_43b89bd7)) or
     (OverlayRole and (ParamStr(1) = CozyText_Handoff_game_overlay_c16e7097))),
    CozyText_Handoff_Text_3a3af42f);
  try
    try
      Pipe := ParseHandle(ParamStr(2));
      ValidateInherited(Pipe);
      Check(GetFileType(Pipe) = FILE_TYPE_PIPE, CozyText_Handoff_Text_2f24cd32);
      Deadline := CozyTick + HandoffTimeoutMS;
      SetLength(PublicBootstrap, SizeOf(BootstrapHeader));
      ReadExact(Pipe, PublicBootstrap, 0, Length(PublicBootstrap), Deadline);
      Move(PublicBootstrap[0], BootstrapHeader, SizeOf(BootstrapHeader));
      Check((BootstrapHeader.Magic = HandshakeMagic) and
        (BootstrapHeader.Version = HandoffVersion) and
        (BootstrapHeader.ComponentRole = DWORD(Ord(OverlayRole))) and
        (BootstrapHeader.ReplyPipe > 0) and
        (BootstrapHeader.ReplyPipe < UInt64(High(NativeUInt))) and
        (BootstrapHeader.ReplyPipe <> UInt64(Pipe)), CozyText_Handoff_HANDOFF_BOOTSTRAP_INVALID_517fe843);
      ReplyPipe := THandle(BootstrapHeader.ReplyPipe);
      ValidateInherited(ReplyPipe);
      Check(GetFileType(ReplyPipe) = FILE_TYPE_PIPE, CozyText_Handoff_HANDOFF_REPLY_PIPE_INVALID_5152c5e0);
      ChildSecurity := TDeviceSecurity.Create;
      Cipher := THandoffCipher.Create;
      Hello := BuildHello(BootstrapHeader.ComponentRole, ChildSecurity, Cipher, Nonce);
      AAD := Transcript(PublicBootstrap, Hello);
      WritePublicFrame(ReplyPipe, Hello);
      Close(ReplyPipe);
      SetLength(FrameSizeBytes, SizeOf(FrameSize));
      ReadExact(Pipe, FrameSizeBytes, 0, Length(FrameSizeBytes), Deadline);
      Move(FrameSizeBytes[0], FrameSize, SizeOf(FrameSize));
      Check((FrameSize > 300) and (FrameSize <= MaxHandoffBytes + 300), CozyText_Handoff_HANDOFF_ENVELOPE_SIZE_b5eadb47);
      SetLength(Envelope, FrameSize);
      ReadExact(Pipe, Envelope, 0, Length(Envelope), Deadline);
      RequirePipeEnd(Pipe, Deadline);
      Close(Pipe);
      Payload := Cipher.Decrypt(Envelope, AAD,
        function: Boolean
        begin Result := Remaining(Deadline) = 0; end);
      Check(Length(Payload) >= SizeOf(Header), CozyText_Handoff_HANDOFF_PAYLOAD_SIZE_c583a842);
      Move(Payload[0], Header, SizeOf(Header));
      Check((Header.Magic = HandoffMagic) and (Header.Version = HandoffVersion) and
        (Header.ComponentRole = DWORD(Ord(OverlayRole))) and
        (Header.TotalBytes > DWORD(SizeOf(Header))) and
        (Header.TotalBytes <= MaxHandoffBytes), CozyText_Handoff_Text_b40b884f);
      Total := SizeOf(Header);
      for I := 0 to FieldCount - 1 do
      begin
        Check(Header.Sizes[I] > 0, CozyText_Handoff_Text_67dc1d83);
        Total := Total + Header.Sizes[I];
      end;
      Check(Total = Header.TotalBytes, CozyText_Handoff_Text_979c85bf);
      Check((Header.Sizes[FieldProfile] <= 8192) and
        (Header.Sizes[FieldFlow] <= 256) and (Header.Sizes[FieldToken] <= 8192) and
        (Header.Sizes[FieldClaim] <= 16384) and
        (Header.Sizes[FieldLauncherHash] = 128) and
        (Header.Sizes[FieldBinaryHash] = 128) and
        (Header.Sizes[FieldParentDeviceID] = 64) and
        (Header.Sizes[FieldChildNonce] = 64) and
        (Header.Sizes[FieldDelegation] = 344), CozyText_Handoff_Text_77a22930);
      Check(DWORD(Length(Payload)) = Header.TotalBytes, CozyText_Handoff_HANDOFF_PAYLOAD_SIZE_c583a842);
      Check((Header.ReadyEvent > 0) and
        (Header.ReadyEvent < UInt64(High(NativeUInt))) and
        (Header.ParentProcess > 0) and
        (Header.ParentProcess < UInt64(High(NativeUInt))) and
        (Header.ReadyEvent <> Header.ParentProcess), CozyText_Handoff_Text_004d804d);
      Result := THandoffContext.Create;
      Result.FOverlay := OverlayRole;
      Result.FReadyEvent := THandle(Header.ReadyEvent);
      Result.FParentProcess := THandle(Header.ParentProcess);
      ValidateInherited(Result.FReadyEvent);
      ValidateInherited(Result.FParentProcess);
      Result.FParentID := Header.ParentID;
      Check((Header.ParentID <> 0) and (Header.ParentID <> GetCurrentProcessId) and
        (GetProcessId(Result.FParentProcess) = Header.ParentID),
        CozyText_Handoff_Text_5906b045);
      Check((WaitForSingleObject(Result.FParentProcess, 0) = WAIT_TIMEOUT) and
        (WaitForSingleObject(Result.FReadyEvent, 0) = WAIT_TIMEOUT),
        CozyText_Handoff_Text_f935adb6);
      Result.FLauncherVolume := Header.LauncherVolume;
      Result.FLauncherIndexHigh := Header.LauncherIndexHigh;
      Result.FLauncherIndexLow := Header.LauncherIndexLow;
      Offset := SizeOf(Header);
      ProfileText := DecodeField(Payload, Offset, Header.Sizes[FieldProfile]);
      Result.Profile := TConnectServerProfile.FromJSON(ProfileText);
      Result.FlowID := DecodeField(Payload, Offset, Header.Sizes[FieldFlow]);
      Result.HandoffToken := DecodeField(Payload, Offset, Header.Sizes[FieldToken]);
      Result.ClaimCanonical := DecodeField(Payload, Offset, Header.Sizes[FieldClaim]);
      Result.LauncherSHA512 := DecodeField(Payload, Offset, Header.Sizes[FieldLauncherHash]);
      Result.BinarySHA512 := DecodeField(Payload, Offset, Header.Sizes[FieldBinaryHash]);
      Result.FLauncherPath := DecodeField(Payload, Offset, Header.Sizes[FieldLauncherPath]);
      Result.FBinaryPath := DecodeField(Payload, Offset, Header.Sizes[FieldBinaryPath]);
      ValidateHash(Result.LauncherSHA512);
      ValidateHash(Result.BinarySHA512);
      ValidatePathText(Result.FLauncherPath);
      ValidatePathText(Result.FBinaryPath);
      Check(not SameText(Result.FLauncherPath, Result.FBinaryPath) and
        SameText(ExtractFilePath(Result.FLauncherPath), ExtractFilePath(Result.FBinaryPath)),
        CozyText_Handoff_Text_91b750f0);
      Check(SameText(ImagePath(GetCurrentProcess), Result.FBinaryPath) and
        SameText(ImagePath(Result.FParentProcess), Result.FLauncherPath),
        CozyText_Handoff_Text_a8f85391);
      PinDirectories(Result.FBinaryPath, Pins);
      ImageFile := OpenSafeImage(Result.FBinaryPath, False, Info);
      Check(SameText(HashHandle(ImageFile), Result.BinarySHA512),
        CozyText_Handoff_Text_4a46bfee);
      Result.CodeIntegrity := TCodeIntegrity.Create(ImageFile);
      Close(ImageFile);
      ImageFile := OpenSafeImage(Result.FLauncherPath, False, Info, False, OverlayRole);
      Check((Info.dwVolumeSerialNumber = Result.FLauncherVolume) and
        (Info.nFileIndexHigh = Result.FLauncherIndexHigh) and
        (Info.nFileIndexLow = Result.FLauncherIndexLow) and
        SameText(HashHandle(ImageFile), Result.LauncherSHA512),
        CozyText_Handoff_Text_41951c88);
      ParentID := DecodeField(Payload, Offset, Header.Sizes[FieldParentDeviceID]);
      PayloadNonce := DecodeField(Payload, Offset, Header.Sizes[FieldChildNonce]);
      Delegation := DecodeField(Payload, Offset, Header.Sizes[FieldDelegation]);
      Check((PayloadNonce = Nonce) and (Offset = Length(Payload)), CozyText_Handoff_HANDOFF_CHILD_BINDING_INVALID_1bedf988);
      ChildSecurity.AcceptDelegation(ParentID, HandoffRoleName(OverlayRole),
        Result.ClaimCanonical, Nonce, Delegation);
      Result.Security := ChildSecurity;
      ChildSecurity := nil;
      { This alias is an OS observation. Server grant validation, not this
        value alone, decides whether the parent is a same-session peer. }
      Result.ParentIdentity := NHWStableProcessIdentity(
        Result.FParentProcess, ImageFile, Result.FParentID);
    except
      FreeAndNil(Result);
      raise;
    end;
  finally
    Close(ImageFile);
    CloseAll(Pins);
    Close(Pipe);
    Close(ReplyPipe);
    Cipher.Free; ChildSecurity.Free;
    WipeBytes(PublicBootstrap); WipeBytes(Hello); WipeBytes(AAD);
    WipeBytes(Envelope); WipeBytes(FrameSizeBytes); WipeBytes(Payload);
    WipeText(Nonce); WipeText(ParentID); WipeText(PayloadNonce); WipeText(Delegation);
    WipeText(ProfileText);
  end;
end;

procedure THandoffContext.CompleteClaimAndCleanupCore(const ExpectedCRC64: string);
var
  LauncherFile, BinaryFile, IntegrityFile: THandle;
  LauncherInfo, BinaryInfo, FinalBinaryInfo, IntegrityInfo: TByHandleFileInformation;
  Pins: THandleArray;
  Disposition: TFileDispositionInfoLocal;
  WaitResult, Attributes, Error: DWORD;
begin
  FParentObservation.ProcessID := FParentID;
  Check(not FOverlay, CozyText_Handoff_Overlay_handoff_cannot_retire_its_parent_605694a6);
  Check(not FCompleted, CozyText_Handoff_Text_ff81ad00);
  LauncherFile := 0;
  BinaryFile := 0;
  IntegrityFile := 0;
  try
    Check((FParentProcess <> 0) and (FReadyEvent <> 0) and
      (GetProcessId(FParentProcess) = FParentID) and
      (WaitForSingleObject(FParentProcess, 0) = WAIT_TIMEOUT),
      CozyText_Handoff_Text_7e4d1518);
    Check(SameText(ImagePath(FParentProcess), FLauncherPath) and
      SameText(ImagePath(GetCurrentProcess), FBinaryPath),
      CozyText_Handoff_Text_cf8d7197);
    Check(not SameText(FLauncherPath, FBinaryPath) and
      SameText(ExtractFilePath(FLauncherPath), ExtractFilePath(FBinaryPath)),
      CozyText_Handoff_Text_56363717);
    PinDirectories(FBinaryPath, Pins);
    BinaryFile := OpenSafeImage(FBinaryPath, False, BinaryInfo);
    FParentObservation.CleanupAttempted := True;
    LauncherFile := OpenSafeImage(FLauncherPath, True, LauncherInfo, False, False,
      @FParentObservation.Win32Error);
    Check(not SameIdentity(LauncherInfo, BinaryInfo) and
      (LauncherInfo.dwVolumeSerialNumber = FLauncherVolume) and
      (LauncherInfo.nFileIndexHigh = FLauncherIndexHigh) and
      (LauncherInfo.nFileIndexLow = FLauncherIndexLow),
      CozyText_Handoff_Text_85899adf);
    Check(SameText(HashHandle(BinaryFile), BinarySHA512) and
      SameText(HashHandle(LauncherFile), LauncherSHA512),
      CozyText_Handoff_Text_2fe42bc6);
    { Only the authenticated-claim caller reaches this point. A exits after
      observing this event; neither PID polling nor a path from argv is used. }
    Check(SetEvent(FReadyEvent), CozyText_Handoff_Text_645b04e0);
    Close(FReadyEvent);
    WaitResult := WaitForSingleObject(FParentProcess, ParentExitTimeoutMS);
    FParentObservation.ExitObserved := WaitResult = WAIT_OBJECT_0;
    FParentObservation.ExitTimedOut := WaitResult = WAIT_TIMEOUT;
    Check(FParentObservation.ExitObserved,
      CozyText_Handoff_Text_47ff511a);
    { Hash and delete through the same held file handle. Ancestors cannot be
      renamed, the file cannot be replaced, and B's own identity is excluded. }
    Check(GetFileInformationByHandle(LauncherFile, LauncherInfo) and
      (LauncherInfo.dwVolumeSerialNumber = FLauncherVolume) and
      (LauncherInfo.nFileIndexHigh = FLauncherIndexHigh) and
      (LauncherInfo.nFileIndexLow = FLauncherIndexLow) and
      (LauncherInfo.nNumberOfLinks = 1) and
      SameText(HandlePath(LauncherFile), FLauncherPath) and
      SameText(HashHandle(LauncherFile), LauncherSHA512),
      CozyText_Handoff_Text_b084e304);
    Disposition.DeleteFile := 1;
    FParentObservation.CleanupAttempted := True;
    FParentObservation.DispositionAccepted := SetFileInfo(LauncherFile,
      FileDispositionInfoClass, @Disposition, SizeOf(Disposition));
    if not FParentObservation.DispositionAccepted then
      FParentObservation.Win32Error := GetLastError;
    Check(FParentObservation.DispositionAccepted,
      CozyText_Handoff_Text_caa1db3a);
    Close(LauncherFile);
    Close(FParentProcess);
    Attributes := GetFileAttributesW(PWideChar(FLauncherPath)); Error := GetLastError;
    FParentObservation.FileRemoved := (Attributes = INVALID_FILE_ATTRIBUTES) and
      (Error = ERROR_FILE_NOT_FOUND);
    if (Attributes = INVALID_FILE_ATTRIBUTES) and not FParentObservation.FileRemoved then
      FParentObservation.Win32Error := Error;
    { A has exited and released its image pin. Recheck the exact B even if
      Windows refuses DELETE access. Only OS cleanup failure is nonfatal;
      a changed identity, path, link count or hash still stops execution. }
    Close(BinaryFile);
    BinaryFile := OpenSafeImage(FBinaryPath, True, FinalBinaryInfo, True);
    Check(SameIdentity(BinaryInfo, FinalBinaryInfo),
      CozyText_Handoff_Text_342e0cc0);
    { Keep an independently opened read-only file object for later proofs.
      Duplicating BinaryFile would retain the cleanup file object after its
      close and postpone POSIX unlink until the integrity object is freed.
      The original cleanup pin stays held throughout identity/hash validation. }
    IntegrityFile := OpenSafeImage(FBinaryPath, False, IntegrityInfo, False, True);
    Check(SameIdentity(FinalBinaryInfo, IntegrityInfo) and
      SameText(HashHandle(IntegrityFile), BinarySHA512),
      CozyText_Handoff_Independent_image_integrity_binding_changed_dfe83f8d);
    FImageIntegrity := TImageIntegrity.Create(IntegrityFile, BinarySHA512, ExpectedCRC64);
    Close(IntegrityFile);
    FBinaryCleanupInfo := BinaryInfo;
    FBinaryCleanupFile := BinaryFile;
    BinaryFile := 0;
    FCompleted := True;
    WipeText(HandoffToken);
    WipeText(ClaimCanonical);
  finally
    Close(LauncherFile);
    Close(BinaryFile);
    Close(IntegrityFile);
    CloseAll(Pins);
  end;
end;

function THandoffContext.ParentIsAliveCore: Boolean;
begin
  Result := (FParentProcess <> 0) and
    (GetProcessId(FParentProcess) = FParentID) and
    (WaitForSingleObject(FParentProcess, 0) = WAIT_TIMEOUT);
end;

procedure THandoffContext.CompleteOverlayClaimCore(const ExpectedCRC64: string);
var
  ParentFile, ImageFile: THandle;
  ParentInfo, ImageInfo: TByHandleFileInformation;
  Pins: THandleArray;
begin
  Check(FOverlay and not FCompleted, CozyText_Handoff_Invalid_overlay_handoff_state_d66122e9);
  ParentFile := 0;
  ImageFile := 0;
  try
    Check(ParentIsAliveCore and (FReadyEvent <> 0), CozyText_Handoff_Overlay_parent_is_unavailable_cdd05f72);
    Check(SameText(ImagePath(FParentProcess), FLauncherPath) and
      SameText(ImagePath(GetCurrentProcess), FBinaryPath), CozyText_Handoff_Overlay_process_binding_changed_bdd16710);
    PinDirectories(FBinaryPath, Pins);
    ParentFile := OpenSafeImage(FLauncherPath, False, ParentInfo, False, True);
    ImageFile := OpenSafeImage(FBinaryPath, False, ImageInfo);
    Check(not SameIdentity(ParentInfo, ImageInfo) and
      (ParentInfo.dwVolumeSerialNumber = FLauncherVolume) and
      (ParentInfo.nFileIndexHigh = FLauncherIndexHigh) and
      (ParentInfo.nFileIndexLow = FLauncherIndexLow) and
      SameText(HashHandle(ParentFile), LauncherSHA512) and
      SameText(HashHandle(ImageFile), BinarySHA512), CozyText_Handoff_Overlay_image_binding_changed_00c4ca6b);
    FImageIntegrity := TImageIntegrity.Create(ImageFile, BinarySHA512, ExpectedCRC64);
    FBinaryCleanupInfo := ImageInfo;
    { Keep the authenticated B identity and its ancestors pinned until the
      server transfers ownership and this exact parent process has exited.
      Read sharing permits a DELETE open only after B releases its own pin. }
    FParentImage := ParentFile;
    ParentFile := 0;
    FParentPins := Pins;
    Pins := nil;
    { Readiness is acknowledged separately, after O has obtained its initial
      server report and authority/license lease. Claim alone is insufficient. }
    FCompleted := True;
    WipeText(HandoffToken);
    WipeText(ClaimCanonical);
  finally
    Close(ParentFile);
    Close(ImageFile);
    CloseAll(Pins);
  end;
end;

procedure THandoffContext.ConfirmOverlayReadyCore;
begin
  Check(FOverlay and FCompleted and (FReadyEvent <> 0) and ParentIsAliveCore,
    CozyText_Handoff_Overlay_authorization_cannot_complete_ef5fe7de);
  Check(SetEvent(FReadyEvent), CozyText_Handoff_Cannot_complete_overlay_handoff_e26390f1);
  Close(FReadyEvent);
end;

procedure THandoffContext.CleanupTransferredParentCore;
var
  DeleteFile: THandle;
  HeldInfo, DeleteInfo: TByHandleFileInformation;
  Disposition: TFileDispositionInfoLocal;
  Attributes, Error: DWORD;
begin
  if FParentRetired then Exit;
  FParentObservation.ProcessID := FParentID;
  { Only errors captured by the cleanup operation may be classified as an
    OS refusal. Never reuse a last-error value from an earlier measurement. }
  FParentObservation.Win32Error := 0;
  Check(FOverlay and FCompleted and (FReadyEvent = 0) and
    (FParentImage <> 0) and (FParentProcess <> 0), CozyText_Handoff_Invalid_parent_retirement_4789b7a0);
  Check((GetProcessId(FParentProcess) = FParentID) and
    (WaitForSingleObject(FParentProcess, 0) = WAIT_OBJECT_0),
    CozyText_Handoff_Overlay_parent_has_not_exited_ace1a391);
  FParentObservation.ExitObserved := True;
  {$IFDEF GAME_PRODUCT_FAULT_TESTS}
  { Parent is already signalled; the runner holds only this authenticated
    file to observe real Windows refusal or pending-delete semantics. }
  ProductFaultParentCleanup(FParentID);
  {$ENDIF}
  DeleteFile := 0;
  try
    Check(GetFileInformationByHandle(FParentImage, HeldInfo) and
      (HeldInfo.dwVolumeSerialNumber = FLauncherVolume) and
      (HeldInfo.nFileIndexHigh = FLauncherIndexHigh) and
      (HeldInfo.nFileIndexLow = FLauncherIndexLow) and
      (HeldInfo.nNumberOfLinks = 1) and
      SameText(HandlePath(FParentImage), FLauncherPath) and
      SameText(HashHandle(FParentImage), LauncherSHA512),
      CozyText_Handoff_Transferred_parent_identity_changed_ec563a87);
    { Reopening DELETE cannot affect a substituted path: compare it with the
      continuously held, deny-write original before setting disposition. }
    FParentObservation.CleanupAttempted := True;
    DeleteFile := OpenSafeImage(FLauncherPath, True, DeleteInfo, False, False,
      @FParentObservation.Win32Error);
    Check(SameIdentity(HeldInfo, DeleteInfo) and
      SameText(HashHandle(DeleteFile), LauncherSHA512),
      CozyText_Handoff_Transferred_parent_cleanup_identity_changed_87d48ded);
    Disposition.DeleteFile := 1;
    FParentObservation.CleanupAttempted := True;
    FParentObservation.DispositionAccepted := SetFileInfo(DeleteFile,
      FileDispositionInfoClass, @Disposition, SizeOf(Disposition));
    if not FParentObservation.DispositionAccepted then
      FParentObservation.Win32Error := GetLastError;
    Check(FParentObservation.DispositionAccepted, CozyText_Handoff_Transferred_parent_cleanup_failed_c5482baa);
    Close(DeleteFile);
    Close(FParentImage);
    Close(FParentProcess);
    Attributes := GetFileAttributesW(PWideChar(FLauncherPath)); Error := GetLastError;
    FParentObservation.FileRemoved := (Attributes = INVALID_FILE_ATTRIBUTES) and
      (Error = ERROR_FILE_NOT_FOUND);
    if (Attributes = INVALID_FILE_ATTRIBUTES) and not FParentObservation.FileRemoved then
      FParentObservation.Win32Error := Error;
    CloseAll(FParentPins);
    FParentRetired := True;
  finally
    Close(DeleteFile);
  end;
end;

procedure THandoffContext.CleanupBinaryAfterLicenseCore;
var
  Pins: THandleArray;
begin
  Check(FCompleted, CozyText_Handoff_Text_dbd1685a);
  if FBinaryCleanupAttempted then Exit;
  FBinaryCleanupAttempted := True;
  try
    { Re-pin ancestors before touching the same verified file. This method
      runs between worker API calls, not concurrently with integrity reads. }
    PinDirectories(FBinaryPath, Pins);
    UnlinkVerifiedOwnImage(FBinaryCleanupFile, FBinaryPath, BinarySHA512,
      FBinaryCleanupInfo, False);
  finally
    { Successful unlink closes the sole cleanup-file-object handle above.
      On OS refusal, retain its deny-write/delete pin until context destruction;
      the independent integrity reader must not be left as the sole protection.
      No helper/retry/rename is used. Identity/hash failures still raise. }
    CloseAll(Pins);
  end;
end;

function THandoffContext.TakeImageIntegrityCore: TImageIntegrity;
begin
  Check(FCompleted and Assigned(FImageIntegrity), CozyText_Handoff_Image_integrity_evidence_is_unavailable_09d8ad23);
  Result := FImageIntegrity;
  FImageIntegrity := nil;
end;

function THandoffContext.ParentCleanupObservation: THandoffCleanupObservation;
begin
  FGate.Enter;
  try Result := FParentObservation;
  finally FGate.Leave; end;
end;

function THandoffContext.OwnCleanupObservation: THandoffCleanupObservation;
begin
  FGate.Enter;
  try Result := FOwnObservation;
  finally FGate.Leave; end;
end;

procedure THandoffContext.CleanupOwnImageForShutdown;
var Pins: THandleArray; Info: TByHandleFileInformation;
  Attributes, Error: DWORD;
begin
  FGate.Enter;
  try
    FOwnObservation.ProcessID := GetCurrentProcessId;
    if FOwnObservation.CleanupAttempted then Exit;
    { An incomplete/unclaimed handoff is not authority to erase a template. }
    if not FCompleted then Exit;
    FOwnObservation.CleanupAttempted := True;
    FreeAndNil(FImageIntegrity);
    try
      PinDirectories(FBinaryPath, Pins);
      if FBinaryCleanupFile = 0 then
      begin
        FBinaryCleanupFile := OpenSafeImage(FBinaryPath, True, Info, False, False,
          @FOwnObservation.Win32Error);
        Check(SameIdentity(Info, FBinaryCleanupInfo), CozyText_Handoff_Shutdown_image_identity_changed_1e844966);
      end;
      FOwnObservation.DispositionAccepted := UnlinkVerifiedOwnImage(
        FBinaryCleanupFile, FBinaryPath, BinarySHA512, FBinaryCleanupInfo,
        False, @FOwnObservation.Win32Error);
      Attributes := GetFileAttributesW(PWideChar(FBinaryPath)); Error := GetLastError;
      FOwnObservation.FileRemoved := (Attributes = INVALID_FILE_ATTRIBUTES) and
        (Error = ERROR_FILE_NOT_FOUND);
      if (Attributes = INVALID_FILE_ATTRIBUTES) and not FOwnObservation.FileRemoved then
        FOwnObservation.Win32Error := Error;
    except
      { The report distinguishes refusal from absence; never widen the delete
        to a replacement pathname, helper, reboot task or another identity. }
      { Logical identity/hash failures intentionally carry no stale OS error. }
    end;
    CloseAll(Pins);
    Close(FBinaryCleanupFile);
  finally FGate.Leave; end;
end;

destructor THandoffContext.Destroy;
begin
  if FGate <> nil then FGate.CloseAndWait;
  Close(FParentImage);
  CloseAll(FParentPins);
  Close(FBinaryCleanupFile);
  Close(FReadyEvent);
  Close(FParentProcess);
  Security.Free;
  FImageIntegrity.Free;
  CodeIntegrity.Free;
  Profile.Free;
  WipeText(HandoffToken);
  WipeText(ClaimCanonical);
  WipeText(ParentIdentity);
  FGate.Free;
  inherited Destroy;
end;

destructor TPipeWriter.Destroy;
begin
  WipeBytes(Bytes);
  Close(Pipe);
  Close(CancelEvent);
  inherited Destroy;
end;

function WritePipeThread(Parameter: Pointer): Integer;
var
  Writer: TPipeWriter;
  Offset: Integer;
  Count, Written: DWORD;
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
  FaultAction: Integer;
{$ENDIF}
begin
  Result := 1;
  Writer := TPipeWriter(Parameter);
  try
    try
      Offset := 0;
      while Offset < Length(Writer.Bytes) do
      begin
        if WaitForSingleObject(Writer.CancelEvent, 0) <> WAIT_TIMEOUT then
          Exit;
        Count := DWORD(Length(Writer.Bytes) - Offset);
        if Count > 4096 then Count := 4096;
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
        { Transmit the length and one actual encrypted-body byte; never forge
          a marker before the real partial write succeeds. }
        if (Offset < 5) and ProductFaultTriggered(Writer.FaultStage) then Count := DWORD(5 - Offset);
{$ENDIF}
        if not WriteFile(Writer.Pipe, Writer.Bytes[Offset], Count, Written, nil) or
          (Written = 0) or (Written > Count) then Exit;
        Inc(Offset, Integer(Written));
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
        if (Offset = 5) and ProductFaultTriggered(Writer.FaultStage) then
        begin
          FaultAction := ProductFaultHandoff(Writer.FaultStage, Writer.ChildPID,
            Offset, Length(Writer.Bytes));
          if FaultAction = 2 then
          begin
            TerminateProcess(GetCurrentProcess, 197);
            Exit;
          end;
          if FaultAction = 1 then Exit;
        end;
{$ENDIF}
      end;
      Result := 0;
    except
      Result := 1;
    end;
  finally
    Writer.Free;
  end;
end;

function BuildPayload(const HeaderTemplate: TWireHeader;
  Profile: TConnectServerProfile; Security: TDeviceSecurity;
  const FlowID, Token, Claim, LauncherHash, BinaryHash,
  LauncherPath, BinaryPath, ChildKeyID, ChildNonce: string): TBytes;
var
  Header: TWireHeader;
  Fields: array[0..FieldCount - 1] of TBytes;
  I, Offset, Total: Integer;
  Delegation, Canonical, ProfileText: string;
begin
  Header := HeaderTemplate;
  try
    try
      ProfileText := Profile.ToJSON;
      Fields[FieldProfile] := TEncoding.UTF8.GetBytes(ProfileText);
      Fields[FieldFlow] := TEncoding.UTF8.GetBytes(FlowID);
      Fields[FieldToken] := TEncoding.UTF8.GetBytes(Token);
      Fields[FieldClaim] := TEncoding.UTF8.GetBytes(Claim);
      Fields[FieldLauncherHash] := TEncoding.UTF8.GetBytes(LauncherHash);
      Fields[FieldBinaryHash] := TEncoding.UTF8.GetBytes(BinaryHash);
      Fields[FieldLauncherPath] := TEncoding.UTF8.GetBytes(LauncherPath);
      Fields[FieldBinaryPath] := TEncoding.UTF8.GetBytes(BinaryPath);
      Canonical := HandoffCanonical(CozyText_Handoff_DELEGATION_c9c9ca0d,
        HandoffRoleName(Header.ComponentRole = 1), Claim, ChildKeyID, ChildNonce);
      Delegation := Security.Sign(Canonical);
      Fields[FieldParentDeviceID] := TEncoding.UTF8.GetBytes(Security.DeviceID);
      Fields[FieldChildNonce] := TEncoding.UTF8.GetBytes(ChildNonce);
      Fields[FieldDelegation] := TEncoding.UTF8.GetBytes(Delegation);
      Total := SizeOf(Header);
      for I := 0 to FieldCount - 1 do
      begin
        Check((Length(Fields[I]) > 0) and (Length(Fields[I]) <= MaxHandoffBytes),
          CozyText_Handoff_Text_77a22930);
        Inc(Total, Length(Fields[I]));
        Header.Sizes[I] := DWORD(Length(Fields[I]));
      end;
      Check(Total <= MaxHandoffBytes, CozyText_Handoff_Text_40b4f5b2);
      Header.Magic := HandoffMagic;
      Header.Version := HandoffVersion;
      Header.TotalBytes := DWORD(Total);
      SetLength(Result, Total);
      Move(Header, Result[0], SizeOf(Header));
      Offset := SizeOf(Header);
      for I := 0 to FieldCount - 1 do
      begin
        Move(Fields[I][0], Result[Offset], Length(Fields[I]));
        Inc(Offset, Length(Fields[I]));
      end;
    except
      WipeBytes(Result);
      raise;
    end;
  finally
    for I := 0 to FieldCount - 1 do
      WipeBytes(Fields[I]);
    WipeText(Delegation); WipeText(Canonical); WipeText(ProfileText);
  end;
end;

{ One linearization point for ready/death/cancellation. A manual ready event
  alone is not proof that its owner is alive: death or cancellation already
  visible at acceptance always wins, including simultaneously signalled waits. }
procedure WaitHandoffReadiness(ReadyEvent, ChildProcess, CancelEvent: THandle;
  Deadline: UInt64; const MaintainParent: TProc = nil);
var Handles: array[0..2] of THandle; Count, ReadyIndex, WaitResult, WaitMS: DWORD;
  procedure RequirePending;
  var Status: DWORD;
  begin
    if CancelEvent <> 0 then
    begin
      Status := WaitForSingleObject(CancelEvent, 0);
      Check(Status <> WAIT_OBJECT_0, CozyText_Handoff_HANDOFF_CANCELLED_008c77a9);
      Check(Status = WAIT_TIMEOUT, CozyText_Handoff_HANDOFF_WAIT_FAILED_f021a214);
    end;
    Status := WaitForSingleObject(ChildProcess, 0);
    Check(Status <> WAIT_OBJECT_0, CozyText_Handoff_HANDOFF_CHILD_EXITED_3a4d1e65);
    Check(Status = WAIT_TIMEOUT, CozyText_Handoff_HANDOFF_WAIT_FAILED_f021a214);
  end;
begin
  Check((ReadyEvent <> 0) and (ChildProcess <> 0), CozyText_Handoff_HANDOFF_WAIT_HANDLE_INVALID_29420634);
  RequirePending;
  Check(Remaining(Deadline) > 0, CozyText_Handoff_HANDOFF_READY_TIMEOUT_e041c0ad);
  Count := 0;
  if CancelEvent <> 0 then
  begin Handles[Count] := CancelEvent; Inc(Count); end;
  Handles[Count] := ChildProcess; Inc(Count);
  ReadyIndex := Count; Handles[Count] := ReadyEvent; Inc(Count);
  repeat
    RequirePending;
    Check(Remaining(Deadline) > 0, CozyText_Handoff_HANDOFF_READY_TIMEOUT_e041c0ad);
    { Accept ready before performing any maintenance. The child and cancel
      checks still win over a simultaneously signalled ready event. }
    WaitResult := WaitForSingleObject(ReadyEvent, 0);
    Check((WaitResult = WAIT_OBJECT_0) or (WaitResult = WAIT_TIMEOUT), CozyText_Handoff_HANDOFF_WAIT_FAILED_f021a214);
    if WaitResult = WAIT_OBJECT_0 then
    begin
      RequirePending;
      Check(Remaining(Deadline) > 0, CozyText_Handoff_HANDOFF_READY_TIMEOUT_e041c0ad);
      Exit;
    end;
    if Assigned(MaintainParent) then
    begin
      MaintainParent();
      RequirePending;
      Check(Remaining(Deadline) > 0, CozyText_Handoff_HANDOFF_READY_TIMEOUT_e041c0ad);
    end;
    WaitMS := Remaining(Deadline);
    if Assigned(MaintainParent) and (WaitMS > 1000) then WaitMS := 1000;
    WaitResult := WaitForMultipleObjects(Count, @Handles[0], False, WaitMS);
    RequirePending;
    Check(Remaining(Deadline) > 0, CozyText_Handoff_HANDOFF_READY_TIMEOUT_e041c0ad);
    if WaitResult = WAIT_OBJECT_0 + ReadyIndex then Exit;
    Check(WaitResult = WAIT_TIMEOUT, CozyText_Handoff_HANDOFF_WAIT_FAILED_f021a214);
    Check(Assigned(MaintainParent), CozyText_Handoff_HANDOFF_READY_TIMEOUT_e041c0ad);
  until False;
end;

function LaunchWithHandoff(const BinaryPath: string;
  Profile: TConnectServerProfile; Security: TDeviceSecurity;
  const FlowID, HandoffToken, ClaimCanonical, LauncherSHA512,
  BinarySHA512: string; PreserveParent: Boolean;
  LaunchProfile: THandoffLaunchProfile; const MaintainParent: TProc): Boolean;
var
  Attributes: TSecurityAttributes;
  Startup: TStartupInfoExLocal;
  Process: TProcessInformation;
  ReadPipe, WritePipe, ReplyRead, ReplyWrite, ReadyEvent, ParentProcess, CancelEvent: THandle;
  WriterThread, LauncherFile, BinaryFile, ReducedChild: THandle;
  InheritedHandles: array[0..3] of THandle;
  AttributeBytes: NativeUInt;
  AttributeInitialized: Boolean;
  Header: TWireHeader;
  BootstrapHeader: THandshakeHeader;
  LauncherInfo, BinaryInfo: TByHandleFileInformation;
  Payload, PublicBootstrap, Hello, Wrapping, AAD, Envelope: TBytes;
  FrameSize: DWORD;
  Pins: THandleArray;
  Writer: TPipeWriter;
  LauncherPath, CommandLine, WorkingDirectory, ChildKeyID, ChildNonce, Environment: string;
  ThreadID, ExitCode, WaitResult, Timeout: DWORD;
  Deadline: UInt64;
begin
  Result := False;
  ReadPipe := 0;
  ReducedChild := 0;
  WritePipe := 0; ReplyRead := 0; ReplyWrite := 0;
  ReadyEvent := 0;
  ParentProcess := 0;
  CancelEvent := 0;
  WriterThread := 0;
  LauncherFile := 0;
  BinaryFile := 0;
  Writer := nil;
  AttributeInitialized := False;
  FillChar(Startup, SizeOf(Startup), 0);
  FillChar(Process, SizeOf(Process), 0);
  FillChar(Header, SizeOf(Header), 0);
  try
    CheckABI;
    Check((LaunchProfile = hlpInherit) or
      ((LaunchProfile = hlpOverlayRestricted) and PreserveParent),
      CozyText_Handoff_HANDOFF_RESTRICTED_PROFILE_O_ONLY_f244533e);
    Check((Profile <> nil) and (Security <> nil), CozyText_Handoff_Text_3eb70708);
    ValidateHash(LauncherSHA512);
    ValidateHash(BinarySHA512);
    LauncherPath := ImagePath(GetCurrentProcess);
    ValidatePathText(LauncherPath);
    ValidatePathText(BinaryPath);
    Check(not SameText(LauncherPath, BinaryPath) and
      SameText(ExtractFilePath(LauncherPath), ExtractFilePath(BinaryPath)),
      CozyText_Handoff_Text_c4ea254a);
    PinDirectories(BinaryPath, Pins);
    LauncherFile := OpenSafeImage(LauncherPath, False, LauncherInfo, False, PreserveParent);
    BinaryFile := OpenSafeImage(BinaryPath, False, BinaryInfo);
    Check(not SameIdentity(LauncherInfo, BinaryInfo),
      CozyText_Handoff_Text_b5fb5dfb);
    Check(SameText(HashHandle(LauncherFile), LauncherSHA512) and
      SameText(HashHandle(BinaryFile), BinarySHA512),
      CozyText_Handoff_Text_688dca9d);
    FillChar(Attributes, SizeOf(Attributes), 0);
    Attributes.nLength := SizeOf(Attributes);
    Attributes.bInheritHandle := True;
    Check(CreatePipe(ReadPipe, WritePipe, @Attributes, MaxHandoffBytes),
      CozyText_Handoff_Text_5442867f);
    Check(SetHandleInformation(WritePipe, HANDLE_FLAG_INHERIT, 0),
      CozyText_Handoff_Text_d05ccac1);
    Check(CreatePipe(ReplyRead, ReplyWrite, @Attributes, MaxHandoffBytes), CozyText_Handoff_HANDOFF_REPLY_PIPE_CREATE_dff45df5);
    Check(SetHandleInformation(ReplyRead, HANDLE_FLAG_INHERIT, 0), CozyText_Handoff_HANDOFF_REPLY_PIPE_PROTECT_c587b148);
    ReadyEvent := CreateEventW(@Attributes, True, False, nil);
    Check(ReadyEvent <> 0, CozyText_Handoff_Text_77cbc404);
    Check(DuplicateHandle(GetCurrentProcess, GetCurrentProcess,
      GetCurrentProcess, @ParentProcess,
      SYNCHRONIZE or ProcessQueryLimitedInformation, True, 0),
      CozyText_Handoff_Text_1fe10888);
    Header.ComponentRole := DWORD(Ord(PreserveParent));
    Header.ReadyEvent := UInt64(ReadyEvent);
    Header.ParentProcess := UInt64(ParentProcess);
    Header.ParentID := GetCurrentProcessId;
    Header.LauncherVolume := LauncherInfo.dwVolumeSerialNumber;
    Header.LauncherIndexHigh := LauncherInfo.nFileIndexHigh;
    Header.LauncherIndexLow := LauncherInfo.nFileIndexLow;
    FillChar(BootstrapHeader, SizeOf(BootstrapHeader), 0);
    BootstrapHeader.Magic := HandshakeMagic; BootstrapHeader.Version := HandoffVersion;
    BootstrapHeader.ComponentRole := Header.ComponentRole;
    BootstrapHeader.ReplyPipe := UInt64(ReplyWrite);
    SetLength(PublicBootstrap, SizeOf(BootstrapHeader));
    Move(BootstrapHeader, PublicBootstrap[0], SizeOf(BootstrapHeader));
    InheritedHandles[0] := ReadPipe;
    InheritedHandles[1] := ReadyEvent;
    InheritedHandles[2] := ParentProcess;
    InheritedHandles[3] := ReplyWrite;
    AttributeBytes := 0;
    InitializeAttributeList(nil, 1, 0, AttributeBytes);
    Check((AttributeBytes > 0) and (AttributeBytes <= 65536),
      CozyText_Handoff_Text_00ca898c);
    GetMem(Startup.AttributeList, AttributeBytes);
    Check(InitializeAttributeList(Startup.AttributeList, 1, 0, AttributeBytes),
      CozyText_Handoff_Text_c5ff6d0b);
    AttributeInitialized := True;
    Check(UpdateAttribute(Startup.AttributeList, 0, AttributeHandleList,
      @InheritedHandles[0], SizeOf(InheritedHandles), nil, nil),
      CozyText_Handoff_Text_be913fa0);
    Startup.StartupInfo.cb := SizeOf(Startup);
    if PreserveParent then
      CommandLine := '"' + BinaryPath + CozyText_Handoff_game_overlay_bd4c3917 + UIntToStr(UInt64(ReadPipe))
    else
      CommandLine := '"' + BinaryPath + CozyText_Handoff_game_handoff_2077ff3a + UIntToStr(UInt64(ReadPipe));
    UniqueString(CommandLine);
    RequireProcessCommand(TApiBuffer.Borrow(PWideChar(CommandLine),
      (Length(CommandLine) + 1) * SizeOf(Char), True), Length(CommandLine) + 1);
    WorkingDirectory := ExtractFilePath(BinaryPath);
    Environment := ChildEnvironment;
    Deadline := CozyTick + HandoffTimeoutMS;
    if LaunchProfile = hlpOverlayRestricted then
      CreateOverlayRestrictedProcess(BinaryPath, CommandLine, Environment,
        WorkingDirectory, Startup.StartupInfo, Process)
    else if not CreateProcessW(PWideChar(BinaryPath), PWideChar(CommandLine), nil, nil,
      True, ExtendedStartupInfoPresent or UnicodeEnvironmentFlag, PWideChar(Environment),
      PWideChar(WorkingDirectory), Startup.StartupInfo, Process) then
      raise EHandoff.Create(CozyText_Handoff_HANDOFF_PROCESS_CREATE_FAILED_ee850506);
    Close(Process.hThread);
    { Retain only wait/query and bounded failure-cleanup rights for the exact
      created child. No VM write/operation or thread creation capability is
      needed by this handoff. Do not retain the CreateProcess all-access handle. }
    Check(DuplicateHandle(GetCurrentProcess, Process.hProcess, GetCurrentProcess,
      @ReducedChild, SYNCHRONIZE or ProcessQueryLimitedInformation or
      PROCESS_TERMINATE, False, 0), CozyText_Handoff_Text_1fe10888);
    Close(Process.hProcess);
    Process.hProcess := ReducedChild;
    ReducedChild := 0;
    Close(ReadPipe);
    Close(ReplyWrite);
    WritePublicFrame(WritePipe, PublicBootstrap);
    Hello := ReadHello(ReplyRead, Header.ComponentRole, Deadline, ChildKeyID, ChildNonce, Wrapping);
    Close(ReplyRead);
    Check((GetProcessId(Process.hProcess) = Process.dwProcessId) and
      (WaitForSingleObject(Process.hProcess, 0) = WAIT_TIMEOUT), CozyText_Handoff_HANDOFF_CHILD_EXITED_3a4d1e65);
    if LaunchProfile = hlpOverlayRestricted then
      RequireOverlayRestrictedProcess(Process.hProcess);
    AAD := Transcript(PublicBootstrap, Hello);
    Payload := BuildPayload(Header, Profile, Security, FlowID, HandoffToken,
      ClaimCanonical, LauncherSHA512, BinarySHA512, LauncherPath, BinaryPath,
      ChildKeyID, ChildNonce);
    Envelope := THandoffCipher.Encrypt(Wrapping, Payload, AAD,
      function: Boolean
      begin
        Result := (Remaining(Deadline) = 0) or
          (WaitForSingleObject(Process.hProcess, 0) <> WAIT_TIMEOUT);
      end);
    WipeBytes(Payload);
    FrameSize := Length(Envelope);
    SetLength(Payload, SizeOf(FrameSize) + Length(Envelope));
    Move(FrameSize, Payload[0], SizeOf(FrameSize));
    Move(Envelope[0], Payload[SizeOf(FrameSize)], Length(Envelope));
    WipeBytes(Envelope);
    { B must be able to obtain DELETE access to the held A identity before
      signaling ready. The directory pins remain held by both processes. }
    Close(LauncherFile);
    Close(BinaryFile);
    CancelEvent := CreateEventW(nil, True, False, nil);
    Check(CancelEvent <> 0, CozyText_Handoff_Text_f8b08cd1);
    Writer := TPipeWriter.Create;
    Check(DuplicateHandle(GetCurrentProcess, CancelEvent, GetCurrentProcess,
      @Writer.CancelEvent, 0, False, DUPLICATE_SAME_ACCESS),
      CozyText_Handoff_Text_f98304bb);
    Writer.Pipe := WritePipe;
    WritePipe := 0;
    Writer.Bytes := Payload;
{$IFDEF GAME_PRODUCT_FAULT_TESTS}
    if PreserveParent then Writer.FaultStage := CozyText_Handoff_handoff_body_bo_d217df46
    else Writer.FaultStage := CozyText_Handoff_handoff_body_ab_a5d31a28;
    Writer.ChildPID := Process.dwProcessId;
{$ENDIF}
    Payload := nil;
    WriterThread := BeginThread(nil, 0, WritePipeThread, Writer, 0, ThreadID);
    Check(WriterThread <> 0, CozyText_Handoff_Text_b576dd8a);
    Writer := nil; // the worker now owns its bytes, pipe, and cancellation handle
    Timeout := Remaining(Deadline);
    if Timeout > PipeWriteTimeoutMS then Timeout := PipeWriteTimeoutMS;
    WaitResult := WaitForSingleObject(WriterThread, Timeout);
    if WaitResult = WAIT_TIMEOUT then
      raise EHandoff.Create(CozyText_Handoff_HANDOFF_PIPE_TIMEOUT_59183af5);
    if WaitResult <> WAIT_OBJECT_0 then
      raise EHandoff.Create(CozyText_Handoff_HANDOFF_WAIT_FAILED_f021a214);
    if not GetExitCodeThread(WriterThread, ExitCode) then
      raise EHandoff.Create(CozyText_Handoff_HANDOFF_WAIT_FAILED_f021a214);
    if ExitCode <> 0 then
      raise EHandoff.Create(CozyText_Handoff_HANDOFF_PIPE_FAILED_e2a9e904);
    Close(WriterThread);
    if PreserveParent then
      Inc(Deadline, OverlayReadyTimeoutMS - HandoffTimeoutMS);
    { The same process-start anchor is retained; progress never restarts it. }
    WaitHandoffReadiness(ReadyEvent, Process.hProcess, CancelEvent, Deadline, MaintainParent);
    if LaunchProfile = hlpOverlayRestricted then
      RequireOverlayRestrictedProcess(Process.hProcess);
    Result := True;
  finally
    { Stop and join only the exact child created by this call. The launcher
      then removes only its own created download and personalized image. }
    if not Result and (Process.hProcess <> 0) then
    begin
      TerminateProcess(Process.hProcess, 1);
      WaitForSingleObject(Process.hProcess, ParentExitTimeoutMS);
    end;
    if CancelEvent <> 0 then SetEvent(CancelEvent);
    if WriterThread <> 0 then
    begin
      CancelThreadIO(WriterThread);
      WaitForSingleObject(WriterThread, 2000);
      { If a driver delays cancellation, the self-owned worker still has its
        own handles and will wipe/free its buffer when its pending call ends. }
    end;
    Writer.Free;
    Close(WriterThread);
    Close(CancelEvent);
    Close(Process.hThread);
    Close(Process.hProcess);
    Close(ReducedChild);
    Close(ParentProcess);
    Close(ReadyEvent);
    Close(ReadPipe);
    Close(WritePipe);
    Close(ReplyRead); Close(ReplyWrite);
    Close(LauncherFile);
    Close(BinaryFile);
    CloseAll(Pins);
    if AttributeInitialized then DeleteAttributeList(Startup.AttributeList);
    if Startup.AttributeList <> nil then FreeMem(Startup.AttributeList);
    WipeBytes(Payload); WipeBytes(PublicBootstrap); WipeBytes(Hello);
    WipeBytes(Wrapping); WipeBytes(AAD); WipeBytes(Envelope);
    WipeText(ChildKeyID); WipeText(ChildNonce); WipeText(Environment);
  end;
end;

constructor THandoffContext.Create;
begin
  inherited Create;
  FGate := TGameCallGate.Create;
end;

procedure THandoffContext.CompleteOverlayClaim(const ExpectedCRC64: string);
begin
  FGate.Enter;
  try
    CompleteOverlayClaimCore(ExpectedCRC64);
  finally FGate.Leave; end;
end;

procedure THandoffContext.ConfirmOverlayReady;
begin
  FGate.Enter;
  try
    ConfirmOverlayReadyCore;
  finally FGate.Leave; end;
end;

procedure THandoffContext.CleanupTransferredParent;
begin
  FGate.Enter;
  try
    try CleanupTransferredParentCore;
    except
      Close(FParentImage); Close(FParentProcess); CloseAll(FParentPins);
      { Sharing/DELETE permission refusal is a truthful cleanup failure, not
        a license rejection. Do not kill a valid O merely because Windows
        refused to delete the stopped B. Hash/identity/path failures have no
        captured cleanup Win32 error and remain fatal. No arbitrary path,
        helper, reboot task or permission weakening is used as a fallback. }
      if FParentObservation.ExitObserved and
        FParentObservation.CleanupAttempted and
        (FParentObservation.Win32Error <> 0) then
        FParentRetired := True
      else raise;
    end;
  finally FGate.Leave; end;
end;

function THandoffContext.ParentIsAlive: Boolean;
begin
  FGate.Enter;
  try
    Result := ParentIsAliveCore;
  finally FGate.Leave; end;
end;

procedure THandoffContext.CompleteClaimAndCleanup(const ExpectedCRC64: string);
begin
  FGate.Enter;
  try
    try CompleteClaimAndCleanupCore(ExpectedCRC64);
    except
      Close(FParentProcess);
      raise;
    end;
  finally FGate.Leave; end;
end;

procedure THandoffContext.CleanupBinaryAfterLicense;
begin
  FGate.Enter;
  try
    CleanupBinaryAfterLicenseCore;
  finally FGate.Leave; end;
end;

function THandoffContext.TakeImageIntegrity: TImageIntegrity;
begin
  FGate.Enter;
  try
    Result := TakeImageIntegrityCore;
  finally FGate.Leave; end;
end;

{$IFDEF GAME_HANDOFF_CONTRACT_TESTS}
{$I ..\..\Cozy.Tests\Cozy.Handoff\Cozy.HandoffPipeContracts.inc}
{$I ..\..\Cozy.Tests\Cozy.Handoff\Cozy.HandoffProcessContracts.inc}
{$ENDIF}

initialization
  BindApiPointer(ApiSlot_GetEnvironmentVariableW, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_GetEnvironmentVariableW));
  { API binding only; original startup actions follow unchanged. }

  BindApiPointer(ApiSlot_GetCurrentProcessId, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_GetCurrentProcessId));
  BindApiPointer(ApiSlot_GetLastError, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_GetLastError));
  BindApiPointer(ApiSlot_CloseHandle, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_CloseHandle));
  BindApiPointer(ApiSlot_CreateEventW, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_CreateEventW));
  BindApiPointer(ApiSlot_SetEvent, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_SetEvent));
  BindApiPointer(ApiSlot_WaitForSingleObject, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_WaitForSingleObject));
  BindApiPointer(ApiSlot_WaitForMultipleObjects, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_WaitForMultipleObjects));

  BindApiPointer(ApiSlot_CreateFileW, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_CreateFileW));
  BindApiPointer(ApiSlot_GetFileInformationByHandle, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_GetFileInformationByHandle));
  BindApiPointer(ApiSlot_GetFileType, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_GetFileType));
  BindApiPointer(ApiSlot_GetFileAttributesW, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_GetFileAttributesW));
  BindApiPointer(ApiSlot_GetFullPathNameW, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_GetFullPathNameW));
  BindApiPointer(ApiSlot_ReadFile, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_ReadFile));
  BindApiPointer(ApiSlot_WriteFile, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_WriteFile));
  BindApiPointer(ApiSlot_CreatePipe, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_CreatePipe));
  BindApiPointer(ApiSlot_PeekNamedPipe, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_PeekNamedPipe));
  BindApiPointer(ApiSlot_GetHandleInformation, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_GetHandleInformation));
  BindApiPointer(ApiSlot_SetHandleInformation, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_SetHandleInformation));
  BindApiPointer(ApiSlot_DuplicateHandle, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_DuplicateHandle));
  BindApiPointer(ApiSlot_CreateProcessW, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_CreateProcessW));
  BindApiPointer(ApiSlot_GetProcessId, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_GetProcessId));
  BindApiPointer(ApiSlot_GetExitCodeThread, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_GetExitCodeThread));
  BindApiPointer(ApiSlot_TerminateProcess, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_TerminateProcess));
  BindApiPointer(ApiSlot_MultiByteToWideChar, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_MultiByteToWideChar));
  BindApiPointer(ApiSlot_InitializeAttributeList, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_InitializeProcThreadAttributeList));
  BindApiPointer(ApiSlot_UpdateAttribute, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_UpdateProcThreadAttribute));
  BindApiPointer(ApiSlot_DeleteAttributeList, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_DeleteProcThreadAttributeList));
  BindApiPointer(ApiSlot_QueryImagePath, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_QueryFullProcessImageNameW));
  BindApiPointer(ApiSlot_FinalPathByHandle, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_GetFinalPathNameByHandleW));
  BindApiPointer(ApiSlot_SetFileInfo, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_SetFileInformationByHandle));
  BindApiPointer(ApiSlot_CancelThreadIO, RequireProcAddressHash64(CozyText_Handoff_kernel32_dll_74783ecd, HASH_CancelSynchronousIo));

end.
