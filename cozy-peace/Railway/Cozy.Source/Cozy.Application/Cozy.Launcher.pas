unit Cozy.Launcher;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$B-}
{$ALIGN 8}

interface
{ Cozy central text imports. }
uses
  Cozy.Strings.Application;


function RunLauncher: Integer;

implementation

uses Cozy.Clock,
  Winapi.Windows, System.SysUtils, System.Classes, System.JSON, System.NetEncoding,
  System.Generics.Collections, Cozy.Server.Profile,
  Cozy.Security, Cozy.Bootstrap, Cozy.Handoff, Cozy.Integrity, Cozy.Hashes, Cozy.CodeIntegrity, Cozy.Measurement,
  Cozy.Lifecycle, Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer,
  Cozy.Protection.Engine, Cozy.IssuedA, Cozy.NHW.Guard, Cozy.NHW.ClientGuard,
  Cozy.Overlay.ShutdownGuard;

{ Private API pointers: initialized before application code starts. }
var

  ApiSlot_CloseHandle: TEncodedApiPointer;
  ApiSlot_CreateFileW: TEncodedApiPointer;
  ApiSlot_GetFileInformationByHandle: TEncodedApiPointer;
  ApiSlot_GetFileType: TEncodedApiPointer;
  ApiSlot_WriteFile: TEncodedApiPointer;
  ApiSlot_FlushFileBuffers: TEncodedApiPointer;
  ApiSlot_MultiByteToWideChar: TEncodedApiPointer;


type
  TLauncherConfig = class
  public
    Profile: TConnectServerProfile;
    CodeIntegrity: TCodeIntegrity;
    ImageIntegrity: TImageIntegrity;
    LauncherID: string;
    ExpiresAt: Int64;
    ImageInfo: TByHandleFileInformation;
    ImageDigest: TImageDigest;
    destructor Destroy; override;
  end;
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
  { Public V3 fields are carried inside a separately authenticated issued A. }
  BinaryConfigMarker: AnsiString = CozyText_Launcher_COZYACF3_5e20d861;
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

function MultiByteToWideChar(CodePage: UINT; Flags: DWORD; Input: PAnsiChar; InputLength: Integer;
    Output: PWideChar; OutputLength: Integer): Integer; stdcall;
var
  ApiTarget: TApiMultiByteToWideChar;
begin
  ApiTarget := TApiMultiByteToWideChar(DecodeApiPointer(ApiSlot_MultiByteToWideChar));
  Result := ApiTarget(CodePage, Flags, Input, InputLength, Output, OutputLength);
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

procedure Fail;
begin
  raise EBootstrap.Create(CozyText_Launcher_The_launcher_could_not_complete_securely_b00b69e7);
end;

procedure RequireLauncherWatch(Watch: TCozyNHWGuard);
begin
  if (Watch <> nil) and Watch.Confirmed then Fail;
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

function StrictUTF8(const Bytes: TBytes): string;
var Count: Integer;
begin
  if Length(Bytes) = 0 then Fail;
  Count := MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
    PAnsiChar(@Bytes[0]), Length(Bytes), nil, 0);
  if Count <= 0 then Fail;
  SetLength(Result, Count);
  if MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
    PAnsiChar(@Bytes[0]), Length(Bytes), PWideChar(Result), Count) <> Count then Fail;
end;

destructor TLauncherConfig.Destroy;
begin
  Profile.Free;
  ImageIntegrity.Free;
  CodeIntegrity.Free;
  inherited;
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
    (Copy(Full, 2, 2) <> CozyText_Launcher_Text_f67c3445) or (Pos('/', Full) > 0) or
    (Pos(':', Copy(Full, 3, MaxInt)) > 0) then Fail;
  Part := Copy(Full, 1, 3);
  Pin(Part);
  if Length(Full) = 3 then Exit;
  StartAt := 4;
  for I := 4 to Length(Full) + 1 do
    if (I > Length(Full)) or (Full[I] = '\') then
    begin
      Component := Copy(Full, StartAt, I - StartAt);
      if (Component = '') or (Component = '.') or (Component = CozyText_Launcher_Text_8e1db3f1) or
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

function ParsePublicConfig(const Data: TBytes): TLauncherConfig;
var
  Cursor, I, FieldCount: Integer;
  HostBytes, PortBytes, KeyIdBytes, PublicBytes, TlsNameBytes, PinBytes,
    LauncherBytes, ExpiryBytes, PinStateBytes: TBytes;
  ProfileObj: TJSONObject;
  ProfileText, PublicText: string;
  Encoding: TBase64Encoding;
  Expiry: UInt64;
  function U16(Offset: Integer): Word;
  begin
    if (Offset < 0) or (Offset > Length(Data) - 2) then Fail;
    Result := Word(Data[Offset]) or (Word(Data[Offset + 1]) shl 8);
  end;
  function U32(Offset: Integer): Cardinal;
  begin
    if (Offset < 0) or (Offset > Length(Data) - 4) then Fail;
    Result := Cardinal(Data[Offset]) or (Cardinal(Data[Offset + 1]) shl 8) or
      (Cardinal(Data[Offset + 2]) shl 16) or (Cardinal(Data[Offset + 3]) shl 24);
  end;
  function Field(Expected, Minimum, Maximum: Integer): TBytes;
  var N: Integer;
  begin
    if (Cursor > Length(Data) - 4) or (U16(Cursor) <> Expected) then Fail;
    N := U16(Cursor + 2);
    if (N < Minimum) or (N > Maximum) or
      (N > Length(Data) - Cursor - 4) then Fail;
    Result := Copy(Data, Cursor + 4, N);
    Inc(Cursor, 4 + N);
  end;
  function Hex(const Bytes: TBytes; Upper: Boolean): string;
  const Digits: string = CozyText_Launcher_0123456789abcdef_4f03e899;
  var J: Integer;
  begin
    SetLength(Result, Length(Bytes) * 2);
    for J := 0 to Length(Bytes) - 1 do
    begin
      Result[J * 2 + 1] := Digits[(Bytes[J] shr 4) + 1];
      Result[J * 2 + 2] := Digits[(Bytes[J] and 15) + 1];
    end;
    if Upper then Result := UpperCase(Result);
  end;
  procedure CheckASCII(const Bytes: TBytes);
  var J: Integer;
  begin
    for J := 0 to Length(Bytes) - 1 do
      if (Bytes[J] < $21) or (Bytes[J] > $7E) then Fail;
  end;
begin
  Result := nil;
  ProfileObj := nil;
  Encoding := nil;
  try
    if (Length(Data) < 16) or (Length(Data) > 8192) or
      not CompareMem(@Data[0], PAnsiChar(BinaryConfigMarker), Length(BinaryConfigMarker)) or
      (U16(8) <> 3) or ((U16(10) <> 8) and (U16(10) <> 9)) or (U32(12) <> Cardinal(Length(Data))) then Fail;
    FieldCount := U16(10);
    Cursor := 16;
    HostBytes := Field(1, 1, 253);
    PortBytes := Field(2, 2, 2);
    KeyIdBytes := Field(3, 32, 32);
    PublicBytes := Field(4, 281, 288);
    TlsNameBytes := Field(5, 1, 253);
    PinBytes := Field(6, 32, 32);
    LauncherBytes := Field(7, 12, 12);
    ExpiryBytes := Field(8, 8, 8);
    if FieldCount = 9 then PinStateBytes := Field(9, 1, 6144);
    if Cursor <> Length(Data) then Fail;
    CheckASCII(HostBytes);
    CheckASCII(TlsNameBytes);
    Expiry := 0;
    for I := 0 to 7 do Expiry := Expiry or (UInt64(ExpiryBytes[I]) shl (I * 8));
    if (Expiry = 0) or (Expiry > UInt64(9007199254740991)) then Fail;
    Encoding := TBase64Encoding.Create(0);
    PublicText := Encoding.EncodeBytesToString(PublicBytes);
    ProfileObj := TJSONObject.Create;
    ProfileObj.AddPair(CozyText_Launcher_version_09cb5dbc, TJSONNumber.Create(4));
    ProfileObj.AddPair(CozyText_Launcher_protocol_d0182438, CozyText_Launcher_GAME_CONNECT_4_f75a4f60);
    ProfileObj.AddPair(CozyText_Launcher_host_30b25d6b, StrictUTF8(HostBytes));
    ProfileObj.AddPair(CozyText_Launcher_port_2b84cba3, TJSONNumber.Create(Integer(PortBytes[0]) or (Integer(PortBytes[1]) shl 8)));
    ProfileObj.AddPair(CozyText_Launcher_serverKeyId_e0124a87, Hex(KeyIdBytes, False));
    ProfileObj.AddPair(CozyText_Launcher_serverPublicKey_adaaeeb3, PublicText);
    ProfileObj.AddPair(CozyText_Launcher_tlsServerName_e9480132, StrictUTF8(TlsNameBytes));
    ProfileObj.AddPair(CozyText_Launcher_tlsCertificateSha256_1e17dd4d, Hex(PinBytes, False));
    if FieldCount = 9 then ProfileObj.AddPair(CozyText_Launcher_tlsPinState_7225f272, StrictUTF8(PinStateBytes));
    ProfileText := ProfileObj.ToJSON;
    Result := TLauncherConfig.Create;
    try
      { Reuse the existing strict DNS, RSA blob/key-id and TLS pin validation.
        Public connection information grants no client execution authority. }
      Result.Profile := TConnectServerProfile.FromJSON(ProfileText);
      Result.LauncherID := Hex(LauncherBytes, True);
      Result.ExpiresAt := Int64(Expiry);
    except
      FreeAndNil(Result);
      raise;
    end;
  finally
    Encoding.Free;
    ProfileObj.Free;
    WipeText(ProfileText);
    WipeText(PublicText);
    WipeBytes(HostBytes); WipeBytes(PortBytes); WipeBytes(KeyIdBytes);
    WipeBytes(PublicBytes); WipeBytes(TlsNameBytes); WipeBytes(PinBytes);
    WipeBytes(LauncherBytes); WipeBytes(ExpiryBytes);
    WipeBytes(PinStateBytes);
  end;
end;

function ReadConfig(const LauncherPath: string;
  out LauncherHash, LauncherCRC64: string; var FailureStage: Integer): TLauncherConfig;
var Handle: THandle; Info: TByHandleFileInformation;
  Bytes: TBytes;
  Digest: TImageDigest;
begin
  Result := nil;
  FailureStage := 31012;
  Handle := CreateFileW(PWideChar(LauncherPath), GENERIC_READ,
    FILE_SHARE_READ or FILE_SHARE_DELETE, nil, OPEN_EXISTING,
    OpenReparsePointFlag or FILE_FLAG_SEQUENTIAL_SCAN, 0);
  if Handle = INVALID_HANDLE_VALUE then Fail;
  try
    CheckRegularFile(Handle, Info);
    { Authenticate the exact template and issued settings with the compiled
      public issuer anchor BEFORE interpreting the endpoint or TLS identity.
      The held handle denies concurrent ordinary writes. No unsigned fallback. }
    FailureStage := 31013;
    Bytes := ReadVerifiedIssuedAConfig(Handle, FileSize(Info));
    FailureStage := 31014;
    Result := ParsePublicConfig(Bytes);
    try
      FailureStage := 31015;
      if Result.ExpiresAt <= BootstrapUTCNowMS then Fail;
      Result.ImageInfo := Info;
      FailureStage := 31016;
      Digest := IntegrityHashHandle(Handle);
      Result.ImageDigest := Digest;
      LauncherHash := Digest.SHA512;
      LauncherCRC64 := Digest.CRC64;
      FailureStage := 31017;
      Result.CodeIntegrity := TCodeIntegrity.Create(Handle);
      FailureStage := 31018;
      Result.ImageIntegrity := TImageIntegrity.Create(Handle, Digest.SHA512, Digest.CRC64);
    except
      FreeAndNil(Result);
      raise;
    end;
  finally
    WipeBytes(Bytes);
    CloseHandle(Handle);
  end;
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
    FILE_SHARE_READ or FILE_SHARE_DELETE, nil, OPEN_EXISTING,
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

function DownloadVerifiedBinary(Client: TBootstrapClient;
  const Flow: TBootstrapFlow; const BinaryPath: string;
  out CreatedInfo: TByHandleFileInformation; Lifecycle: TLifecycleReporter;
  Watch: TCozyNHWGuard; const Revalidate: TProc): THandle;
var Handle: THandle; Info: TByHandleFileInformation;
  Bytes, Download: TBytes; Offset: Int64; Written, Part: DWORD; Started: UInt64;
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
      RequireLauncherWatch(Watch);
      if (CozyTick - Started >= DownloadDeadlineMS) or
        (BootstrapUTCNowMS >= Flow.ExpiresAt) then Fail;
      if (Watch <> nil) and Watch.ConsumeRevalidationRequest and
        Assigned(Revalidate) then Revalidate();
      RequireLauncherWatch(Watch);
      Bytes := Client.Chunk(Flow, Offset);
      if Lifecycle <> nil then Lifecycle.Prepare('A', Flow.FlowID, Flow.DownloadTicket);
      if (Length(Bytes) < 1) or
        (Int64(Length(Bytes)) > Flow.Release.Size - Offset) then Fail;
      Move(Bytes[0], Download[Integer(Offset)], Length(Bytes));
      Inc(Offset, Length(Bytes));
      WipeBytes(Bytes);
    end;
    if (CozyTick - Started >= DownloadDeadlineMS) or
      (IntegritySHA512Bytes(Download) <> Flow.Release.SHA512) or
      (IntegrityCRC64Bytes(Download) <> Flow.Release.CRC64) or
      (XXHash3_128Bytes(Download) <> Flow.Release.XXH3_128) or
      (Blake3Bytes(Download) <> Flow.Release.Blake3) then Fail;
    RequireLauncherWatch(Watch);
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
    { Close the writer before Windows maps the image, then reopen/pin and
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

function RunLauncher: Integer;
var Config: TLauncherConfig; Security: TDeviceSecurity;
  Client: TBootstrapClient; Pins: TDirectoryPins; Flow: TBootstrapFlow;
  Grant: TBootstrapGrant; LauncherPath, LauncherHash, LauncherCRC64, BinaryPath: string;
  BinaryHandle: THandle; CreatedInfo: TByHandleFileInformation;
  CurrentLauncher: TImageDigest;
  HandoffSucceeded: Boolean;
  DownloadStarted, FailureElapsed: UInt64;
  ReportNow, ReportBudget: Int64;
  Lifecycle: TLifecycleReporter;
  Watch: TCozyNHWGuard;
  ShutdownGuard: TOverlayShutdownGuard;
begin
  ShutdownGuard := nil;
  Result := 31010;
  Watch := nil;
  Config := nil;
  Security := nil;
  Client := nil;
  Pins := nil;
  BinaryHandle := INVALID_HANDLE_VALUE;
  HandoffSucceeded := False;
  DownloadStarted := 0;
  Lifecycle := nil;
  FillChar(CreatedInfo, SizeOf(CreatedInfo), 0);
  try
    ShutdownGuard := TOverlayShutdownGuard.Create;
    ShutdownGuard.Start;
  try
    try
      LauncherPath := CurrentImagePath;
      Result := 31011;
      Pins := TDirectoryPins.Create(ExtractFileDir(LauncherPath));
      Config := ReadConfig(LauncherPath, LauncherHash, LauncherCRC64, Result);
      Result := 31015;
      if (ParamCount <> 0) or (Config.ExpiresAt <= BootstrapUTCNowMS) then Fail;
      Watch := TCozyNHWClientGuard.Create(nrLauncher);
      Watch.Start;
      Result := 31019;
      BinaryPath := ExtractFilePath(LauncherPath) + BootstrapRandomFileName(CozyText_Launcher_exe_920d934b);
      if SameText(LauncherPath, BinaryPath) then Fail;
      Result := 31020;
      Security := TDeviceSecurity.Create;
      Result := 31021;
      Client := TBootstrapClient.Create(Config.Profile);
      Client.AttachNHW(Watch);
      Result := 31022;
      RequireLauncherWatch(Watch);
      Flow := Client.BeginKeylessFlow(BootstrapRequestID, Config.LauncherID,
        LauncherHash, LauncherCRC64, Security, Config.CodeIntegrity, @Result);
      DownloadStarted := CozyTick;
      try Lifecycle := TLifecycleReporter.Create(Config.Profile, Security, 'A');
      except Lifecycle := nil; end;
      if Lifecycle <> nil then Lifecycle.Prepare('A', Flow.FlowID, Flow.DownloadTicket);
      Result := 31030;
      RequireLauncherWatch(Watch);
      Client.ReportIntegrity(Flow, Security, Config.CodeIntegrity, Config.ImageDigest, False, msMeasured, Config.ImageIntegrity);
      Watch.SecurityContext.SetPhase('A_ATTESTED');
      Watch.SecurityContext.SetPhase('A_ISSUANCE');
      Result := 31031;
      BinaryHandle := DownloadVerifiedBinary(Client, Flow, BinaryPath, CreatedInfo, Lifecycle, Watch,
        procedure
        begin
          { A has no UI. Revalidation runs on this existing owner, never on a
            sensor callback or while an independent response transport is locked. }
          CurrentLauncher := Config.ImageIntegrity.VerifyNow;
          Client.ReportIntegrity(Flow, Security, Config.CodeIntegrity,
            CurrentLauncher, False, msMeasured, Config.ImageIntegrity);
        end);
      Result := 31032;
      try
        CurrentLauncher := Config.ImageIntegrity.VerifyNow;
        if (CurrentLauncher.SHA512 <> LauncherHash) or
          (CurrentLauncher.CRC64 <> LauncherCRC64) or
          (CurrentLauncher.XXH3_128 <> Config.ImageDigest.XXH3_128) or
          (CurrentLauncher.Blake3 <> Config.ImageDigest.Blake3) then
          raise EMeasurement.Create(msChanged, CozyText_Launcher_LAUNCHER_DIGEST_CHANGED_375f57c9);
      except
        on E: Exception do
        begin
          try
            Client.ReportIntegrity(Flow, Security, Config.CodeIntegrity,
              Default(TImageDigest), False, MeasurementFailureStatus(E));
          except
            { Preserve the original failure if the diagnostic cannot be sent. }
          end;
          raise;
        end;
      end;
      { Inventory is measured after download, immediately before server handoff. }
      Result := 31033;
      RequireLauncherWatch(Watch);
      Client.ReportIntegrity(Flow, Security, Config.CodeIntegrity, CurrentLauncher, True, msMeasured, Config.ImageIntegrity);
      if Lifecycle <> nil then
        Lifecycle.Prepare('A', Flow.FlowID, Flow.DownloadTicket);
      Result := 31034;
      RequireLauncherWatch(Watch);
      { Drain already queued causes while A still owns its flow ticket. The
        three independent response workers share this one bounded wait; no
        successful-delivery claim or retired-session grace is introduced. }
      ReportNow := BootstrapUTCNowMS;
      if (ReportNow <= 0) or (Flow.ExpiresAt <= ReportNow) then Fail;
      ReportBudget := Flow.ExpiresAt - ReportNow;
      if ReportBudget > 7000 then ReportBudget := 7000;
      Client.FlushNHWReports(Cardinal(ReportBudget));
      { A server rejection received during the drain must prevent handoff. }
      RequireLauncherWatch(Watch);
      if BootstrapUTCNowMS >= Flow.ExpiresAt then Fail;
      Watch.SecurityContext.SetPhase('A_HANDOFF_TO_B');
      Grant := Client.Finish(Flow, Security, Config.CodeIntegrity);
      Result := 31035;
      RequireLauncherWatch(Watch);
      HandoffSucceeded := LaunchWithHandoff(BinaryPath, Config.Profile, Security,
        Flow.FlowID, Grant.HandoffToken, Grant.ClaimCanonical,
        LauncherHash, Flow.Release.SHA512, False, hlpInherit,
        procedure begin RequireLauncherWatch(Watch); end);
      if HandoffSucceeded then Result := 0;
    except
      on E: Exception do
      begin
        { A bounded, authenticated observation, not a server attestation of
          process behavior. Reuse the existing one-use diagnostic permit.
          DownloadVerifiedBinary refreshes it; no local log is introduced. }
        if (E.Message = CozyText_Launcher_BOOTSTRAP_DOWNLOAD_DEADLINE_32bf226e) and
          (Lifecycle <> nil) and (DownloadStarted <> 0) then
        begin
          FailureElapsed := CozyTick - DownloadStarted;
          if FailureElapsed > 600000 then FailureElapsed := 600000;
          Lifecycle.Note('A', CozyText_Launcher_DOWNLOAD_DEADLINE_29534e3d, CozyText_Launcher_OBSERVED_c5712428,
            TLifecycleReporter.ProcessID, 0, Cardinal(FailureElapsed));
        end;
        { Preserve the numeric failing stage. No UI, credentials, settings,
          exception text, or diagnostic files on the user machine. }
      end;
    end;
  finally
    { Same-process lifetime fallback. Normal cleanup runs first; a wedged OS
      collector cannot leave A alive forever or cause live objects to be freed. }
    if ShutdownGuard <> nil then ShutdownGuard.ArmAfter(15000);
    if Watch <> nil then
    begin
      Watch.SecurityContext.SetPhase('A_SHUTDOWN');
      Watch.RequestStop;
      Watch.StopChildObservers;
      { Ready can race the last observation. Abort only this exact issued
        flow and leave the child's existing lease/cleanup path in control. }
      if HandoffSucceeded and Watch.Confirmed then
      begin
        HandoffSucceeded := False;
        Result := 31035;
      end;
    end;
    if Client <> nil then Client.FlushNHWReports;
    { An authenticated report verdict can arrive while the final drain runs. }
    if HandoffSucceeded and (Watch <> nil) and Watch.Confirmed then
    begin HandoffSucceeded := False; Result := 31035; end;
    if Lifecycle <> nil then
      Lifecycle.Note('A', CozyText_Launcher_SHUTDOWN_BEGIN_f2f74dc0, CozyText_Launcher_REQUESTED_c40bf4d6, TLifecycleReporter.ProcessID);
    if BinaryHandle <> INVALID_HANDLE_VALUE then CloseHandle(BinaryHandle);
    if not HandoffSucceeded then
    begin
      { Remove local files first. A network timeout must not delay disposal. }
      try
        DeleteCreatedBinary(BinaryPath, Flow.Release.SHA512, CreatedInfo);
      except
        { Never widen cleanup to another pathname or file identity. }
      end;
      { Only a fully parsed personalized overlay authorizes self-disposal.
        The administrator's raw build template has no overlay and stays intact. }
      if Config <> nil then
        try
          RemoveOwnImage(LauncherHash, Config.ImageInfo);
          if Lifecycle <> nil then Lifecycle.Note('A', CozyText_Launcher_FILE_CLEANUP_d7a2d602, CozyText_Launcher_REMOVED_07f238cb,
            TLifecycleReporter.ProcessID);
        except
          if Lifecycle <> nil then Lifecycle.Note('A', CozyText_Launcher_FILE_CLEANUP_d7a2d602, CozyText_Launcher_FAILED_8963bda6,
            TLifecycleReporter.ProcessID);
          { Filesystem/OS refusal remains fail-closed; do not schedule a helper. }
        end;
      { Never revoke a successful handoff. A failed flow is closed server-side
        after local cleanup; transport timeout is bounded, with no retries. }
      if Client <> nil then
        try
          Client.AbortFlow(Flow);
          if Lifecycle <> nil then Lifecycle.Note('A', CozyText_Launcher_CLOSE_RESPONSE_88914c2b, CozyText_Launcher_ACKNOWLEDGED_31ddafff);
        except
          if Lifecycle <> nil then Lifecycle.Note('A', CozyText_Launcher_CLOSE_RESPONSE_88914c2b, CozyText_Launcher_FAILED_8963bda6);
          { Server deadlines still invalidate an unreachable flow. }
        end;
    end;
    if Lifecycle <> nil then
    begin
      Lifecycle.Note('A', CozyText_Launcher_SHUTDOWN_BEGIN_f2f74dc0, CozyText_Launcher_REQUESTED_c40bf4d6, TLifecycleReporter.ProcessID);
      Lifecycle.Submit('A', TLifecycleReporter.Tick + 1500);
    end;
    Lifecycle.Free;
    Flow.ClearSecrets;
    Grant.ClearSecrets;
    Client.Free;
    Security.Free;
    Config.Free;
    Pins.Free;
    Watch.Free;
  end;
  finally
    if ShutdownGuard <> nil then
    begin ShutdownGuard.Cancel; ShutdownGuard.Free; end;
  end;
end;

initialization
  { API binding only; original startup actions follow unchanged. }

  BindApiPointer(ApiSlot_CloseHandle, RequireProcAddressHash64(CozyText_Launcher_kernel32_dll_2542b27c, HASH_CloseHandle));
  BindApiPointer(ApiSlot_CreateFileW, RequireProcAddressHash64(CozyText_Launcher_kernel32_dll_2542b27c, HASH_CreateFileW));
  BindApiPointer(ApiSlot_GetFileInformationByHandle, RequireProcAddressHash64(CozyText_Launcher_kernel32_dll_2542b27c, HASH_GetFileInformationByHandle));
  BindApiPointer(ApiSlot_GetFileType, RequireProcAddressHash64(CozyText_Launcher_kernel32_dll_2542b27c, HASH_GetFileType));
  BindApiPointer(ApiSlot_WriteFile, RequireProcAddressHash64(CozyText_Launcher_kernel32_dll_2542b27c, HASH_WriteFile));
  BindApiPointer(ApiSlot_FlushFileBuffers, RequireProcAddressHash64(CozyText_Launcher_kernel32_dll_2542b27c, HASH_FlushFileBuffers));
  BindApiPointer(ApiSlot_MultiByteToWideChar, RequireProcAddressHash64(CozyText_Launcher_kernel32_dll_2542b27c, HASH_MultiByteToWideChar));
  BindApiPointer(ApiSlot_LauncherSetFileInformationByHandle, RequireProcAddressHash64(CozyText_Launcher_kernel32_dll_2542b27c, HASH_SetFileInformationByHandle));

end.
