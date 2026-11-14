unit Cozy.WinApi;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$IFNDEF MSWINDOWS}
  {$MESSAGE FATAL 'Cozy.WinApi requires Windows.'}
{$ENDIF}
{$IFNDEF CPUX64}
  {$MESSAGE FATAL 'Cozy.WinApi requires the Delphi x64 compiler.'}
{$ENDIF}

interface

{$ALIGN 8}

uses
{ Cozy central text imports. }
  Cozy.Strings.Platform,
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform,
{$ENDIF}

  Winapi.Windows, Winapi.WinSock2;

{ ABI declarations only. Each original unit binds only the functions it uses
  in its own initialization section. This avoids adding unused DLLs to the
  launcher just because the console client also uses clipboard APIs.
  Existing Winapi units remain in uses clauses for their types/constants.
  RTL helpers and compiler atomic intrinsics are deliberately unchanged. }
type
  { Shared Windows x64 ABI records. Consumers alias these exact declarations;
    no CNG provider handle or native SDK object is hidden in the record. }
  TGameStartupInfoEx = record
    StartupInfo: TStartupInfo;
    AttributeList: Pointer;
  end;
  TGameOaepPaddingInfo = record
    Algorithm: PWideChar;
    LabelBytes: PByte;
    LabelSize: DWORD;
  end;
  TGamePkcs1PaddingInfo = record
    pszAlgId: PWideChar;
  end;
  TGameRsaPublicHeader = record
    Magic, BitLength, PublicExponentBytes, ModulusBytes,
      Prime1Bytes, Prime2Bytes: DWORD;
  end;
  { FILE_DISPOSITION_INFO uses BOOLEAN, not the four-byte Win32 BOOL. }
  TGameFileDispositionInfo = record
    DeleteFile: Byte;
  end;
  TGameFileDispositionInfoEx = record
    Flags: DWORD;
  end;
  { MEMORY_BASIC_INFORMATION on Windows x64; PartitionId shares explicit padding. }
  TGameMemoryBasicInformation = record
    BaseAddress, AllocationBase: Pointer;
    AllocationProtect: DWORD;
    PartitionId, AlignmentPadding: Word;
    RegionSize: NativeUInt;
    State, Protect, Kind, TrailingPadding: DWORD;
  end;
  TGameAuthenticatedCipherInfo = record
    Size, Version: DWORD;
    Nonce: PByte;
    NonceSize: DWORD;
    AuthData: PByte;
    AuthDataSize: DWORD;
    Tag: PByte;
    TagSize: DWORD;
    MacContext: PByte;
    MacContextSize, AADSize: DWORD;
    DataSize: UInt64;
    Flags: DWORD;
  end;

  TGameStoragePropertyQuery = record
    PropertyId, QueryType: DWORD;
    AdditionalParameters: array[0..3] of Byte;
  end;
  TGameStorageDeviceDescriptor = record
    Version, Size: DWORD;
    DeviceType, DeviceTypeModifier, RemovableMedia, CommandQueueing: Byte;
    VendorIdOffset, ProductIdOffset, ProductRevisionOffset, SerialNumberOffset,
      BusType, RawPropertiesLength: DWORD;
    RawDeviceProperties: array[0..3] of Byte;
  end;
  TGameMibIfRow2 = record
    InterfaceLuid: UInt64;
    InterfaceIndex: DWORD;
    InterfaceGuid: TGUID;
    AliasName, Description: array[0..256] of WideChar;
    PhysicalAddressLength: DWORD;
    PhysicalAddress, PermanentPhysicalAddress: array[0..31] of Byte;
    Mtu, InterfaceType, TunnelType, MediaType, PhysicalMediumType,
      AccessType, DirectionType: DWORD;
    InterfaceAndOperStatusFlags: Byte;
    StatusPadding: array[0..2] of Byte;
    OperStatus, AdminStatus, MediaConnectState: DWORD;
    NetworkGuid: TGUID;
    ConnectionType, LinkPadding: DWORD;
    TransmitLinkSpeed, ReceiveLinkSpeed, InOctets, InUcastPkts, InNUcastPkts,
      InDiscards, InErrors, InUnknownProtos, InUcastOctets, InMulticastOctets,
      InBroadcastOctets, OutOctets, OutUcastPkts, OutNUcastPkts, OutDiscards,
      OutErrors, OutUcastOctets, OutMulticastOctets, OutBroadcastOctets, OutQLen: UInt64;
  end;
  TGameMibIfTable2 = record
    NumEntries, AlignmentPadding: DWORD;
    Table: array[0..0] of TGameMibIfRow2;
  end;

  TApiConsoleHandler = function(ControlType: DWORD): BOOL; stdcall;
  TApiThreadStart = function(Parameter: Pointer): DWORD; stdcall;
  TApiCreateThread = function(Attributes: PSecurityAttributes; StackSize: NativeUInt;
    StartAddress: TApiThreadStart; Parameter: Pointer; CreationFlags: DWORD;
    ThreadId: PDWORD): THandle; stdcall;
  TApiGetTickCount64 = function: UInt64; stdcall;
  TApiGetCurrentProcess = function: THandle; stdcall;
  TApiGetCurrentProcessId = function: DWORD; stdcall;
  TApiGetLastError = function: DWORD; stdcall;
  TApiGetComputerName = function(Buffer: PWideChar; var Size: DWORD): BOOL; stdcall;
  TApiCloseHandle = function(Handle: THandle): BOOL; stdcall;
  TApiCreateEvent = function(Attributes: PSecurityAttributes; ManualReset, InitialState: BOOL;
    Name: PWideChar): THandle; stdcall;
  TApiCreateEventW = function(Attributes: PSecurityAttributes; ManualReset, InitialState: BOOL;
    Name: PWideChar): THandle; stdcall;
  TApiSetEvent = function(Event: THandle): BOOL; stdcall;
  TApiWaitForSingleObject = function(Handle: THandle; Milliseconds: DWORD): DWORD; stdcall;
  TApiWaitForMultipleObjects = function(Count: DWORD; Handles: Pointer; WaitAll: BOOL;
    Milliseconds: DWORD): DWORD; stdcall;
  TApiSleep = procedure(Milliseconds: DWORD); stdcall;
  TApiCreateFileW = function(FileName: PWideChar; DesiredAccess, ShareMode: DWORD;
    Attributes: PSecurityAttributes; CreationDisposition, FlagsAndAttributes: DWORD;
    TemplateFile: THandle): THandle; stdcall;
  TApiGetFileInformationByHandle = function(Handle: THandle;
    var Information: TByHandleFileInformation): BOOL; stdcall;
  TApiGetFileType = function(Handle: THandle): DWORD; stdcall;
  TApiGetFileAttributesW = function(FileName: PWideChar): DWORD; stdcall;
  TApiGetFullPathNameW = function(FileName: PWideChar; BufferLength: DWORD; Buffer: PWideChar;
    var FilePart: PWideChar): DWORD; stdcall;
  TApiReadFile = function(Handle: THandle; var Buffer; Count: DWORD; var BytesRead: DWORD;
    Overlapped: POverlapped): BOOL; stdcall;
  TApiWriteFile = function(Handle: THandle; const Buffer; Count: DWORD; var BytesWritten: DWORD;
    Overlapped: POverlapped): BOOL; stdcall;
  TApiFlushFileBuffers = function(Handle: THandle): BOOL; stdcall;
  TApiCreatePipe = function(var ReadPipe, WritePipe: THandle; Attributes: PSecurityAttributes;
    Size: DWORD): BOOL; stdcall;
  TApiPeekNamedPipe = function(Pipe: THandle; Buffer: Pointer; BufferSize: DWORD;
    BytesRead, TotalAvailable, BytesLeft: PDWORD): BOOL; stdcall;
  TApiGetHandleInformation = function(Handle: THandle; var Flags: DWORD): BOOL; stdcall;
  TApiSetHandleInformation = function(Handle: THandle; Mask, Flags: DWORD): BOOL; stdcall;
  TApiDuplicateHandle = function(SourceProcess, SourceHandle, TargetProcess: THandle; TargetHandle: PHandle;
    DesiredAccess: DWORD; InheritHandle: BOOL; Options: DWORD): BOOL; stdcall;
  TApiCreateProcessW = function(ApplicationName, CommandLine: PWideChar;
    ProcessAttributes, ThreadAttributes: PSecurityAttributes; InheritHandles: BOOL; CreationFlags: DWORD;
    Environment: Pointer; CurrentDirectory: PWideChar; var StartupInfo: TStartupInfo;
    var ProcessInformation: TProcessInformation): BOOL; stdcall;
  TApiGetProcessId = function(Process: THandle): DWORD; stdcall;
  TApiGetExitCodeThread = function(Thread: THandle; var ExitCode: DWORD): BOOL; stdcall;
  TApiTerminateProcess = function(Process: THandle; ExitCode: UINT): BOOL; stdcall;
  TApiMultiByteToWideChar = function(CodePage: UINT; Flags: DWORD; Input: PAnsiChar; InputLength: Integer;
    Output: PWideChar; OutputLength: Integer): Integer; stdcall;
  TApiGetSystemTimeAsFileTime = procedure(var Time: TFileTime); stdcall;
  TApiGetModuleFileNameW = function(Module: HMODULE; FileName: PWideChar; Size: DWORD): DWORD; stdcall;
  TApiGetModuleHandle = function(ModuleName: PWideChar): HMODULE; stdcall;
  TApiGetStdHandle = function(StandardHandle: DWORD): THandle; stdcall;
  TApiGetConsoleMode = function(Console: THandle; var Mode: DWORD): BOOL; stdcall;
  TApiSetConsoleMode = function(Console: THandle; Mode: DWORD): BOOL; stdcall;
  TApiWriteConsoleW = function(Console: THandle; Buffer: Pointer; Count: DWORD; var Written: DWORD;
    Reserved: Pointer): BOOL; stdcall;
  TApiFillConsoleOutputCharacterW = function(Console: THandle; Character: WideChar; Length: DWORD;
    Position: TCoord; var Written: DWORD): BOOL; stdcall;
  TApiSetConsoleCursorPosition = function(Console: THandle; Position: TCoord): BOOL; stdcall;
  TApiSetConsoleTitleW = function(Title: PWideChar): BOOL; stdcall;
  TApiSetConsoleCtrlHandler = function(Handler: TApiConsoleHandler; Add: BOOL): BOOL; stdcall;
  TApiAllocConsole = function: BOOL; stdcall;
  TApiFreeConsole = function: BOOL; stdcall;
  TApiGlobalSize = function(Memory: HGLOBAL): NativeUInt; stdcall;
  TApiGlobalLock = function(Memory: HGLOBAL): Pointer; stdcall;
  TApiGlobalUnlock = function(Memory: HGLOBAL): BOOL; stdcall;
  TApiOpenClipboard = function(Window: HWND): BOOL; stdcall;
  TApiCloseClipboard = function: BOOL; stdcall;
  TApiGetClipboardData = function(Format: UINT): THandle; stdcall;
  TApiIsClipboardFormatAvailable = function(Format: UINT): BOOL; stdcall;
  TApiRegOpenKeyExW = function(Key: HKEY; SubKey: PWideChar; Options: DWORD; Access: REGSAM;
    var ResultKey: HKEY): LongInt; stdcall;
  TApiRegQueryValueExW = function(Key: HKEY; ValueName: PWideChar; Reserved, Kind: PDWORD; Data: PByte;
    DataSize: PDWORD): LongInt; stdcall;
  TApiRegCloseKey = function(Key: HKEY): LongInt; stdcall;
  TApiWSAStartup = function(Version: Word; var Data: TWSAData): Integer; stdcall;
  TApiWSACleanup = function: Integer; stdcall;
  TApiWSAGetLastError = function: Integer; stdcall;
  TApiGethostbyname = function(Name: PAnsiChar): PHostEnt; stdcall;
  TApiHtons = function(Value: Word): Word; stdcall;
  TApiIoctlsocket = function(Socket: TSocket; Command: LongInt; var Argument: Cardinal): Integer; stdcall;
  TApiSocket = function(AddressFamily, SocketType, Protocol: Integer): TSocket; stdcall;
  TApiConnect = function(Socket: TSocket; const Address: TSockAddr; AddressLength: Integer): Integer; stdcall;
  TApiSelect = function(Count: Integer; ReadSet, WriteSet, ErrorSet, Timeout: Pointer): Integer; stdcall;
  TApiSetsockopt = function(Socket: TSocket; Level, Option: Integer; Value: PAnsiChar;
    ValueLength: Integer): Integer; stdcall;
  TApiGetsockopt = function(Socket: TSocket; Level, Option: Integer; Value: PAnsiChar;
    var ValueLength: Integer): Integer; stdcall;
  TApiShutdown = function(Socket: TSocket; How: Integer): Integer; stdcall;
  TApiClosesocket = function(Socket: TSocket): Integer; stdcall;
  TApiSend = function(Socket: TSocket; const Buffer; Length, Flags: Integer): Integer; stdcall;
  TApiRecv = function(Socket: TSocket; var Buffer; Length, Flags: Integer): Integer; stdcall;

{ Invoked during unit initialization, before any consumer calls Windows. }
function Win64ApiLayoutValid: Boolean;
{$IFDEF GAME_NATIVE_ABI_TESTS}
procedure WriteWin64AbiContract;
{$ENDIF}

implementation

uses System.SysUtils;

{$IF SizeOf(TGameStartupInfoEx) <> 112}
  {$MESSAGE FATAL 'STARTUPINFOEXW layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TGameOaepPaddingInfo) <> 24}
  {$MESSAGE FATAL 'BCRYPT_OAEP_PADDING_INFO layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TGameAuthenticatedCipherInfo) <> 88}
  {$MESSAGE FATAL 'BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO layout mismatch.'}
{$ENDIF}

{$IF SizeOf(TGamePkcs1PaddingInfo) <> 8}
  {$MESSAGE FATAL 'BCRYPT_PKCS1_PADDING_INFO layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TGameRsaPublicHeader) <> 24}
  {$MESSAGE FATAL 'BCRYPT_RSAKEY_BLOB layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TGameFileDispositionInfo) <> 1}
  {$MESSAGE FATAL 'FILE_DISPOSITION_INFO layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TGameFileDispositionInfoEx) <> 4}
  {$MESSAGE FATAL 'FILE_DISPOSITION_INFO_EX layout mismatch.'}
{$ENDIF}

{$IF SizeOf(TGameMemoryBasicInformation) <> 48}
  {$MESSAGE FATAL 'MEMORY_BASIC_INFORMATION layout mismatch.'}
{$ENDIF}

{$IF SizeOf(TGameStoragePropertyQuery) <> 12}
  {$MESSAGE FATAL 'STORAGE_PROPERTY_QUERY layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TGameStorageDeviceDescriptor) <> 40}
  {$MESSAGE FATAL 'STORAGE_DEVICE_DESCRIPTOR layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TGameMibIfRow2) <> 1352}
  {$MESSAGE FATAL 'MIB_IF_ROW2 layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TGameMibIfTable2) <> 1360}
  {$MESSAGE FATAL 'MIB_IF_TABLE2 layout mismatch.'}
{$ENDIF}

function Win64ApiLayoutValid: Boolean;
var
  Startup: TGameStartupInfoEx;
  Attributes: TSecurityAttributes;
  ProcessInfo: TProcessInformation;
  FileInfo: TByHandleFileInformation;
  Overlapped: TOverlapped;
  OAEP: TGameOaepPaddingInfo;
  Cipher: TGameAuthenticatedCipherInfo;
  PKCS1: TGamePkcs1PaddingInfo;
  RSA: TGameRsaPublicHeader;
  Disposition: TGameFileDispositionInfo;
  DispositionEx: TGameFileDispositionInfoEx;
  MemoryRegion: TGameMemoryBasicInformation;
  Storage: TGameStorageDeviceDescriptor;
  Nic: TGameMibIfRow2;
  NicTable: TGameMibIfTable2;
begin
  Result := (SizeOf(Pointer) = 8) and (SizeOf(DWORD) = 4) and
    (SizeOf(BOOL) = 4) and (SizeOf(LongInt) = 4) and
    (SizeOf(Storage) = 40) and
    (NativeUInt(@Storage.SerialNumberOffset) - NativeUInt(@Storage) = 24) and
    (NativeUInt(@Storage.RawDeviceProperties) - NativeUInt(@Storage) = 36) and
    (SizeOf(Nic) = 1352) and
    (NativeUInt(@Nic.PhysicalAddressLength) - NativeUInt(@Nic) = 1056) and
    (NativeUInt(@Nic.PermanentPhysicalAddress) - NativeUInt(@Nic) = 1092) and
    (NativeUInt(@Nic.InterfaceType) - NativeUInt(@Nic) = 1128) and
    (NativeUInt(@Nic.InterfaceAndOperStatusFlags) - NativeUInt(@Nic) = 1152) and
    (NativeUInt(@Nic.TransmitLinkSpeed) - NativeUInt(@Nic) = 1192) and
    (NativeUInt(@Nic.OutQLen) - NativeUInt(@Nic) = 1344) and
    (NativeUInt(@NicTable.Table) - NativeUInt(@NicTable) = 8) and
    (SizeOf(MemoryRegion) = 48) and
    (NativeUInt(@MemoryRegion.AllocationBase) - NativeUInt(@MemoryRegion) = 8) and
    (NativeUInt(@MemoryRegion.AllocationProtect) - NativeUInt(@MemoryRegion) = 16) and
    (NativeUInt(@MemoryRegion.RegionSize) - NativeUInt(@MemoryRegion) = 24) and
    (NativeUInt(@MemoryRegion.State) - NativeUInt(@MemoryRegion) = 32) and
    (NativeUInt(@MemoryRegion.Protect) - NativeUInt(@MemoryRegion) = 36) and
    (NativeUInt(@MemoryRegion.Kind) - NativeUInt(@MemoryRegion) = 40) and
    (SizeOf(TStartupInfo) = 104) and (SizeOf(Startup) = 112) and
    (NativeUInt(@Startup.AttributeList) - NativeUInt(@Startup) = 104) and
    (NativeUInt(@Startup.StartupInfo.lpReserved) - NativeUInt(@Startup) = 8) and
    (NativeUInt(@Startup.StartupInfo.dwFlags) - NativeUInt(@Startup) = 60) and
    (NativeUInt(@Startup.StartupInfo.lpReserved2) - NativeUInt(@Startup) = 72) and
    (NativeUInt(@Startup.StartupInfo.hStdInput) - NativeUInt(@Startup) = 80) and
    (NativeUInt(@Startup.StartupInfo.hStdError) - NativeUInt(@Startup) = 96) and
    (SizeOf(Attributes) = 24) and
    (NativeUInt(@Attributes.lpSecurityDescriptor) - NativeUInt(@Attributes) = 8) and
    (NativeUInt(@Attributes.bInheritHandle) - NativeUInt(@Attributes) = 16) and
    (SizeOf(ProcessInfo) = 24) and
    (NativeUInt(@ProcessInfo.hThread) - NativeUInt(@ProcessInfo) = 8) and
    (NativeUInt(@ProcessInfo.dwProcessId) - NativeUInt(@ProcessInfo) = 16) and
    (NativeUInt(@ProcessInfo.dwThreadId) - NativeUInt(@ProcessInfo) = 20) and
    (SizeOf(FileInfo) = 52) and
    (NativeUInt(@FileInfo.ftCreationTime) - NativeUInt(@FileInfo) = 4) and
    (NativeUInt(@FileInfo.dwVolumeSerialNumber) - NativeUInt(@FileInfo) = 28) and
    (NativeUInt(@FileInfo.nFileSizeHigh) - NativeUInt(@FileInfo) = 32) and
    (NativeUInt(@FileInfo.nFileIndexLow) - NativeUInt(@FileInfo) = 48) and
    (SizeOf(Overlapped) = 32) and
    (NativeUInt(@Overlapped.InternalHigh) - NativeUInt(@Overlapped) = 8) and
    (NativeUInt(@Overlapped.Offset) - NativeUInt(@Overlapped) = 16) and
    (NativeUInt(@Overlapped.hEvent) - NativeUInt(@Overlapped) = 24) and
    (SizeOf(OAEP) = 24) and
    (NativeUInt(@OAEP.LabelBytes) - NativeUInt(@OAEP) = 8) and
    (NativeUInt(@OAEP.LabelSize) - NativeUInt(@OAEP) = 16) and
    (SizeOf(Cipher) = 88) and
    (NativeUInt(@Cipher.Version) - NativeUInt(@Cipher) = 4) and
    (NativeUInt(@Cipher.Nonce) - NativeUInt(@Cipher) = 8) and
    (NativeUInt(@Cipher.NonceSize) - NativeUInt(@Cipher) = 16) and
    (NativeUInt(@Cipher.AuthData) - NativeUInt(@Cipher) = 24) and
    (NativeUInt(@Cipher.AuthDataSize) - NativeUInt(@Cipher) = 32) and
    (NativeUInt(@Cipher.Tag) - NativeUInt(@Cipher) = 40) and
    (NativeUInt(@Cipher.TagSize) - NativeUInt(@Cipher) = 48) and
    (NativeUInt(@Cipher.MacContext) - NativeUInt(@Cipher) = 56) and
    (NativeUInt(@Cipher.MacContextSize) - NativeUInt(@Cipher) = 64) and
    (NativeUInt(@Cipher.AADSize) - NativeUInt(@Cipher) = 68) and
    (NativeUInt(@Cipher.DataSize) - NativeUInt(@Cipher) = 72) and
    (NativeUInt(@Cipher.Flags) - NativeUInt(@Cipher) = 80) and
    (SizeOf(PKCS1) = 8) and (NativeUInt(@PKCS1.pszAlgId) - NativeUInt(@PKCS1) = 0) and
    (SizeOf(RSA) = 24) and
    (NativeUInt(@RSA.BitLength) - NativeUInt(@RSA) = 4) and
    (NativeUInt(@RSA.PublicExponentBytes) - NativeUInt(@RSA) = 8) and
    (NativeUInt(@RSA.ModulusBytes) - NativeUInt(@RSA) = 12) and
    (NativeUInt(@RSA.Prime1Bytes) - NativeUInt(@RSA) = 16) and
    (NativeUInt(@RSA.Prime2Bytes) - NativeUInt(@RSA) = 20) and
    (SizeOf(Disposition) = 1) and
    (NativeUInt(@Disposition.DeleteFile) - NativeUInt(@Disposition) = 0) and
    (SizeOf(DispositionEx) = 4) and
    (NativeUInt(@DispositionEx.Flags) - NativeUInt(@DispositionEx) = 0);
end;

{$IFDEF GAME_NATIVE_ABI_TESTS}
{$I ..\..\Cozy.Tests\Cozy.Platform\Cozy.Win64AbiContract.inc}
{$ENDIF}

initialization
  if not Win64ApiLayoutValid then
    raise EInvalidOpException.Create(CozyText_WinApi_Windows_x64_API_record_layout_mismatch_eb8eeee2);

end.
