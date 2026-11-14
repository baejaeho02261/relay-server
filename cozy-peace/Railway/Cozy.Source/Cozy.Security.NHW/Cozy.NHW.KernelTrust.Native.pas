unit Cozy.NHW.KernelTrust.Native;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.Native;

const
  SYSTEM_BOOT_ENVIRONMENT_INFORMATION_CLASS = 90;
  SYSTEM_MODULE_INFORMATION_CLASS = 11;
  SYSTEM_CODEINTEGRITY_INFORMATION_CLASS = 103;
  SYSTEM_SECUREBOOT_INFORMATION_CLASS = 145;

  CODEINTEGRITY_OPTION_ENABLED = $00000001;
  CODEINTEGRITY_OPTION_TESTSIGN = $00000002;
  CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED = $00000080;
  CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED = $00000400;
  CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED = $00000800;
  CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED = $00001000;
  CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED = $00002000;

  KERNEL_MODULE_MAX = 4096;
  KERNEL_MODULE_PATH_BYTES = 256;

type
  TSecureBootSnapshot = record
    NativeValid: Boolean;
    SecureBootCapable: Boolean;
    SecureBootEnabled: Boolean;
    RegistryValid: Boolean;
    RegistryEnabled: Boolean;
  end;

  TCodeIntegritySnapshot = record
    NativeValid: Boolean;
    Options: Cardinal;
    RegistryVBSValid: Boolean;
    RegistryVBSEnabled: Boolean;
    RegistryHVCIValid: Boolean;
    RegistryHVCIEnabled: Boolean;
  end;

  TBootIdentity = record
    LowPart: UInt64;
    HighPart: UInt64;
  end;

  TKernelModuleInfo = record
    Base: NativeUInt;
    ImageSize: Cardinal;
    RawPath: string;
    Path: string;
  end;
  TKernelModuleInfos = TArray<TKernelModuleInfo>;
  TKernelBaseList = TArray<NativeUInt>;

  TDriverFileIdentity = record
    Valid: Boolean;
    VolumeSerial: Cardinal;
    FileIndex: UInt64;
    FileSize: UInt64;
    WriteTime: UInt64;
  end;

function CaptureBootIdentity(out Identity: TBootIdentity): Boolean;
function CaptureSecureBootSnapshot(out Snapshot: TSecureBootSnapshot): Boolean;
function CaptureCodeIntegritySnapshot(out Snapshot: TCodeIntegritySnapshot): Boolean;
function CaptureNativeKernelModules(out Modules: TKernelModuleInfos): Boolean;
function CapturePSAPIKernelModules(out Modules: TKernelModuleInfos): Boolean;
function CapturePSAPIKernelBases(out Bases: TKernelBaseList): Boolean;
procedure KernelModulesToBases(const Modules: TKernelModuleInfos; out Bases: TKernelBaseList);
function KernelBaseListContains(const Bases: TKernelBaseList; Base: NativeUInt): Boolean;
function NormalizeKernelImagePath(const RawPath: string): string;
function GetWindowsRoot: string;
function KernelModuleKey(const M: TKernelModuleInfo): string;
function QueryDriverFileIdentity(const Path: string; out Identity: TDriverFileIdentity): Boolean;
function HashDriverFileSHA256(const Path: string; out DigestHex: string): Boolean;
function LoadRecommendedDriverDenyHashes(out Hashes: TArray<string>): Boolean;

implementation

uses
  Cozy.NHW.WinPointers,
  Cozy.NHW.NativeSafety;

const
  REG_KEY_QUERY_VALUE = $0001;
  OBJ_CASE_INSENSITIVE = $00000040;
  KEY_VALUE_PARTIAL_INFORMATION = 2;
  REG_DWORD_TYPE = 4;
  FILE_READ_DATA = $0001;
  FILE_READ_ATTRIBUTES = $0080;
  FILE_SHARE_DELETE_LOCAL = $00000004;
  OPEN_EXISTING_LOCAL = 3;
  FILE_ATTRIBUTE_NORMAL_LOCAL = $00000080;
  SECUREBOOT_REG_PATH = '\Registry\Machine\SYSTEM\CurrentControlSet\Control\SecureBoot\State';
  DEVICEGUARD_REG_PATH = '\Registry\Machine\SYSTEM\CurrentControlSet\Control\DeviceGuard';
  HVCI_REG_PATH = '\Registry\Machine\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity';

type
  TKernelUnicodeString = record
    Length: Word;
    MaximumLength: Word;
    Buffer: PWideChar;
  end;

  PKernelUnicodeString = ^TKernelUnicodeString;

  TKernelObjectAttributes = record
    Length: Cardinal;
    RootDirectory: THandle;
    ObjectName: PKernelUnicodeString;
    Attributes: Cardinal;
    SecurityDescriptor: Pointer;
    SecurityQualityOfService: Pointer;
  end;

  TKeyValuePartialInfo = record
    TitleIndex: Cardinal;
    DataType: Cardinal;
    DataLength: Cardinal;
    Data: array[0..3] of Byte;
  end;

  TNtQuerySystemInformationLocal = function(InformationClass: Cardinal; Buffer: Pointer;
    BufferSize: Cardinal; ReturnLength: PCardinal): TNTStatus; stdcall;
  TNtOpenKey = function(var KeyHandle: THandle; DesiredAccess: Cardinal;
    ObjectAttributes: Pointer): TNTStatus; stdcall;
  TNtQueryValueKey = function(KeyHandle: THandle; ValueName: Pointer;
    InformationClass: Cardinal; Buffer: Pointer; Length: Cardinal;
    ResultLength: PCardinal): TNTStatus; stdcall;
  TNtCloseLocal = function(Handle: THandle): TNTStatus; stdcall;

  TSystemSecureBootInformation = packed record
    SecureBootEnabled: Byte;
    SecureBootCapable: Byte;
  end;

  TSystemCodeIntegrityInformation = record
    Length: Cardinal;
    CodeIntegrityOptions: Cardinal;
  end;

  TRtlProcessModuleInformation = record
    Section: Pointer;
    MappedBase: Pointer;
    ImageBase: Pointer;
    ImageSize: Cardinal;
    Flags: Cardinal;
    LoadOrderIndex: Word;
    InitOrderIndex: Word;
    LoadCount: Word;
    OffsetToFileName: Word;
    FullPathName: array[0..KERNEL_MODULE_PATH_BYTES - 1] of AnsiChar;
  end;

  TEnumDeviceDrivers = function(Drivers: Pointer; BufferBytes: Cardinal;
    out Needed: Cardinal): BOOL; stdcall;
  TGetDeviceDriverFileNameW = function(ImageBase: Pointer; Filename: PWideChar;
    Size: Cardinal): Cardinal; stdcall;
  TGetWindowsDirectoryW = function(Buffer: PWideChar; Size: Cardinal): Cardinal; stdcall;
  TReadFileLocal = function(FileHandle: THandle; Buffer: Pointer;
    BytesToRead: Cardinal; out BytesRead: Cardinal; Overlapped: Pointer): BOOL; stdcall;

  TBcryptOpenAlgorithmProvider = function(var Alg: Pointer; AlgId, ProviderImplementation: PWideChar;
    Flags: Cardinal): LongInt; stdcall;
  TBcryptGetProperty = function(Handle: Pointer; PropertyName: PWideChar;
    Output: Pointer; OutputBytes: Cardinal; out ResultBytes: Cardinal;
    Flags: Cardinal): LongInt; stdcall;
  TBcryptCreateHash = function(Alg: Pointer; var Hash: Pointer; HashObject: Pointer;
    HashObjectBytes: Cardinal; Secret: Pointer; SecretBytes: Cardinal;
    Flags: Cardinal): LongInt; stdcall;
  TBcryptHashData = function(Hash: Pointer; Input: Pointer; InputBytes: Cardinal;
    Flags: Cardinal): LongInt; stdcall;
  TBcryptFinishHash = function(Hash: Pointer; Output: Pointer; OutputBytes: Cardinal;
    Flags: Cardinal): LongInt; stdcall;
  TBcryptDestroyHash = function(Hash: Pointer): LongInt; stdcall;
  TBcryptCloseAlgorithmProvider = function(Alg: Pointer; Flags: Cardinal): LongInt; stdcall;

var
  NtQuerySystemInformationPtr: TNtQuerySystemInformationLocal = nil;
  NtOpenKeyPtr: TNtOpenKey = nil;
  NtQueryValueKeyPtr: TNtQueryValueKey = nil;
  NtClosePtr: TNtCloseLocal = nil;
  EnumDeviceDriversPtr: TEnumDeviceDrivers = nil;
  GetDeviceDriverFileNamePtr: TGetDeviceDriverFileNameW = nil;
  GetWindowsDirectoryPtr: TGetWindowsDirectoryW = nil;
  ReadFilePtr: TReadFileLocal = nil;
  BcryptOpenPtr: TBcryptOpenAlgorithmProvider = nil;
  BcryptGetPropertyPtr: TBcryptGetProperty = nil;
  BcryptCreateHashPtr: TBcryptCreateHash = nil;
  BcryptHashDataPtr: TBcryptHashData = nil;
  BcryptFinishHashPtr: TBcryptFinishHash = nil;
  BcryptDestroyHashPtr: TBcryptDestroyHash = nil;
  BcryptClosePtr: TBcryptCloseAlgorithmProvider = nil;
  NativeResolved: Boolean = False;
  PSAPIResolved: Boolean = False;
  HashResolved: Boolean = False;

function NtSuccess(Status: TNTStatus): Boolean; inline;
begin
  Result := Status >= 0;
end;

procedure ResolveKernelNative;
var N: HMODULE;
begin
  if NativeResolved then Exit;
  N := WinModule('ntdll.dll');
  if N = 0 then Exit;
  NtQuerySystemInformationPtr := TNtQuerySystemInformationLocal(
    WinExport(N, 'NtQuerySystemInformation'));
  NtOpenKeyPtr := TNtOpenKey(WinExport(N, 'NtOpenKey'));
  NtQueryValueKeyPtr := TNtQueryValueKey(WinExport(N, 'NtQueryValueKey'));
  NtClosePtr := TNtCloseLocal(WinExport(N, 'NtClose'));
  NativeResolved := Assigned(NtQuerySystemInformationPtr) and Assigned(NtOpenKeyPtr) and
    Assigned(NtQueryValueKeyPtr) and Assigned(NtClosePtr);
end;

procedure ResolvePSAPI;
var P, K: HMODULE;
begin
  if PSAPIResolved then Exit;
  P := WinLoadLibrary('psapi.dll');
  K := WinModule('kernel32.dll');
  EnumDeviceDriversPtr := TEnumDeviceDrivers(WinExport(P, 'EnumDeviceDrivers'));
  if not Assigned(EnumDeviceDriversPtr) then
    EnumDeviceDriversPtr := TEnumDeviceDrivers(WinExport(K, 'K32EnumDeviceDrivers'));
  GetDeviceDriverFileNamePtr := TGetDeviceDriverFileNameW(
    WinExport(P, 'GetDeviceDriverFileNameW'));
  if not Assigned(GetDeviceDriverFileNamePtr) then
    GetDeviceDriverFileNamePtr := TGetDeviceDriverFileNameW(
      WinExport(K, 'K32GetDeviceDriverFileNameW'));
  GetWindowsDirectoryPtr := TGetWindowsDirectoryW(WinExport(K, 'GetWindowsDirectoryW'));
  ReadFilePtr := TReadFileLocal(WinExport(K, 'ReadFile'));
  PSAPIResolved := Assigned(GetWindowsDirectoryPtr) and Assigned(ReadFilePtr);
end;

procedure ResolveHash;
var B: HMODULE;
begin
  if HashResolved then Exit;
  B := WinLoadLibrary('bcrypt.dll');
  if B = 0 then Exit;
  BcryptOpenPtr := TBcryptOpenAlgorithmProvider(WinExport(B, 'BCryptOpenAlgorithmProvider'));
  BcryptGetPropertyPtr := TBcryptGetProperty(WinExport(B, 'BCryptGetProperty'));
  BcryptCreateHashPtr := TBcryptCreateHash(WinExport(B, 'BCryptCreateHash'));
  BcryptHashDataPtr := TBcryptHashData(WinExport(B, 'BCryptHashData'));
  BcryptFinishHashPtr := TBcryptFinishHash(WinExport(B, 'BCryptFinishHash'));
  BcryptDestroyHashPtr := TBcryptDestroyHash(WinExport(B, 'BCryptDestroyHash'));
  BcryptClosePtr := TBcryptCloseAlgorithmProvider(WinExport(B, 'BCryptCloseAlgorithmProvider'));
  HashResolved := Assigned(BcryptOpenPtr) and Assigned(BcryptGetPropertyPtr) and
    Assigned(BcryptCreateHashPtr) and Assigned(BcryptHashDataPtr) and
    Assigned(BcryptFinishHashPtr) and Assigned(BcryptDestroyHashPtr) and
    Assigned(BcryptClosePtr);
end;

procedure InitUnicode(const S: string; out U: TKernelUnicodeString);
begin
  U := Default(TKernelUnicodeString);
  if Length(S) > (High(Word) div SizeOf(WideChar)) then Exit;
  U.Buffer := PWideChar(S);
  U.Length := Word(Length(S) * SizeOf(WideChar));
  U.MaximumLength := U.Length;
end;

function QueryRegistryDword(const NativePath, ValueName: string;
  out Value: Cardinal): Boolean;
var
  PathU, NameU: TKernelUnicodeString;
  OA: TKernelObjectAttributes;
  H: THandle;
  Info: TKeyValuePartialInfo;
  Needed: Cardinal;
  Status: TNTStatus;
begin
  Result := False;
  Value := 0;
  ResolveKernelNative;
  if not NativeResolved then Exit;
  InitUnicode(NativePath, PathU);
  InitUnicode(ValueName, NameU);
  if (PathU.Buffer = nil) or (NameU.Buffer = nil) then Exit;
  OA := Default(TKernelObjectAttributes);
  OA.Length := SizeOf(OA);
  OA.ObjectName := @PathU;
  OA.Attributes := OBJ_CASE_INSENSITIVE;
  H := 0;
  Status := NtOpenKeyPtr(H, REG_KEY_QUERY_VALUE, @OA);
  if not NtSuccess(Status) or (H = 0) then Exit;
  try
    Info := Default(TKeyValuePartialInfo);
    Needed := 0;
    Status := NtQueryValueKeyPtr(H, @NameU, KEY_VALUE_PARTIAL_INFORMATION,
      @Info, SizeOf(Info), @Needed);
    if not NtSuccess(Status) then Exit;
    if (Info.DataType <> REG_DWORD_TYPE) or (Info.DataLength <> SizeOf(Cardinal)) then Exit;
    Move(Info.Data[0], Value, SizeOf(Value));
    Result := True;
  finally
    NtClosePtr(H);
  end;
end;

function CaptureBootIdentity(out Identity: TBootIdentity): Boolean;
var
  Buffer: array[0..31] of Byte;
  Returned: Cardinal;
  Status: TNTStatus;
begin
  Result := False;
  Identity := Default(TBootIdentity);
  ResolveKernelNative;
  if not Assigned(NtQuerySystemInformationPtr) then Exit;
  FillChar(Buffer, SizeOf(Buffer), 0);
  Returned := 0;
  Status := NtQuerySystemInformationPtr(SYSTEM_BOOT_ENVIRONMENT_INFORMATION_CLASS,
    @Buffer[0], SizeOf(Buffer), @Returned);
  if not NtSuccess(Status) then Exit;
  if (Returned <> 0) and (Returned < 16) then Exit;
  // SystemBootEnvironmentInformation starts with the boot-session GUID.
  // Treat the 16 bytes only as an opaque equality token; never dereference.
  Move(Buffer[0], Identity.LowPart, SizeOf(UInt64));
  Move(Buffer[8], Identity.HighPart, SizeOf(UInt64));
  if (Identity.LowPart = 0) and (Identity.HighPart = 0) then Exit;
  Result := True;
end;

function CaptureSecureBootSnapshot(out Snapshot: TSecureBootSnapshot): Boolean;
var
  Native: TSystemSecureBootInformation;
  RegValue, Returned: Cardinal;
  Status: TNTStatus;
begin
  Snapshot := Default(TSecureBootSnapshot);
  ResolveKernelNative;
  Native := Default(TSystemSecureBootInformation);
  Returned := 0;
  if NativeResolved then
  begin
    Status := NtQuerySystemInformationPtr(SYSTEM_SECUREBOOT_INFORMATION_CLASS,
      @Native, SizeOf(Native), @Returned);
    if NtSuccess(Status) and ((Returned = 0) or (Returned >= SizeOf(Native))) then
    begin
      Snapshot.NativeValid := True;
      Snapshot.SecureBootEnabled := Native.SecureBootEnabled <> 0;
      Snapshot.SecureBootCapable := Native.SecureBootCapable <> 0;
    end;
  end;
  if QueryRegistryDword(SECUREBOOT_REG_PATH, 'UEFISecureBootEnabled', RegValue) then
  begin
    Snapshot.RegistryValid := True;
    Snapshot.RegistryEnabled := RegValue <> 0;
  end;
  Result := Snapshot.NativeValid or Snapshot.RegistryValid;
end;

function CaptureCodeIntegritySnapshot(out Snapshot: TCodeIntegritySnapshot): Boolean;
var
  Native: TSystemCodeIntegrityInformation;
  RegValue, Returned: Cardinal;
  Status: TNTStatus;
begin
  Snapshot := Default(TCodeIntegritySnapshot);
  ResolveKernelNative;
  Native := Default(TSystemCodeIntegrityInformation);
  Native.Length := SizeOf(Native);
  Returned := 0;
  if NativeResolved then
  begin
    Status := NtQuerySystemInformationPtr(SYSTEM_CODEINTEGRITY_INFORMATION_CLASS,
      @Native, SizeOf(Native), @Returned);
    if NtSuccess(Status) and (Native.Length >= SizeOf(Native)) then
    begin
      Snapshot.NativeValid := True;
      Snapshot.Options := Native.CodeIntegrityOptions;
    end;
  end;
  if QueryRegistryDword(DEVICEGUARD_REG_PATH, 'EnableVirtualizationBasedSecurity', RegValue) then
  begin
    Snapshot.RegistryVBSValid := True;
    Snapshot.RegistryVBSEnabled := RegValue <> 0;
  end;
  if QueryRegistryDword(HVCI_REG_PATH, 'Enabled', RegValue) then
  begin
    Snapshot.RegistryHVCIValid := True;
    Snapshot.RegistryHVCIEnabled := RegValue <> 0;
  end;
  Result := Snapshot.NativeValid or Snapshot.RegistryVBSValid or Snapshot.RegistryHVCIValid;
end;

function ReadAnsiPath(P: PAnsiChar; MaxBytes: Integer): AnsiString;
var N: Integer;
begin
  Result := '';
  if (P = nil) or (MaxBytes <= 0) then Exit;
  N := 0;
  while (N < MaxBytes) and (P[N] <> #0) do Inc(N);
  if N = 0 then Exit;
  SetString(Result, P, N);
end;

procedure SortKernelModules(var Modules: TKernelModuleInfos);
var I, J: Integer; V: TKernelModuleInfo;
begin
  for I := 1 to High(Modules) do
  begin
    V := Modules[I];
    J := I;
    while (J > 0) and (Modules[J-1].Base > V.Base) do
    begin
      Modules[J] := Modules[J-1];
      Dec(J);
    end;
    Modules[J] := V;
  end;
end;

function GetWindowsRoot: string;
var B: array[0..32767] of WideChar; N: Cardinal;
begin
  Result := '';
  ResolvePSAPI;
  if not Assigned(GetWindowsDirectoryPtr) then Exit;
  N := GetWindowsDirectoryPtr(@B[0], Length(B));
  if (N = 0) or (N >= Cardinal(Length(B))) then Exit;
  SetString(Result, PWideChar(@B[0]), N);
end;

function NormalizeKernelImagePath(const RawPath: string): string;
var W: string;
begin
  Result := StringReplace(RawPath, '/', '\', [rfReplaceAll]);
  if Result = '' then Exit;
  W := GetWindowsRoot;
  if SameText(Copy(Result, 1, 12), '\SystemRoot\') then
  begin
    if W <> '' then Result := W + Copy(Result, 12, MaxInt);
    Exit;
  end;
  if SameText(Copy(Result, 1, 4), '\??\') then
  begin
    Result := Copy(Result, 5, MaxInt);
    Exit;
  end;
  if SameText(Copy(Result, 1, 9), 'System32\') and (W <> '') then
    Result := W + '\' + Result;
end;

function KernelModuleKey(const M: TKernelModuleInfo): string;
begin
  Result := IntToHex(UInt64(M.Base), 16) + '|' + LowerCase(M.RawPath);
end;

function CaptureNativeKernelModules(out Modules: TKernelModuleInfos): Boolean;
var
  Data: TBytes;
  Failure: TNTStatus;
  Count: Cardinal;
  I: Integer;
  HeaderBytes, RequiredBytes, Pos: NativeUInt;
  E: ^TRtlProcessModuleInformation;
  Item: TKernelModuleInfo;
  PathAnsi: AnsiString;
begin
  Result := False;
  Modules := nil;
  if SizeOf(TRtlProcessModuleInformation) <> 296 then Exit;
  if not FetchSystemData(SYSTEM_MODULE_INFORMATION_CLASS, 128 * 1024,
       32 * 1024 * 1024, Data, Failure) then Exit;
  if Length(Data) < 8 then Exit;
  Move(Data[0], Count, SizeOf(Count));
  if (Count = 0) or (Count > KERNEL_MODULE_MAX) then Exit;
  HeaderBytes := 8;
  RequiredBytes := HeaderBytes + NativeUInt(Count) * SizeOf(TRtlProcessModuleInformation);
  if RequiredBytes > NativeUInt(Length(Data)) then Exit;
  SetLength(Modules, Count);
  for I := 0 to Integer(Count) - 1 do
  begin
    Pos := HeaderBytes + NativeUInt(I) * SizeOf(TRtlProcessModuleInformation);
    if not NHWAddressSpan(NativeUInt(@Data[0]) + Pos,
         SizeOf(TRtlProcessModuleInformation)) then Exit(False);
    E := Pointer(NativeUInt(@Data[0]) + Pos);
    if (E^.ImageBase = nil) or (NativeUInt(E^.ImageBase) < $10000) or
       (E^.ImageSize = 0) or (E^.ImageSize > $80000000) or
       (E^.OffsetToFileName >= KERNEL_MODULE_PATH_BYTES) then Exit(False);
    PathAnsi := ReadAnsiPath(@E^.FullPathName[0], KERNEL_MODULE_PATH_BYTES);
    if PathAnsi = '' then Exit(False);
    Item := Default(TKernelModuleInfo);
    Item.Base := NativeUInt(E^.ImageBase);
    Item.ImageSize := E^.ImageSize;
    Item.RawPath := string(PathAnsi);
    Item.Path := NormalizeKernelImagePath(Item.RawPath);
    Modules[I] := Item;
  end;
  SortKernelModules(Modules);
  for I := 1 to High(Modules) do
    if Modules[I].Base = Modules[I-1].Base then Exit(False);
  Result := True;
end;

procedure SortBases(var Bases: TKernelBaseList);
var I, J: Integer; V: NativeUInt;
begin
  for I := 1 to High(Bases) do
  begin
    V := Bases[I];
    J := I;
    while (J > 0) and (Bases[J-1] > V) do
    begin
      Bases[J] := Bases[J-1];
      Dec(J);
    end;
    Bases[J] := V;
  end;
end;

function CapturePSAPIKernelModules(out Modules: TKernelModuleInfos): Boolean;
var
  Buffer: array[0..KERNEL_MODULE_MAX - 1] of Pointer;
  PathBuffer: array[0..32767] of WideChar;
  Needed, Count, I, N: Cardinal;
  Item: TKernelModuleInfo;
begin
  Result := False;
  Modules := nil;
  ResolvePSAPI;
  if not Assigned(EnumDeviceDriversPtr) or
     not Assigned(GetDeviceDriverFileNamePtr) then Exit;
  FillChar(Buffer, SizeOf(Buffer), 0);
  Needed := 0;
  if not EnumDeviceDriversPtr(@Buffer[0], SizeOf(Buffer), Needed) then Exit;
  if (Needed = 0) or (Needed > SizeOf(Buffer)) or
     ((Needed mod SizeOf(Pointer)) <> 0) then Exit;
  Count := Needed div SizeOf(Pointer);
  if (Count = 0) or (Count > KERNEL_MODULE_MAX) then Exit;
  SetLength(Modules, Count);
  for I := 0 to Count - 1 do
  begin
    // Windows 11 24H2 can return zero addresses when SeDebugPrivilege is absent.
    // Treat that as an unavailable view, never as a mismatch.
    if (Buffer[I] = nil) or (NativeUInt(Buffer[I]) < $10000) then Exit(False);
    FillChar(PathBuffer, SizeOf(PathBuffer), 0);
    N := GetDeviceDriverFileNamePtr(Buffer[I], @PathBuffer[0], Length(PathBuffer));
    if (N = 0) or (N >= Cardinal(Length(PathBuffer))) then Exit(False);
    Item := Default(TKernelModuleInfo);
    Item.Base := NativeUInt(Buffer[I]);
    SetString(Item.RawPath, PWideChar(@PathBuffer[0]), N);
    Item.Path := NormalizeKernelImagePath(Item.RawPath);
    if Item.RawPath = '' then Exit(False);
    Modules[I] := Item;
  end;
  SortKernelModules(Modules);
  for I := 1 to Count - 1 do
    if Modules[I].Base = Modules[I-1].Base then Exit(False);
  Result := True;
end;

procedure KernelModulesToBases(const Modules: TKernelModuleInfos;
  out Bases: TKernelBaseList);
var I: Integer;
begin
  SetLength(Bases, Length(Modules));
  for I := 0 to High(Modules) do Bases[I] := Modules[I].Base;
end;

function CapturePSAPIKernelBases(out Bases: TKernelBaseList): Boolean;
var Modules: TKernelModuleInfos;
begin
  Result := CapturePSAPIKernelModules(Modules);
  if Result then KernelModulesToBases(Modules, Bases)
  else Bases := nil;
end;

function KernelBaseListContains(const Bases: TKernelBaseList; Base: NativeUInt): Boolean;
var L, R, M: Integer;
begin
  Result := False;
  L := 0;
  R := High(Bases);
  while L <= R do
  begin
    M := L + ((R - L) div 2);
    if Bases[M] = Base then Exit(True);
    if Bases[M] < Base then L := M + 1 else R := M - 1;
  end;
end;

function FileTime64(const F: TFileTime): UInt64; inline;
begin
  Result := (UInt64(F.dwHighDateTime) shl 32) or UInt64(F.dwLowDateTime);
end;

function QueryDriverFileIdentity(const Path: string; out Identity: TDriverFileIdentity): Boolean;
var H: THandle; Info: BY_HANDLE_FILE_INFORMATION;
begin
  Identity := Default(TDriverFileIdentity);
  Result := False;
  if (Path = '') or (Pos(#0, Path) <> 0) then Exit;
  H := WinCreateFile(PWideChar(Path), FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE_LOCAL, nil,
    OPEN_EXISTING_LOCAL, FILE_ATTRIBUTE_NORMAL_LOCAL, 0);
  if H = INVALID_HANDLE_VALUE then Exit;
  try
    if not WinGetFileInformationByHandle(H, Info) then Exit;
    Identity.Valid := True;
    Identity.VolumeSerial := Info.dwVolumeSerialNumber;
    Identity.FileIndex := (UInt64(Info.nFileIndexHigh) shl 32) or UInt64(Info.nFileIndexLow);
    Identity.FileSize := (UInt64(Info.nFileSizeHigh) shl 32) or UInt64(Info.nFileSizeLow);
    Identity.WriteTime := FileTime64(Info.ftLastWriteTime);
    Result := True;
  finally
    WinCloseHandle(H);
  end;
end;

function BytesToHex(const Data: array of Byte): string;
const Hex: PChar = '0123456789ABCDEF';
var I, P: Integer;
begin
  SetLength(Result, Length(Data) * 2);
  P := 1;
  for I := 0 to High(Data) do
  begin
    Result[P] := Hex[(Data[I] shr 4) + 1];
    Result[P+1] := Hex[(Data[I] and $0F) + 1];
    Inc(P, 2);
  end;
end;

function HashDriverFileSHA256(const Path: string; out DigestHex: string): Boolean;
var
  H: THandle;
  Alg, Hash: Pointer;
  ObjectBytes, HashBytes, Returned, ReadBytes: Cardinal;
  ObjectBuffer, Digest, Chunk: TBytes;
  Status: LongInt;
begin
  Result := False;
  DigestHex := '';
  ResolvePSAPI;
  ResolveHash;
  if not PSAPIResolved or not HashResolved then Exit;
  H := WinCreateFile(PWideChar(Path), FILE_READ_DATA or FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE_LOCAL, nil,
    OPEN_EXISTING_LOCAL, FILE_ATTRIBUTE_NORMAL_LOCAL, 0);
  if H = INVALID_HANDLE_VALUE then Exit;
  Alg := nil;
  Hash := nil;
  try
    Status := BcryptOpenPtr(Alg, PWideChar('SHA256'), nil, 0);
    if Status <> 0 then Exit;
    ObjectBytes := 0;
    Returned := 0;
    if BcryptGetPropertyPtr(Alg, PWideChar('ObjectLength'), @ObjectBytes,
         SizeOf(ObjectBytes), Returned, 0) <> 0 then Exit;
    HashBytes := 0;
    Returned := 0;
    if BcryptGetPropertyPtr(Alg, PWideChar('HashDigestLength'), @HashBytes,
         SizeOf(HashBytes), Returned, 0) <> 0 then Exit;
    if (ObjectBytes = 0) or (ObjectBytes > 1024 * 1024) or
       (HashBytes <> 32) then Exit;
    SetLength(ObjectBuffer, ObjectBytes);
    SetLength(Digest, HashBytes);
    if BcryptCreateHashPtr(Alg, Hash, @ObjectBuffer[0], ObjectBytes,
         nil, 0, 0) <> 0 then Exit;
    SetLength(Chunk, 64 * 1024);
    while True do
    begin
      ReadBytes := 0;
      if not ReadFilePtr(H, @Chunk[0], Length(Chunk), ReadBytes, nil) then Exit;
      if ReadBytes = 0 then Break;
      if ReadBytes > Cardinal(Length(Chunk)) then Exit;
      if BcryptHashDataPtr(Hash, @Chunk[0], ReadBytes, 0) <> 0 then Exit;
    end;
    if BcryptFinishHashPtr(Hash, @Digest[0], HashBytes, 0) <> 0 then Exit;
    DigestHex := BytesToHex(Digest);
    Result := Length(DigestHex) = 64;
  finally
    if Hash <> nil then BcryptDestroyHashPtr(Hash);
    if Alg <> nil then BcryptClosePtr(Alg, 0);
    WinCloseHandle(H);
  end;
end;

function ReadWholeFileBytes(const Path: string; out Data: TBytes): Boolean;
const MAX_POLICY_BYTES = 16 * 1024 * 1024;
var H: THandle; Info: BY_HANDLE_FILE_INFORMATION; Size64: UInt64; Pos: Cardinal; ReadBytes: Cardinal;
begin
  Result := False;
  Data := nil;
  ResolvePSAPI;
  if not Assigned(ReadFilePtr) then Exit;
  H := WinCreateFile(PWideChar(Path), FILE_READ_DATA or FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE_LOCAL, nil,
    OPEN_EXISTING_LOCAL, FILE_ATTRIBUTE_NORMAL_LOCAL, 0);
  if H = INVALID_HANDLE_VALUE then Exit;
  try
    if not WinGetFileInformationByHandle(H, Info) then Exit;
    Size64 := (UInt64(Info.nFileSizeHigh) shl 32) or UInt64(Info.nFileSizeLow);
    if (Size64 = 0) or (Size64 > MAX_POLICY_BYTES) or (Size64 > UInt64(High(Integer))) then Exit;
    SetLength(Data, Integer(Size64));
    Pos := 0;
    while Pos < Cardinal(Length(Data)) do
    begin
      ReadBytes := 0;
      if not ReadFilePtr(H, @Data[Pos], Cardinal(Length(Data)) - Pos, ReadBytes, nil) then Exit;
      if (ReadBytes = 0) or (ReadBytes > Cardinal(Length(Data)) - Pos) then Exit;
      Inc(Pos, ReadBytes);
    end;
    Result := True;
  finally
    WinCloseHandle(H);
  end;
end;

function IsHexByte(C: Byte): Boolean; inline;
begin
  Result := ((C >= Ord('0')) and (C <= Ord('9'))) or
    ((C >= Ord('A')) and (C <= Ord('F'))) or
    ((C >= Ord('a')) and (C <= Ord('f')));
end;

function UpperHexChar(C: Byte): Char; inline;
begin
  if (C >= Ord('a')) and (C <= Ord('f')) then Dec(C, 32);
  Result := Char(C);
end;

function AppendHash(var Hashes: TArray<string>; const H: string): Boolean;
var N: Integer;
begin
  Result := Length(H) = 64;
  if not Result then Exit;
  N := Length(Hashes);
  SetLength(Hashes, N + 1);
  Hashes[N] := H;
end;

procedure ScanAsciiHashes(const Data: TBytes; var Hashes: TArray<string>);
const Needle: AnsiString = 'Hash="';
var I, J: Integer; H: string; Match: Boolean;
begin
  I := 0;
  while I + Length(Needle) + 64 < Length(Data) do
  begin
    Match := True;
    for J := 1 to Length(Needle) do
      if Data[I + J - 1] <> Ord(Needle[J]) then
      begin Match := False; Break; end;
    if not Match then begin Inc(I); Continue; end;
    Inc(I, Length(Needle));
    if I + 64 >= Length(Data) then Break;
    SetLength(H, 64);
    Match := True;
    for J := 0 to 63 do
    begin
      if not IsHexByte(Data[I + J]) then begin Match := False; Break; end;
      H[J+1] := UpperHexChar(Data[I + J]);
    end;
    if Match and (Data[I + 64] = Ord('"')) then AppendHash(Hashes, H);
    Inc(I, 64);
  end;
end;

procedure ScanUtf16LEHashes(const Data: TBytes; var Hashes: TArray<string>);
const Needle: string = 'Hash="';
var I, J, P: Integer; H: string; Match: Boolean; C: Byte;
begin
  I := 0;
  while I + Length(Needle) * 2 + 64 * 2 + 2 <= Length(Data) do
  begin
    Match := True;
    for J := 1 to Length(Needle) do
    begin
      P := I + (J - 1) * 2;
      if (Data[P] <> Ord(Needle[J])) or (Data[P+1] <> 0) then
      begin Match := False; Break; end;
    end;
    if not Match then begin Inc(I, 2); Continue; end;
    Inc(I, Length(Needle) * 2);
    SetLength(H, 64);
    Match := True;
    for J := 0 to 63 do
    begin
      P := I + J * 2;
      C := Data[P];
      if (Data[P+1] <> 0) or not IsHexByte(C) then
      begin Match := False; Break; end;
      H[J+1] := UpperHexChar(C);
    end;
    P := I + 64 * 2;
    if Match and (Data[P] = Ord('"')) and (Data[P+1] = 0) then
      AppendHash(Hashes, H);
    Inc(I, 64 * 2);
  end;
end;

function LoadRecommendedDriverDenyHashes(out Hashes: TArray<string>): Boolean;
var
  W, Path: string;
  Data: TBytes;
begin
  Result := False;
  Hashes := nil;
  W := GetWindowsRoot;
  if W = '' then Exit;
  Path := W + '\schemas\CodeIntegrity\ExamplePolicies\RecommendedDriverBlock_Enforced.xml';
  if not ReadWholeFileBytes(Path, Data) then Exit;
  ScanAsciiHashes(Data, Hashes);
  if Length(Hashes) = 0 then ScanUtf16LEHashes(Data, Hashes);
  Result := Length(Hashes) > 0;
end;

end.
