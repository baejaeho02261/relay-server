unit Cozy.Integrity;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity,

  Winapi.Windows, System.SysUtils, Cozy.Measurement, Cozy.Lifetime;

type
  EImageIntegrity = class(Exception);
  TImageDigest = record
    SHA512, CRC64, XXH3_128, Blake3: string;
    Size: UInt64;
  end;
  { A duplicate of the verified own-image handle remains open after the
    directory entry is removed. This is file evidence, not memory attestation. }
  TImageIntegrity = class
  private
    FGate: TGameCallGate;
    FHandle, FReadHandle: THandle;
    FInfo: TByHandleFileInformation;
    FExpected: TImageDigest;
    FLock: TObject;
    function VerifyNowCore(const Budget: TMeasurementBudget): TImageDigest;
  public
    constructor Create(Handle: THandle; const SHA512, CRC64: string);
    destructor Destroy; override;
    function VerifyNow: TImageDigest; overload;
    function VerifyNow(const Budget: TMeasurementBudget): TImageDigest; overload;
  end;

{ Caller position is PRESERVED, including through DuplicateHandle aliases.
  The bounded overload never silently publishes a partial digest. }
function IntegrityHashHandle(Handle: THandle): TImageDigest; overload;
function IntegrityHashHandle(Handle: THandle; const Budget: TMeasurementBudget): TImageDigest; overload;
function IntegrityHashFile(const FileName: string): TImageDigest; overload;
function IntegrityHashFile(const FileName: string; const Budget: TMeasurementBudget): TImageDigest; overload;
function IntegritySHA512Bytes(const Bytes: TBytes): string;
function IntegrityCRC64Bytes(const Bytes: TBytes): string;
function IntegritySHA512Text(const Text: string): string;
{ SHA-256 is retained for stable identity, pins and opaque token compatibility. }
function IntegritySHA256Bytes(const Bytes: TBytes): string;
function IntegritySHA256Text(const Text: string): string;
function IntegrityMachineID: string;

implementation

uses
  System.Classes, System.SyncObjs, Cozy.Hashes, Cozy.Hashes.Workers, Cozy.CrcLayers, Cozy.Api.Contracts,
  Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer;

{ Private API pointers: initialized before application code starts. }
var
  ApiSlot_CloseHandle: TEncodedApiPointer;
  ApiSlot_CreateFileW: TEncodedApiPointer;
  ApiSlot_GetFileInformationByHandle: TEncodedApiPointer;
  ApiSlot_GetFileType: TEncodedApiPointer;
  ApiSlot_ReadFile: TEncodedApiPointer;
  ApiSlot_DuplicateHandle: TEncodedApiPointer;
  ApiSlot_RegOpenKeyExW: TEncodedApiPointer;
  ApiSlot_RegQueryValueExW: TEncodedApiPointer;
  ApiSlot_RegCloseKey: TEncodedApiPointer;


const
  OpenReparsePointFlag: DWORD = $00200000;
  FirmwareRSMB: DWORD = $52534D42;

type
  TCngHandle = NativeUInt;
  TCngStatus = LongInt;

type
  TResolved_BCryptOpenAlgorithmProvider = function(out Algorithm: TCngHandle;
  AlgorithmName, ImplementationName: PWideChar; Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptOpenAlgorithmProvider: TEncodedApiPointer;
type
  TResolved_BCryptCreateHash = function(Algorithm: TCngHandle; out Hash: TCngHandle;
  HashObject: PByte; HashObjectSize: DWORD; Secret: PByte;
  SecretSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptCreateHash: TEncodedApiPointer;
type
  TResolved_BCryptHashData = function(Hash: TCngHandle; Input: PByte;
  InputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptHashData: TEncodedApiPointer;
type
  TResolved_BCryptFinishHash = function(Hash: TCngHandle; Output: PByte;
  OutputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptFinishHash: TEncodedApiPointer;
type
  TResolved_BCryptDestroyHash = function(Hash: TCngHandle): TCngStatus; stdcall;
var
  ApiSlot_BCryptDestroyHash: TEncodedApiPointer;
type
  TResolved_BCryptCloseAlgorithmProvider = function(Algorithm: TCngHandle;
  Flags: DWORD): TCngStatus; stdcall;
var
  ApiSlot_BCryptCloseAlgorithmProvider: TEncodedApiPointer;
type
  TResolved_ReadFirmwareTable = function(ProviderSignature, TableID: DWORD;
  Buffer: Pointer; BufferSize: DWORD): DWORD; stdcall;
var
  ApiSlot_ReadFirmwareTable: TEncodedApiPointer;

{ POINTER WRAPPERS 1 BEGIN }
function GetCurrentProcess: THandle; stdcall;
begin
  { Documented Windows current-process pseudo-handle. No lookup, syscall,
    foreign-process access or dependency on undocumented TEB offsets. }
  Result := THandle(NativeInt(-1));
end;

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

function ReadFile(Handle: THandle; var Buffer; Count: DWORD; var BytesRead: DWORD;
    Overlapped: POverlapped): BOOL; stdcall;
var
  ApiTarget: TApiReadFile;
begin
  ApiTarget := TApiReadFile(DecodeApiPointer(ApiSlot_ReadFile));
  Result := ApiTarget(Handle, Buffer, Count, BytesRead, Overlapped);
end;

function DuplicateHandle(SourceProcess, SourceHandle, TargetProcess: THandle; TargetHandle: PHandle;
    DesiredAccess: DWORD; InheritHandle: BOOL; Options: DWORD): BOOL; stdcall;
var
  ApiTarget: TApiDuplicateHandle;
begin
  ApiTarget := TApiDuplicateHandle(DecodeApiPointer(ApiSlot_DuplicateHandle));
  Result := ApiTarget(SourceProcess, SourceHandle, TargetProcess, TargetHandle, DesiredAccess, InheritHandle, Options);
end;

function RegOpenKeyExW(Key: HKEY; SubKey: PWideChar; Options: DWORD; Access: REGSAM;
    var ResultKey: HKEY): LongInt; stdcall;
var
  ApiTarget: TApiRegOpenKeyExW;
begin
  ApiTarget := TApiRegOpenKeyExW(DecodeApiPointer(ApiSlot_RegOpenKeyExW));
  Result := ApiTarget(Key, SubKey, Options, Access, ResultKey);
end;

function RegQueryValueExW(Key: HKEY; ValueName: PWideChar; Reserved, Kind: PDWORD; Data: PByte;
    DataSize: PDWORD): LongInt; stdcall;
var
  ApiTarget: TApiRegQueryValueExW;
begin
  ApiTarget := TApiRegQueryValueExW(DecodeApiPointer(ApiSlot_RegQueryValueExW));
  Result := ApiTarget(Key, ValueName, Reserved, Kind, Data, DataSize);
end;

function RegCloseKey(Key: HKEY): LongInt; stdcall;
var
  ApiTarget: TApiRegCloseKey;
begin
  ApiTarget := TApiRegCloseKey(DecodeApiPointer(ApiSlot_RegCloseKey));
  Result := ApiTarget(Key);
end;

function BCryptOpenAlgorithmProvider(out Algorithm: TCngHandle;
  AlgorithmName, ImplementationName: PWideChar; Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptOpenAlgorithmProvider;
begin
  ApiTarget := TResolved_BCryptOpenAlgorithmProvider(DecodeApiPointer(ApiSlot_BCryptOpenAlgorithmProvider));
  Result := ApiTarget(Algorithm, AlgorithmName, ImplementationName, Flags);
end;

function BCryptCreateHash(Algorithm: TCngHandle; out Hash: TCngHandle;
  HashObject: PByte; HashObjectSize: DWORD; Secret: PByte;
  SecretSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptCreateHash;
begin
  ApiTarget := TResolved_BCryptCreateHash(DecodeApiPointer(ApiSlot_BCryptCreateHash));
  Result := ApiTarget(Algorithm, Hash, HashObject, HashObjectSize, Secret, SecretSize, Flags);
end;

function BCryptHashData(Hash: TCngHandle; Input: PByte;
  InputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptHashData;
begin
  ApiTarget := TResolved_BCryptHashData(DecodeApiPointer(ApiSlot_BCryptHashData));
  Result := ApiTarget(Hash, Input, InputSize, Flags);
end;

function BCryptFinishHash(Hash: TCngHandle; Output: PByte;
  OutputSize, Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptFinishHash;
begin
  ApiTarget := TResolved_BCryptFinishHash(DecodeApiPointer(ApiSlot_BCryptFinishHash));
  Result := ApiTarget(Hash, Output, OutputSize, Flags);
end;

function BCryptDestroyHash(Hash: TCngHandle): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptDestroyHash;
begin
  ApiTarget := TResolved_BCryptDestroyHash(DecodeApiPointer(ApiSlot_BCryptDestroyHash));
  Result := ApiTarget(Hash);
end;

function BCryptCloseAlgorithmProvider(Algorithm: TCngHandle;
  Flags: DWORD): TCngStatus; stdcall;
var
  ApiTarget: TResolved_BCryptCloseAlgorithmProvider;
begin
  ApiTarget := TResolved_BCryptCloseAlgorithmProvider(DecodeApiPointer(ApiSlot_BCryptCloseAlgorithmProvider));
  Result := ApiTarget(Algorithm, Flags);
end;

function ReadFirmwareTable(ProviderSignature, TableID: DWORD;
  Buffer: Pointer; BufferSize: DWORD): DWORD; stdcall;
var
  ApiTarget: TResolved_ReadFirmwareTable;
begin
  ApiTarget := TResolved_ReadFirmwareTable(DecodeApiPointer(ApiSlot_ReadFirmwareTable));
  Result := ApiTarget(ProviderSignature, TableID, Buffer, BufferSize);
end;
{ POINTER WRAPPERS 1 END }

procedure Check(Success: Boolean);
begin
  if not Success then
    raise EImageIntegrity.Create(CozyText_Integrity_Executable_integrity_verification_failed_b79f134e);
end;

procedure CngCheck(Status: TCngStatus);
begin
  Check(Status = 0);
end;

function HexBytes(const Bytes: TBytes): string;
const Digits: string = CozyText_Integrity_0123456789abcdef_0f7078ca;
var I: Integer;
begin
  SetLength(Result, Length(Bytes) * 2);
  for I := 0 to High(Bytes) do
  begin
    Result[I * 2 + 1] := Digits[(Bytes[I] shr 4) + 1];
    Result[I * 2 + 2] := Digits[(Bytes[I] and $F) + 1];
  end;
end;

type
  PHashMeasurementCancellation = ^THashMeasurementCancellation;
  THashMeasurementCancellation = record
    Budget: TMeasurementBudget;
    Lock: TCriticalSection;
    Failure: TMeasurementStatus;
  end;

function HashMeasurementCancelled(Context: Pointer): Boolean;
var State: PHashMeasurementCancellation;
begin
  State := PHashMeasurementCancellation(Context);
  { Serialize the existing measurement callback. The callback and budget remain
    alive in the calling stack until the executor has joined every worker. }
  State^.Lock.Acquire;
  try
    if State^.Failure = msMeasured then
      try State^.Budget.Check(0, 0);
      except
        on E: EMeasurement do State^.Failure := E.Status;
        on E: Exception do State^.Failure := msReadError;
      end;
    Result := State^.Failure <> msMeasured;
  finally State^.Lock.Release; end;
end;

function HashMeasurementHandle(Handle: THandle; const Budget: TMeasurementBudget): TImageDigest;
var
  Buffer: TBytes;
  Count, Want, ReadWant, ReadCount: DWORD;
  CRC: TCrcState;
  Hasher: TIntegrityHasher;
  Digests: TIntegrityHashResult;
  BeforeInfo, AfterInfo: TByHandleFileInformation;
  Offset, FileSize: UInt64;
  Cancellation: THashCancellation;
  CancellationState: THashMeasurementCancellation;
begin
  Result := Default(TImageDigest);
  Budget.Check(0, 0);
  if not GetFileInformationByHandle(Handle, BeforeInfo) then
    raise EMeasurement.Create(msReadError, CozyText_Integrity_FILE_INFORMATION_a507631c);
  FileSize := (UInt64(BeforeInfo.nFileSizeHigh) shl 32) or BeforeInfo.nFileSizeLow;
  Budget.Check(0, FileSize);
  CrcInit(CRC, ckEcma182);
  Hasher := nil;
  CancellationState.Budget := Budget;
  CancellationState.Failure := msMeasured;
  CancellationState.Lock := TCriticalSection.Create;
  Cancellation.Check := HashMeasurementCancelled;
  Cancellation.Context := @CancellationState;
  try
    Hasher := TIntegrityHasher.Create;
    SetLength(Buffer, 1024 * 1024);
    Offset := 0;
    while Offset < FileSize do
    begin
      Want := Length(Buffer);
      if FileSize - Offset < Want then Want := Cardinal(FileSize - Offset);
      Count := 0;
      while Count < Want do
      begin
        { Preserve the measurement reader's 64 KiB deadline/cancel boundary. }
        ReadWant := Want - Count;
        if ReadWant > 65536 then ReadWant := 65536;
        ReadCount := ReadMeasurementAt(Handle, Offset + Count, @Buffer[Count], ReadWant, Budget);
        if ReadCount = 0 then raise EMeasurement.Create(msChanged, CozyText_Integrity_EARLY_EOF_9bb67e1e);
        Inc(Count, ReadCount);
      end;
      Budget.Check(Offset, Count);
      try
        Hasher.UpdateParallelCancellable(Buffer[0], Count,
          ExecuteBlake3WorkersCancellable, Cancellation);
      except
        on E: EHashCancelled do
        begin
          { Preserve the measurement status instead of reporting cancelled or
            deadline-limited work as a digest mismatch/read success. }
          if CancellationState.Failure = msMeasured then
            CancellationState.Failure := msCancelled;
          raise EMeasurement.Create(CancellationState.Failure, CozyText_Integrity_HASH_STOPPED_cd35a51b);
        end;
      end;
      { All native workers are joined before cancellation can release Buffer. }
      Budget.Check(Offset + Count, 0);
      CrcUpdate(CRC, @Buffer[0], Count);
      Inc(Offset, Count);
    end;
    Budget.Check(Offset, 0);
    if not GetFileInformationByHandle(Handle, AfterInfo) then
      raise EMeasurement.Create(msReadError, CozyText_Integrity_FINAL_FILE_INFORMATION_6937d761);
    if (BeforeInfo.dwVolumeSerialNumber <> AfterInfo.dwVolumeSerialNumber) or
      (BeforeInfo.nFileIndexHigh <> AfterInfo.nFileIndexHigh) or
      (BeforeInfo.nFileIndexLow <> AfterInfo.nFileIndexLow) or
      (BeforeInfo.nFileSizeHigh <> AfterInfo.nFileSizeHigh) or
      (BeforeInfo.nFileSizeLow <> AfterInfo.nFileSizeLow) or
      (BeforeInfo.ftLastWriteTime.dwHighDateTime <> AfterInfo.ftLastWriteTime.dwHighDateTime) or
      (BeforeInfo.ftLastWriteTime.dwLowDateTime <> AfterInfo.ftLastWriteTime.dwLowDateTime) then
      raise EMeasurement.Create(msChanged, CozyText_Integrity_FILE_METADATA_CHANGED_98fbb5ec);
    Digests := Hasher.Finish; Budget.Check(Offset, 0);
    Result.SHA512 := Digests.SHA512; Result.CRC64 := CrcFinalHex(CRC);
    Result.XXH3_128 := Digests.XXH3_128; Result.Blake3 := Digests.Blake3;
    Result.Size := Digests.Size;
  finally
    if Length(Buffer) <> 0 then FillChar(Buffer[0], Length(Buffer), 0);
    Buffer := nil; Hasher.Free;
    CancellationState.Lock.Free;
    CancellationState.Budget.Cancelled := nil;
  end;
end;

function IntegrityHashHandle(Handle: THandle): TImageDigest;
begin
  Result := IntegrityHashHandle(Handle, TMeasurementBudget.Start(64 * 1024 * 1024, 30000));
end;

function IntegrityHashHandle(Handle: THandle; const Budget: TMeasurementBudget): TImageDigest;
var ReadHandle: THandle;
begin
  Budget.Check(0, 0);
  if (Handle = 0) or (Handle = INVALID_HANDLE_VALUE) or
    (GetFileType(Handle) <> FILE_TYPE_DISK) then
    raise EMeasurement.Create(msReadError, CozyText_Integrity_INVALID_DISK_HANDLE_cc6f697f);
  ReadHandle := OpenMeasurementHandle(Handle);
  try Result := HashMeasurementHandle(ReadHandle, Budget);
  finally CloseMeasurementHandle(ReadHandle); end;
end;

function IntegrityHashFile(const FileName: string): TImageDigest;
begin
  Result := IntegrityHashFile(FileName, TMeasurementBudget.Start(64 * 1024 * 1024, 30000));
end;

function IntegrityHashFile(const FileName: string; const Budget: TMeasurementBudget): TImageDigest;
var Handle: THandle; Info: TByHandleFileInformation;
begin
  Budget.Check(0, 0);
  Handle := CreateFileW(PWideChar(FileName), GENERIC_READ, FILE_SHARE_READ,
    nil, OPEN_EXISTING, OpenReparsePointFlag or FILE_FLAG_SEQUENTIAL_SCAN, 0);
  if Handle = INVALID_HANDLE_VALUE then raise EMeasurement.Create(msReadError, CozyText_Integrity_OPEN_FILE_FAILED_82c119db);
  try
    Budget.Check(0, 0);
    if not GetFileInformationByHandle(Handle, Info) then
      raise EMeasurement.Create(msReadError, CozyText_Integrity_FILE_INFORMATION_a507631c);
    if ((Info.dwFileAttributes and (FILE_ATTRIBUTE_DIRECTORY or
      FILE_ATTRIBUTE_REPARSE_POINT)) <> 0) or (Info.nNumberOfLinks <> 1) then
      raise EMeasurement.Create(msReadError, CozyText_Integrity_UNSUPPORTED_FILE_LOCATION_9707696d);
    Result := IntegrityHashHandle(Handle, Budget);
  finally
    CloseHandle(Handle);
  end;
end;

function IntegritySHA512Bytes(const Bytes: TBytes): string;
begin
  { The common bounded-memory implementation accepts NativeUInt lengths;
    the former single CNG call narrowed a byte-array length to DWORD. }
  Result := Cozy.Hashes.SHA512Bytes(Bytes);
end;

function IntegrityCRC64Bytes(const Bytes: TBytes): string;
begin
  Result := CrcBytes(ckEcma182, Bytes);
end;

function IntegritySHA512Text(const Text: string): string;
var Bytes: TBytes;
begin
  Bytes := TEncoding.UTF8.GetBytes(Text);
  try
    Result := IntegritySHA512Bytes(Bytes);
  finally
    { This overload owns its UTF-8 buffer; the bytes overload never mutates
      the caller's buffer or an aliased dynamic array. }
    if Length(Bytes) > 0 then FillChar(Bytes[0], Length(Bytes), 0);
  end;
end;

function IntegritySHA256Bytes(const Bytes: TBytes): string;
var Algorithm, Hash: TCngHandle; Digest: TBytes; InputSpan, OutputSpan: TApiBuffer;
begin
  Algorithm := 0;
  Hash := 0;
  try
    CngCheck(BCryptOpenAlgorithmProvider(Algorithm, CozyText_Integrity_SHA256_9b78531f, nil, 0));
    CngCheck(BCryptCreateHash(Algorithm, Hash, nil, 0, nil, 0, 0));
    if UInt64(Length(Bytes)) > High(Cardinal) then
      raise EArgumentException.Create(CozyText_Integrity_API_CNG_LENGTH_5361fa9a);
    InputSpan := TApiBuffer.ReadBytes(Bytes); InputSpan.Read(0, Length(Bytes));
    if Length(Bytes) > 0 then
      CngCheck(BCryptHashData(Hash, @Bytes[0], DWORD(Length(Bytes)), 0));
    SetLength(Digest, 32);
    OutputSpan := TApiBuffer.WriteBytes(Digest);
    RequireCngBuffers(InputSpan, OutputSpan, Length(Bytes), 32, False);
    CngCheck(BCryptFinishHash(Hash, @Digest[0], 32, 0));
    Result := HexBytes(Digest);
  finally
    if Length(Digest) > 0 then FillChar(Digest[0], Length(Digest), 0);
    if Hash <> 0 then BCryptDestroyHash(Hash);
    if Algorithm <> 0 then BCryptCloseAlgorithmProvider(Algorithm, 0);
  end;
end;

function IntegritySHA256Text(const Text: string): string;
var Bytes: TBytes;
begin
  Bytes := TEncoding.UTF8.GetBytes(Text);
  try
    Result := IntegritySHA256Bytes(Bytes);
  finally
    { This overload owns its UTF-8 buffer; the bytes overload never mutates
      the caller's buffer or an aliased dynamic array. }
    if Length(Bytes) > 0 then FillChar(Bytes[0], Length(Bytes), 0);
  end;
end;

function ReadSMBIOSUUID: string;
var Bytes, UUID: TBytes; Count, TableLength: DWORD;
  Position, EndAt, RecordLength, I: Integer; AllZero, AllFF: Boolean;
begin
  Result := '';
  Count := ReadFirmwareTable(FirmwareRSMB, 0, nil, 0);
  if (Count < 8) or (Count > 1024 * 1024) then Exit;
  SetLength(Bytes, Count);
  try
    if ReadFirmwareTable(FirmwareRSMB, 0, @Bytes[0], Count) <> Count then Exit;
    Move(Bytes[4], TableLength, SizeOf(TableLength));
    if (TableLength > Count - 8) or (TableLength < 4) then Exit;
    EndAt := Integer(TableLength) + 8;
    Position := 8;
    while Position + 4 <= EndAt do
    begin
      RecordLength := Bytes[Position + 1];
      if (RecordLength < 4) or (Position + RecordLength > EndAt) then Exit;
      if (Bytes[Position] = 1) and (RecordLength >= 24) then
      begin
        SetLength(UUID, 16);
        Move(Bytes[Position + 8], UUID[0], 16);
        AllZero := True;
        AllFF := True;
        for I := 0 to 15 do
        begin
          AllZero := AllZero and (UUID[I] = 0);
          AllFF := AllFF and (UUID[I] = $FF);
        end;
        if not AllZero and not AllFF then Result := HexBytes(UUID);
        Exit;
      end;
      if Bytes[Position] = 127 then Exit;
      Inc(Position, RecordLength);
      while Position + 1 < EndAt do
      begin
        if (Bytes[Position] = 0) and (Bytes[Position + 1] = 0) then Break;
        Inc(Position);
      end;
      Inc(Position, 2);
    end;
  finally
    if Length(UUID) > 0 then FillChar(UUID[0], Length(UUID), 0);
    if Length(Bytes) > 0 then FillChar(Bytes[0], Length(Bytes), 0);
  end;
end;

function ReadMachineGuid: string;
var Key: HKEY; Kind, Size: DWORD; Buffer: array[0..127] of WideChar;
  I: Integer;
begin
  Result := '';
  Key := 0;
  FillChar(Buffer, SizeOf(Buffer), 0);
  if RegOpenKeyExW(HKEY_LOCAL_MACHINE, CozyText_Integrity_SOFTWARE_Microsoft_Cryptography_b2d9b149, 0,
    KEY_QUERY_VALUE or KEY_WOW64_64KEY, Key) <> ERROR_SUCCESS then Exit;
  try
    Size := SizeOf(Buffer);
    Kind := 0;
    if (RegQueryValueExW(Key, CozyText_Integrity_MachineGuid_5b96a3ea, nil, @Kind, PByte(@Buffer[0]), @Size) <>
      ERROR_SUCCESS) or (Kind <> REG_SZ) or (Size < 2) or
      (Size > SizeOf(Buffer)) or ((Size mod SizeOf(WideChar)) <> 0) then Exit;
    Buffer[High(Buffer)] := #0;
    Result := UpperCase(Trim(string(PWideChar(@Buffer[0]))));
    if Length(Result) <> 36 then
    begin
      Result := '';
      Exit;
    end;
    for I := 1 to Length(Result) do
      if not CharInSet(Result[I], ['0'..'9', 'A'..'F', '-']) then
      begin
        Result := '';
        Exit;
      end;
  finally
    FillChar(Buffer, SizeOf(Buffer), 0);
    RegCloseKey(Key);
  end;
end;

function IntegrityMachineID: string;
var UUID, Guid, Source: string;
  procedure Clear(var Value: string);
  begin
    if Value <> '' then
    begin
      UniqueString(Value);
      FillChar(PWideChar(Value)^, Length(Value) * SizeOf(WideChar), 0);
      Value := '';
    end;
  end;
begin
  UUID := ReadSMBIOSUUID;
  Guid := ReadMachineGuid;
  try
    { Best-effort fingerprint only: the owner/admin of a PC can replace these
      inputs. No raw hardware identifier or MachineGuid leaves this function. }
    Check((UUID <> '') or (Guid <> ''));
    Source := CozyText_Integrity_GAME_MACHINE_V1_5526da3d + #10 + UUID + #10 + Guid;
    Result := UpperCase(IntegritySHA256Text(Source));
  finally
    Clear(UUID);
    Clear(Guid);
    Clear(Source);
  end;
end;

constructor TImageIntegrity.Create(Handle: THandle; const SHA512, CRC64: string);
begin
  inherited Create;
  FGate := TGameCallGate.Create;
  FLock := TObject.Create;
  Check(DuplicateHandle(GetCurrentProcess, Handle, GetCurrentProcess,
    @FHandle, 0, False, DUPLICATE_SAME_ACCESS));
  Check(GetFileInformationByHandle(FHandle, FInfo) and
    ((FInfo.dwFileAttributes and (FILE_ATTRIBUTE_DIRECTORY or
      FILE_ATTRIBUTE_REPARSE_POINT)) = 0) and (FInfo.nNumberOfLinks = 1));
  FReadHandle := OpenMeasurementHandle(FHandle);
  FExpected := HashMeasurementHandle(FReadHandle, TMeasurementBudget.Start(64 * 1024 * 1024, 30000));
  Check((FExpected.SHA512 = SHA512) and (FExpected.CRC64 = CRC64));
end;

destructor TImageIntegrity.Destroy;
begin
  if FGate <> nil then FGate.CloseAndWait;
  CloseMeasurementHandle(FReadHandle);
  if (FHandle <> 0) and (FHandle <> INVALID_HANDLE_VALUE) then CloseHandle(FHandle);
  FLock.Free;
  FGate.Free;
  inherited;
end;

function TImageIntegrity.VerifyNow: TImageDigest;
begin
  Result := VerifyNow(TMeasurementBudget.Start(64 * 1024 * 1024, 30000));
end;

function TImageIntegrity.VerifyNow(const Budget: TMeasurementBudget): TImageDigest;
var ActiveBudget: TMeasurementBudget;
begin
  FGate.Enter;
  try
    ActiveBudget := Budget.WithCancellation(function: Boolean
      begin Result := FGate.IsClosing; end);
    Result := VerifyNowCore(ActiveBudget);
  finally FGate.Leave; end;
end;

function TImageIntegrity.VerifyNowCore(const Budget: TMeasurementBudget): TImageDigest;
var Info: TByHandleFileInformation;
begin
  Budget.Check(0, 0);
  while not TMonitor.Enter(FLock, 25) do Budget.Check(0, 0);
  try
    Budget.Check(0, 0);
    if not GetFileInformationByHandle(FHandle, Info) then
      raise EMeasurement.Create(msReadError, CozyText_Integrity_PINNED_FILE_INFORMATION_5057b550);
    if not (
      (Info.dwVolumeSerialNumber = FInfo.dwVolumeSerialNumber) and
      (Info.nFileIndexHigh = FInfo.nFileIndexHigh) and
      (Info.nFileIndexLow = FInfo.nFileIndexLow) and
      (Info.nNumberOfLinks <= 1) and
      ((Info.dwFileAttributes and (FILE_ATTRIBUTE_DIRECTORY or
        FILE_ATTRIBUTE_REPARSE_POINT)) = 0)) then
      raise EMeasurement.Create(msChanged, CozyText_Integrity_PINNED_FILE_IDENTITY_cc7f755b);
    Result := HashMeasurementHandle(FReadHandle, Budget);
    if not ((Result.Size = FExpected.Size) and
      (Result.SHA512 = FExpected.SHA512) and (Result.CRC64 = FExpected.CRC64) and
      (Result.XXH3_128 = FExpected.XXH3_128) and (Result.Blake3 = FExpected.Blake3)) then
      raise EMeasurement.Create(msChanged, CozyText_Integrity_EXPECTED_DIGEST_MISMATCH_d8e78c82);
  finally
    TMonitor.Exit(FLock);
  end;
end;

initialization
  { API binding only; original startup actions follow unchanged. }
  BindApiPointer(ApiSlot_CloseHandle, RequireProcAddressHash64(CozyText_Integrity_kernel32_dll_0b28dcad, HASH_CloseHandle));
  BindApiPointer(ApiSlot_CreateFileW, RequireProcAddressHash64(CozyText_Integrity_kernel32_dll_0b28dcad, HASH_CreateFileW));
  BindApiPointer(ApiSlot_GetFileInformationByHandle, RequireProcAddressHash64(CozyText_Integrity_kernel32_dll_0b28dcad, HASH_GetFileInformationByHandle));
  BindApiPointer(ApiSlot_GetFileType, RequireProcAddressHash64(CozyText_Integrity_kernel32_dll_0b28dcad, HASH_GetFileType));
  BindApiPointer(ApiSlot_ReadFile, RequireProcAddressHash64(CozyText_Integrity_kernel32_dll_0b28dcad, HASH_ReadFile));
  BindApiPointer(ApiSlot_DuplicateHandle, RequireProcAddressHash64(CozyText_Integrity_kernel32_dll_0b28dcad, HASH_DuplicateHandle));
  BindApiPointer(ApiSlot_RegOpenKeyExW, RequireProcAddressHash64(CozyText_Integrity_advapi32_dll_120d9018, HASH_RegOpenKeyExW));
  BindApiPointer(ApiSlot_RegQueryValueExW, RequireProcAddressHash64(CozyText_Integrity_advapi32_dll_120d9018, HASH_RegQueryValueExW));
  BindApiPointer(ApiSlot_RegCloseKey, RequireProcAddressHash64(CozyText_Integrity_advapi32_dll_120d9018, HASH_RegCloseKey));
  BindApiPointer(ApiSlot_BCryptOpenAlgorithmProvider, RequireProcAddressHash64(CozyText_Integrity_bcrypt_dll_40ada3c2, HASH_BCryptOpenAlgorithmProvider));
  BindApiPointer(ApiSlot_BCryptCreateHash, RequireProcAddressHash64(CozyText_Integrity_bcrypt_dll_40ada3c2, HASH_BCryptCreateHash));
  BindApiPointer(ApiSlot_BCryptHashData, RequireProcAddressHash64(CozyText_Integrity_bcrypt_dll_40ada3c2, HASH_BCryptHashData));
  BindApiPointer(ApiSlot_BCryptFinishHash, RequireProcAddressHash64(CozyText_Integrity_bcrypt_dll_40ada3c2, HASH_BCryptFinishHash));
  BindApiPointer(ApiSlot_BCryptDestroyHash, RequireProcAddressHash64(CozyText_Integrity_bcrypt_dll_40ada3c2, HASH_BCryptDestroyHash));
  BindApiPointer(ApiSlot_BCryptCloseAlgorithmProvider, RequireProcAddressHash64(CozyText_Integrity_bcrypt_dll_40ada3c2, HASH_BCryptCloseAlgorithmProvider));
  BindApiPointer(ApiSlot_ReadFirmwareTable, RequireProcAddressHash64(CozyText_Integrity_kernel32_dll_0b28dcad, HASH_GetSystemFirmwareTable));
  Check(CrcSelfTest);

end.
