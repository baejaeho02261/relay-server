unit Cozy.NHW.FileNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

{$POINTERMATH ON}
{$Q-} // UInt64 FNV hashes intentionally wrap on overflow.

interface

uses
  Winapi.Windows,
  System.SysUtils;

type
  TFileEvidence = record
    ReferenceIdKnown: Boolean;
    ReferenceId: string;
    PathKnown: Boolean;
    PathPresent: Boolean;
    PathId: string;
    ReferenceNameKnown: Boolean;
    ReferenceName: string;
    ReparseKnown: Boolean;
    ReparseHash: UInt64;
    StreamsKnown: Boolean;
    StreamsHash: UInt64;
    SecurityKnown: Boolean;
    SecurityHash: UInt64;
    LinksKnown: Boolean;
    LinksMode: Byte; // 1 = complete link-name set, 2 = link count only
    LinksHash: UInt64;
  end;

function FileNativeAvailable: Boolean;
function OpenFileMetadata(const Path: string; OpenReparse: Boolean): THandle;
procedure CloseFileMetadata(var Handle: THandle);
function ReadFileIdentity(Handle: THandle; out Identity: string): Boolean;
function ReadFileName(Handle: THandle; out Name: string): Boolean;
function ReadReparseChain(const Path: string; out Digest: UInt64): Boolean;
function ReadStreamSet(Handle: THandle; out Digest: UInt64): Boolean;
function ReadFileDacl(Handle: THandle; out Digest: UInt64): Boolean;
function ReadLinkSet(Handle: THandle; out Mode: Byte; out Digest: UInt64): Boolean;
procedure ReadPathIdentity(const Path: string; var E: TFileEvidence);

{$IFDEF NHW_NATIVE5B_TESTS}
function TestFileNativeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.Classes,
  System.SyncObjs,
  Cozy.NHW.Native,
  Cozy.NHW.WinPointers,
  Cozy.NHW.FileMetadata.Decoders;

const
  CLASS_FILE_STANDARD = 5;
  CLASS_FILE_NAME = 9;
  CLASS_FILE_STREAM = 22;
  CLASS_FILE_HARD_LINK = 46;
  CLASS_FILE_ID = 59;
  SECURITY_INFO_DACL = $00000004;
  ATTR_REPARSE = $00000400;
  ATTR_READ = $00000080;
  EA_READ = $00000008;
  CONTROL_READ = $00020000;
  REPARSE_CONTROL_GET = $000900A8;
  NATIVE_FILE_FLAG_OPEN_REPARSE_POINT = $00200000;
  STATUS_BUFFER_OVERFLOW = $80000005;
  STATUS_INFO_LENGTH_MISMATCH = $C0000004;
  STATUS_BUFFER_TOO_SMALL = $C0000023;

type
  TNativeIoStatus = record
    Status: NativeInt;
    Information: NativeUInt;
  end;

  TNtQueryFile = function(FileHandle: THandle;
    var IoStatus: TNativeIoStatus; Buffer: Pointer; BufferSize: Cardinal;
    InfoClass: Cardinal): LongInt; stdcall;

  TNativeFileIdInfo = record
    VolumeSerial: UInt64;
    Id: array[0..15] of Byte;
  end;

  TNativeStandardInfo = record
    AllocationSize: Int64;
    EndOfFile: Int64;
    NumberOfLinks: Cardinal;
    DeletePending: Byte;
    Directory: Byte;
    Padding: Word;
  end;

var
  NtQueryFilePtr: TNtQueryFile = nil;
  FileResolveLock: TCriticalSection;
  FileResolved: Integer = 0;

function EnsureResolved: Boolean;
var
  M: HMODULE;
begin
  if TInterlocked.CompareExchange(FileResolved, 0, 0) <> 0 then
    Exit(Assigned(NtQueryFilePtr));
  FileResolveLock.Acquire;
  try
    if FileResolved = 0 then
    begin
      M := WinModule('ntdll.dll');
      if M = 0 then Exit(False);
      NtQueryFilePtr := TNtQueryFile(WinExport(M, 'NtQueryInformationFile'));
      TInterlocked.Exchange(FileResolved, 1);
    end;
    Result := Assigned(NtQueryFilePtr);
  finally
    FileResolveLock.Release;
  end;
end;

function ValidFileHandle(Handle: THandle): Boolean;
begin
  Result := (Handle <> 0) and (Handle <> INVALID_HANDLE_VALUE);
end;

function ValidMetadataPath(const Path: string): Boolean;
begin
  Result := (Path <> '') and (Length(Path) <= 32767) and (Pos(#0, Path) = 0);
end;

function FileNativeAvailable: Boolean;
begin
  Result := EnsureResolved;
end;

function OpenFileMetadata(const Path: string; OpenReparse: Boolean): THandle;
var
  Flags, Access: Cardinal;
begin
  Result := INVALID_HANDLE_VALUE;
  if not ValidMetadataPath(Path) then Exit;
  Flags := FILE_FLAG_BACKUP_SEMANTICS;
  if OpenReparse then
    Flags := Flags or NATIVE_FILE_FLAG_OPEN_REPARSE_POINT;
  if OpenReparse then
    Access := ATTR_READ or EA_READ
  else
    Access := ATTR_READ or CONTROL_READ;
  Result := WinCreateFile(PChar(Path), Access,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
    nil, OPEN_EXISTING, Flags, 0);
  if Result = INVALID_HANDLE_VALUE then
    Result := WinCreateFile(PChar(Path), ATTR_READ or EA_READ,
      FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
      nil, OPEN_EXISTING, Flags, 0);
  if Result = INVALID_HANDLE_VALUE then
    Result := WinCreateFile(PChar(Path), ATTR_READ,
      FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
      nil, OPEN_EXISTING, Flags, 0);
end;

procedure CloseFileMetadata(var Handle: THandle);
begin
  if not ValidFileHandle(Handle) then
  begin
    Handle := INVALID_HANDLE_VALUE;
    Exit;
  end;
  if WinCloseHandle(Handle) then Handle := INVALID_HANDLE_VALUE;
end;

function QueryFixed(Handle: THandle; InfoClass: Cardinal;
  Buffer: Pointer; Bytes: Cardinal): Boolean;
var
  Io: TNativeIoStatus;
  Status: LongInt;
begin
  Result := False;
  if (Buffer = nil) or (Bytes = 0) or (Bytes > MAX_QUERY_BYTES) then Exit;
  FillChar(Buffer^, Bytes, 0);
  if not ValidFileHandle(Handle) or not EnsureResolved then Exit;
  FillChar(Io, SizeOf(Io), 0);
  // Callers supply synchronous metadata handles created by OpenFileMetadata.
  Status := NtQueryFilePtr(Handle, Io, Buffer, Bytes, InfoClass);
  Result := (Status = 0) and (Io.Status = 0) and (Io.Information = Bytes);
  if not Result then FillChar(Buffer^, Bytes, 0);
end;

function QueryVariable(Handle: THandle; InfoClass: Cardinal;
  MaxBytes: Cardinal; out Buffer: TBytes): Boolean;
var
  Io: TNativeIoStatus;
  Capacity: Cardinal;
  Status: LongInt;
begin
  Result := False;
  Buffer := nil;
  if not ValidFileHandle(Handle) or (MaxBytes = 0) or
     (MaxBytes > MAX_QUERY_BYTES) or not EnsureResolved then Exit;
  Capacity := 4096;
  if Capacity > MaxBytes then Capacity := MaxBytes;
  try
    repeat
      SetLength(Buffer, Integer(Capacity));
      FillChar(Buffer[0], Length(Buffer), 0);
      FillChar(Io, SizeOf(Io), 0);
      Status := NtQueryFilePtr(Handle, Io, @Buffer[0], Capacity, InfoClass);
      if Status = 0 then
      begin
        // Allocation size is not a substitute for a valid returned byte count.
        if (Io.Status <> 0) or (Io.Information = 0) or
           (Io.Information > Capacity) then Exit;
        SetLength(Buffer, Integer(Io.Information));
        Exit(True);
      end;
      if (Cardinal(Status) <> STATUS_BUFFER_OVERFLOW) and
         (Cardinal(Status) <> STATUS_INFO_LENGTH_MISMATCH) and
         (Cardinal(Status) <> STATUS_BUFFER_TOO_SMALL) then Exit;
      if Capacity = MaxBytes then Exit;
      if Capacity > MaxBytes div 2 then Capacity := MaxBytes
      else Capacity := Capacity * 2;
    until False;
  finally
    if not Result then Buffer := nil;
  end;
end;

function ReadFileIdentity(Handle: THandle; out Identity: string): Boolean;
var
  Id: TNativeFileIdInfo;
  B: BY_HANDLE_FILE_INFORMATION;
  Index: UInt64;
  I: Integer;
begin
  Result := False;
  Identity := '';
  if not ValidFileHandle(Handle) then Exit;
  FillChar(Id, SizeOf(Id), 0);
  if QueryFixed(Handle, CLASS_FILE_ID, @Id, SizeOf(Id)) then
  begin
    Identity := 'I:' + IntToHex(Id.VolumeSerial, 16) + ':';
    for I := Low(Id.Id) to High(Id.Id) do
      Identity := Identity + IntToHex(Id.Id[I], 2);
    Exit(True);
  end;
  // FileIdInformation may be unavailable on some filesystems. Include volume
  // serial to avoid treating identical local file indices as the same file.
  FillChar(B, SizeOf(B), 0);
  if not WinGetFileInformationByHandle(Handle, B) then Exit;
  Index := (UInt64(B.nFileIndexHigh) shl 32) or UInt64(B.nFileIndexLow);
  Identity := 'L:' + IntToHex(B.dwVolumeSerialNumber, 8) + ':' + IntToHex(Index, 16);
  Result := True;
end;

function ReadFileName(Handle: THandle; out Name: string): Boolean;
var
  B: TBytes;
begin
  Result := False;
  Name := '';
  if QueryVariable(Handle, CLASS_FILE_NAME, 65536, B) then
    Result := DecodeFileName(B, Name);
end;

function ReadReparseChain(const Path: string; out Digest: UInt64): Boolean;
var
  Candidate, Parent: string;
  A, BytesReturned: Cardinal;
  H: THandle;
  B: array[0..16383] of Byte;
  I: Integer;
  CandidateDigest: UInt64;
begin
  Result := False;
  Digest := 0;
  if not ValidMetadataPath(Path) then Exit;
  CandidateDigest := FNV_OFFSET;
  Candidate := ExpandFileName(Path);
  for I := 0 to 63 do
  begin
    A := WinGetFileAttributes(PChar(Candidate));
    if A = INVALID_FILE_ATTRIBUTES then Exit;
    if (A and ATTR_REPARSE) <> 0 then
    begin
      H := OpenFileMetadata(Candidate, True);
      if not ValidFileHandle(H) then Exit;
      try
        FillChar(B, SizeOf(B), 0);
        BytesReturned := 0;
        if not WinDeviceIoControl(H, REPARSE_CONTROL_GET,
          nil, 0, @B[0], SizeOf(B), BytesReturned, nil) then Exit;
        if not ReparsePayloadValid(B, BytesReturned) then Exit;
        HashString(CandidateDigest, LowerCase(Candidate));
        HashCardinal(CandidateDigest, BytesReturned);
        HashMemory(CandidateDigest, @B[0], BytesReturned);
      finally
        CloseFileMetadata(H);
      end;
    end;
    Parent := ExtractFileDir(ExcludeTrailingPathDelimiter(Candidate));
    if (Parent = '') or SameText(Parent, Candidate) then
    begin
      Digest := CandidateDigest;
      Exit(True);
    end;
    Candidate := Parent;
  end;
  // Truncation, unsupported paths and failed reads remain UNKNOWN.
end;

function ReadStreamSet(Handle: THandle; out Digest: UInt64): Boolean;
var
  B: TBytes;
begin
  Result := False;
  Digest := 0;
  if QueryVariable(Handle, CLASS_FILE_STREAM, MAX_QUERY_BYTES, B) then
    Result := DecodeStreamSet(B, Digest);
end;

function ReadFileDacl(Handle: THandle; out Digest: UInt64): Boolean;
var
  B: TBytes;
  Needed: Cardinal;
begin
  Result := False;
  Digest := 0;
  if not ValidFileHandle(Handle) then Exit;
  SetLength(B, 65536 + 4096);
  FillChar(B[0], Length(B), 0);
  Needed := 0;
  if QueryNativeSecurity(Handle, SECURITY_INFO_DACL,
    @B[0], Cardinal(Length(B)), Needed) <> 0 then Exit;
  Result := DecodeFileDacl(B, Needed, Digest);
end;

function ReadLinkNames(Handle: THandle; out Digest: UInt64): Boolean;
var
  B: TBytes;
begin
  Result := False;
  Digest := 0;
  if QueryVariable(Handle, CLASS_FILE_HARD_LINK, MAX_QUERY_BYTES, B) then
    Result := DecodeLinkNames(B, Digest);
end;

function ReadLinkSet(Handle: THandle; out Mode: Byte;
  out Digest: UInt64): Boolean;
var
  Info: TNativeStandardInfo;
begin
  Mode := 0;
  Digest := 0;
  if ReadLinkNames(Handle, Digest) then
  begin
    Mode := 1;
    Exit(True);
  end;
  // Fallback for file systems without FileHardLinkInformation support.
  FillChar(Info, SizeOf(Info), 0);
  Result := QueryFixed(Handle, CLASS_FILE_STANDARD, @Info, SizeOf(Info));
  if Result then
  begin
    Digest := UInt64(Info.NumberOfLinks);
    Mode := 2;
  end;
end;

procedure ReadPathIdentity(const Path: string; var E: TFileEvidence);
var
  H: THandle;
  Attr, Error: Cardinal;
begin
  E.PathKnown := False;
  E.PathPresent := False;
  E.PathId := '';
  if not ValidMetadataPath(Path) then Exit;
  H := OpenFileMetadata(Path, False);
  if ValidFileHandle(H) then
  begin
    try
      if ReadFileIdentity(H, E.PathId) then
      begin
        E.PathKnown := True;
        E.PathPresent := True;
      end;
    finally
      CloseFileMetadata(H);
    end;
    Exit;
  end;
  Error := WinGetLastError;
  if (Error = ERROR_FILE_NOT_FOUND) or (Error = ERROR_PATH_NOT_FOUND) then
  begin
    Attr := WinGetFileAttributes(PChar(Path));
    if (Attr = INVALID_FILE_ATTRIBUTES) then
    begin
      Error := WinGetLastError;
      if (Error = ERROR_FILE_NOT_FOUND) or (Error = ERROR_PATH_NOT_FOUND) then
      begin
        E.PathKnown := True;
        E.PathPresent := False;
      end;
    end;
  end;
end;

{$IFDEF NHW_NATIVE5B_TESTS}
  {$I Cozy.NHW.Native5B.File.inc}
{$ENDIF}
initialization
  FileResolveLock := TCriticalSection.Create;
finalization
  // The engine must have joined workers before Delphi unit finalization.
  FileResolveLock.Free;
end.
