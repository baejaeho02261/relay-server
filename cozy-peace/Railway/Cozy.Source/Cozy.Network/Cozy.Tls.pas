unit Cozy.Tls;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$IFNDEF MSWINDOWS}
  {$MESSAGE FATAL 'Cozy.Tls requires Windows Schannel.'}
{$ENDIF}
{$IFNDEF CPUX64}
  {$MESSAGE FATAL 'Cozy.Tls requires Windows x64 SSPI layouts.'}
{$ENDIF}
{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Network,
{$IF ((Defined(GAME_NATIVE_ABI_TESTS))) or ((Defined(GAME_TLS_CONTRACT_TESTS)))}
  Cozy.Strings.TestsNetwork,
{$ENDIF}

  Winapi.Windows, System.SysUtils, Cozy.Lifetime, Cozy.Api.Contracts;

{$ALIGN 8}

type
  TTlsWrite = function(Buffer: Pointer; Count: Integer): Boolean of object;
  TTlsRead = function(Buffer: Pointer; Count: Integer): Integer of object;
  TSecurityHandle = record
    Lower, Upper: NativeUInt;
  end;
  TTlsStreamSizes = record
    Header, Trailer, MaximumMessage, BufferCount, BlockSize: DWORD;
  end;

  { Documented Windows Schannel SSPI over the caller's bounded Winsock I/O.
    Private certificate trust: the administrator embeds the exact DER SHA256
    certificate pin in A. No TOFU, CA-bypass fallback or plaintext fallback.
    TLS 1.2 is explicit for all supported Windows versions. TLS 1.0/1.1 and
    renegotiation are rejected; inner CNG AES-GCM remains independently checked. }
  TGameTlsStream = class
  private
    { The transport is sequential. Reject concurrent/reentrant operations
      instead of passing the same SSPI context to two callers. The owner must
      stop/join callers before Free; a lock cannot make use-after-Free valid. }
    FCallLock: Integer;
    FGate: TGameCallGate;
    FHandshakeStarted: Boolean;
    FPeerCertificateSha256: string;
    FRead: TTlsRead;
    FWrite: TTlsWrite;
    FCredential, FContext: TSecurityHandle;
    FHaveCredential, FHaveContext, FAuthenticated: Boolean;
    FSizes: TTlsStreamSizes;
    { Fixed owned allocations. SSPI borrows a scope only for its synchronous
      call. Plaintext is copied once from the in-place record, consumed via a
      cursor, and each consumed byte is wiped before the read returns. }
    FCipher, FPlain: TApiSensitiveBuffer;
    FCipherCount, FPlainCount, FPlainOffset: Integer;
    procedure ClearBuffers;
    procedure ReleaseSecurityContext;
    function PerformHandshake(const ServerName, CertificateSha256, AlternateSha256: string): Boolean;
    function PerformWrite(Buffer: Pointer; Count: Integer): Boolean;
    function PerformRead(Buffer: Pointer; Count: Integer): Integer;
    function ReadCipher: Boolean;
    function VerifyCertificate(const CertificateSha256: string): Boolean;
    function KeepExtra(Count: DWORD): Boolean;
  public
    constructor Create(ReadProc: TTlsRead; WriteProc: TTlsWrite);
    destructor Destroy; override;
    function Handshake(const ServerName, CertificateSha256: string; const AlternateSha256: string = ''): Boolean;
    property PeerCertificateSha256: string read FPeerCertificateSha256;
    function Write(Buffer: Pointer; Count: Integer): Boolean;
    function Read(Buffer: Pointer; Count: Integer): Integer;
  end;

{$IFDEF GAME_TLS_CONTRACT_TESTS}
type
  TTlsProbeCounters = record
    HandshakeIncomplete, ReadIncomplete, ReadExtra, ContextExpired,
      RealProviderCalls, ProviderOverrideCalls: Integer;
  end;
procedure ResetTlsProbeCounters;
function ReadTlsProbeCounters: TTlsProbeCounters;
procedure RunTlsContractTests;
{$ENDIF}
{$IFDEF GAME_NATIVE_ABI_TESTS}
procedure WriteTlsAbiContract;
{$ENDIF}

implementation


uses
  System.SyncObjs, Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer;
type
  PSecurityHandle = ^TSecurityHandle;
  TSecBuffer = record
    Size, Kind: DWORD;
    Data: Pointer;
  end;
  PSecBuffer = ^TSecBuffer;
  TSecBufferDesc = record
    Version, Count: DWORD;
    Buffers: PSecBuffer;
  end;
  PSecBufferDesc = ^TSecBufferDesc;
  TSchannelCredential = record
    Version, CredentialCount: DWORD;
    Credentials, RootStore: Pointer;
    MapperCount: DWORD;
    Mappers: Pointer;
    AlgorithmCount: DWORD;
    Algorithms: Pointer;
    Protocols, MinimumCipherStrength, MaximumCipherStrength: DWORD;
    SessionLifespan, Flags, CredentialFormat: DWORD;
  end;
  TCertificateContext = record
    Encoding: DWORD;
    Encoded: PByte;
    EncodedSize: DWORD;
    Info, Store: Pointer;
  end;
  PCertificateContext = ^TCertificateContext;
  TTlsConnectionInfo = record
    Protocol, Cipher, CipherStrength, Hash, HashStrength: DWORD;
    Exchange, ExchangeStrength: DWORD;
  end;

{$IF SizeOf(TSecurityHandle) <> 16}
  {$MESSAGE FATAL 'SSPI SecHandle layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TSecBuffer) <> 16}
  {$MESSAGE FATAL 'SSPI SecBuffer layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TSecBufferDesc) <> 16}
  {$MESSAGE FATAL 'SSPI SecBufferDesc layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TSchannelCredential) <> 80}
  {$MESSAGE FATAL 'SCHANNEL_CRED layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TCertificateContext) <> 40}
  {$MESSAGE FATAL 'CERT_CONTEXT layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TTlsStreamSizes) <> 20}
  {$MESSAGE FATAL 'SSPI stream sizes layout mismatch.'}
{$ENDIF}
{$IF SizeOf(TTlsConnectionInfo) <> 28}
  {$MESSAGE FATAL 'Schannel connection info layout mismatch.'}
{$ENDIF}

const
  SecOk = 0;
  SecContinue = $00090312;
  SecContextExpired = $00090317;
  { Signed SECURITY_STATUS without an out-of-range constant conversion. }
  SecIncompleteMessage: LongInt = -2146893032;
  BufferData = 1;
  BufferToken = 2;
  BufferExtra = 5;
  BufferTrailer = 6;
  BufferHeader = 7;
  AttributeStreamSizes = 4;
  AttributeRemoteCertificate = $53;
  AttributeConnectionInfo = $5A;
  Tls12Client = $00000800;
  RequestReplay = $00000004;
  RequestSequence = $00000008;
  RequestConfidentiality = $00000010;
  RequestSuppliedCredentials = $00000080;
  RequestAllocateMemory = $00000100;
  RequestExtendedError = $00004000;
  RequestStream = $00008000;
  RequestIntegrity = $00010000;
  RequestManualValidation = $00080000;
  ContextFlags = RequestReplay or RequestSequence or RequestConfidentiality or
    RequestSuppliedCredentials or RequestAllocateMemory or RequestExtendedError or
    RequestStream or RequestIntegrity or RequestManualValidation;
  CredentialManualValidation = $00000008;
  CredentialNoDefault = $00000010;
  CredentialStrongCrypto = $00400000;
  MaxCipherBytes = 262144;
  MaxTlsRecordBytes = 65536;

type
  TResolved_AcquireCredentialsHandleW = function(Principal, PackageName: PWideChar;
  CredentialUse: DWORD; LogonId, AuthenticationData, GetKey, GetKeyArgument: Pointer;
  out Credential: TSecurityHandle; out Expiry: Int64): LongInt; stdcall;
var
  ApiSlot_AcquireCredentialsHandleW: TEncodedApiPointer;
type
  TResolved_InitializeSecurityContextW = function(Credential, Context: PSecurityHandle;
  TargetName: PWideChar; Requirements, Reserved1, DataRepresentation: DWORD;
  Input: PSecBufferDesc; Reserved2: DWORD; out NewContext: TSecurityHandle;
  Output: PSecBufferDesc; out Attributes: DWORD; out Expiry: Int64): LongInt; stdcall;
var
  ApiSlot_InitializeSecurityContextW: TEncodedApiPointer;
type
  TResolved_QueryContextAttributesW = function(var Context: TSecurityHandle;
  Attribute: DWORD; Buffer: Pointer): LongInt; stdcall;
var
  ApiSlot_QueryContextAttributesW: TEncodedApiPointer;
type
  TResolved_DeleteSecurityContext = function(var Context: TSecurityHandle): LongInt; stdcall;
var
  ApiSlot_DeleteSecurityContext: TEncodedApiPointer;
type
  TResolved_FreeCredentialsHandle = function(var Credential: TSecurityHandle): LongInt; stdcall;
var
  ApiSlot_FreeCredentialsHandle: TEncodedApiPointer;
type
  TResolved_FreeContextBuffer = function(Buffer: Pointer): LongInt; stdcall;
var
  ApiSlot_FreeContextBuffer: TEncodedApiPointer;
type
  TResolved_EncryptMessage = function(var Context: TSecurityHandle; Quality: DWORD;
  var MessageBuffers: TSecBufferDesc; Sequence: DWORD): LongInt; stdcall;
var
  ApiSlot_EncryptMessage: TEncodedApiPointer;
type
  TResolved_DecryptMessage = function(var Context: TSecurityHandle;
  var MessageBuffers: TSecBufferDesc; Sequence: DWORD; Quality: Pointer): LongInt; stdcall;
var
  ApiSlot_DecryptMessage: TEncodedApiPointer;
type
  TResolved_CertFreeCertificateContext = function(Context: PCertificateContext): BOOL; stdcall;
var
  ApiSlot_CertFreeCertificateContext: TEncodedApiPointer;
type
  TResolved_CertVerifyTimeValidity = function(Time: PFileTime; Info: Pointer): LongInt; stdcall;
var
  ApiSlot_CertVerifyTimeValidity: TEncodedApiPointer;
type
  TResolved_CryptHashCertificate2 = function(Algorithm: PWideChar; Flags: DWORD;
  Reserved: Pointer; Encoded: PByte; EncodedSize: DWORD; Hash: PByte;
  var HashSize: DWORD): BOOL; stdcall;
var
  ApiSlot_CryptHashCertificate2: TEncodedApiPointer;

{$IFDEF GAME_TLS_CONTRACT_TESTS}
var
  TlsProbeCounters: TTlsProbeCounters;
  TlsTestDecrypt: TResolved_DecryptMessage;
  TlsTestAcquire: TResolved_AcquireCredentialsHandleW;
  TlsTestInitialize: TResolved_InitializeSecurityContextW;
  TlsTestDelete: TResolved_DeleteSecurityContext;
  TlsTestFreeCredential: TResolved_FreeCredentialsHandle;
procedure ResetTlsProbeCounters;
begin FillChar(TlsProbeCounters,SizeOf(TlsProbeCounters),0); end;
function ReadTlsProbeCounters: TTlsProbeCounters;
begin Result := TlsProbeCounters; end;
{$ENDIF}

{ POINTER WRAPPERS 1 BEGIN }
function AcquireCredentialsHandleW(Principal, PackageName: PWideChar;
  CredentialUse: DWORD; LogonId, AuthenticationData, GetKey, GetKeyArgument: Pointer;
  out Credential: TSecurityHandle; out Expiry: Int64): LongInt; stdcall;
var
  ApiTarget: TResolved_AcquireCredentialsHandleW;
begin
{$IFDEF GAME_TLS_CONTRACT_TESTS}
  if Assigned(TlsTestAcquire) then
  begin
    TInterlocked.Increment(TlsProbeCounters.ProviderOverrideCalls);
    Exit(TlsTestAcquire(Principal, PackageName, CredentialUse, LogonId, AuthenticationData, GetKey, GetKeyArgument, Credential, Expiry));
  end;
  TInterlocked.Increment(TlsProbeCounters.RealProviderCalls);
{$ENDIF}
  ApiTarget := TResolved_AcquireCredentialsHandleW(DecodeApiPointer(ApiSlot_AcquireCredentialsHandleW));
  Result := ApiTarget(Principal, PackageName, CredentialUse, LogonId, AuthenticationData, GetKey, GetKeyArgument, Credential, Expiry);
end;

function InitializeSecurityContextW(Credential, Context: PSecurityHandle;
  TargetName: PWideChar; Requirements, Reserved1, DataRepresentation: DWORD;
  Input: PSecBufferDesc; Reserved2: DWORD; out NewContext: TSecurityHandle;
  Output: PSecBufferDesc; out Attributes: DWORD; out Expiry: Int64): LongInt; stdcall;
var
  ApiTarget: TResolved_InitializeSecurityContextW;
begin
{$IFDEF GAME_TLS_CONTRACT_TESTS}
  if Assigned(TlsTestInitialize) then
  begin
    TInterlocked.Increment(TlsProbeCounters.ProviderOverrideCalls);
    Exit(TlsTestInitialize(Credential, Context, TargetName, Requirements, Reserved1, DataRepresentation, Input, Reserved2, NewContext, Output, Attributes, Expiry));
  end;
  TInterlocked.Increment(TlsProbeCounters.RealProviderCalls);
{$ENDIF}
  ApiTarget := TResolved_InitializeSecurityContextW(DecodeApiPointer(ApiSlot_InitializeSecurityContextW));
  Result := ApiTarget(Credential, Context, TargetName, Requirements, Reserved1, DataRepresentation, Input, Reserved2, NewContext, Output, Attributes, Expiry);
end;

function QueryContextAttributesW(var Context: TSecurityHandle;
  Attribute: DWORD; Buffer: Pointer): LongInt; stdcall;
var
  ApiTarget: TResolved_QueryContextAttributesW;
begin
  ApiTarget := TResolved_QueryContextAttributesW(DecodeApiPointer(ApiSlot_QueryContextAttributesW));
  Result := ApiTarget(Context, Attribute, Buffer);
end;

function DeleteSecurityContext(var Context: TSecurityHandle): LongInt; stdcall;
var
  ApiTarget: TResolved_DeleteSecurityContext;
begin
{$IFDEF GAME_TLS_CONTRACT_TESTS}
  if Assigned(TlsTestDelete) then
  begin
    TInterlocked.Increment(TlsProbeCounters.ProviderOverrideCalls);
    Exit(TlsTestDelete(Context));
  end;
  TInterlocked.Increment(TlsProbeCounters.RealProviderCalls);
{$ENDIF}
  ApiTarget := TResolved_DeleteSecurityContext(DecodeApiPointer(ApiSlot_DeleteSecurityContext));
  Result := ApiTarget(Context);
end;

function FreeCredentialsHandle(var Credential: TSecurityHandle): LongInt; stdcall;
var
  ApiTarget: TResolved_FreeCredentialsHandle;
begin
{$IFDEF GAME_TLS_CONTRACT_TESTS}
  if Assigned(TlsTestFreeCredential) then
  begin
    TInterlocked.Increment(TlsProbeCounters.ProviderOverrideCalls);
    Exit(TlsTestFreeCredential(Credential));
  end;
  TInterlocked.Increment(TlsProbeCounters.RealProviderCalls);
{$ENDIF}
  ApiTarget := TResolved_FreeCredentialsHandle(DecodeApiPointer(ApiSlot_FreeCredentialsHandle));
  Result := ApiTarget(Credential);
end;

function FreeContextBuffer(Buffer: Pointer): LongInt; stdcall;
var
  ApiTarget: TResolved_FreeContextBuffer;
begin
  ApiTarget := TResolved_FreeContextBuffer(DecodeApiPointer(ApiSlot_FreeContextBuffer));
  Result := ApiTarget(Buffer);
end;

function EncryptMessage(var Context: TSecurityHandle; Quality: DWORD;
  var MessageBuffers: TSecBufferDesc; Sequence: DWORD): LongInt; stdcall;
var
  ApiTarget: TResolved_EncryptMessage;
begin
  ApiTarget := TResolved_EncryptMessage(DecodeApiPointer(ApiSlot_EncryptMessage));
  Result := ApiTarget(Context, Quality, MessageBuffers, Sequence);
end;

function DecryptMessage(var Context: TSecurityHandle;
  var MessageBuffers: TSecBufferDesc; Sequence: DWORD; Quality: Pointer): LongInt; stdcall;
var
  ApiTarget: TResolved_DecryptMessage;
begin
{$IFDEF GAME_TLS_CONTRACT_TESTS}
  if Assigned(TlsTestDecrypt) then
  begin
    TInterlocked.Increment(TlsProbeCounters.ProviderOverrideCalls);
    Exit(TlsTestDecrypt(Context,MessageBuffers,Sequence,Quality));
  end;
  TInterlocked.Increment(TlsProbeCounters.RealProviderCalls);
{$ENDIF}
  ApiTarget := TResolved_DecryptMessage(DecodeApiPointer(ApiSlot_DecryptMessage));
  Result := ApiTarget(Context, MessageBuffers, Sequence, Quality);
end;

function CertFreeCertificateContext(Context: PCertificateContext): BOOL; stdcall;
var
  ApiTarget: TResolved_CertFreeCertificateContext;
begin
  ApiTarget := TResolved_CertFreeCertificateContext(DecodeApiPointer(ApiSlot_CertFreeCertificateContext));
  Result := ApiTarget(Context);
end;

function CertVerifyTimeValidity(Time: PFileTime; Info: Pointer): LongInt; stdcall;
var
  ApiTarget: TResolved_CertVerifyTimeValidity;
begin
  ApiTarget := TResolved_CertVerifyTimeValidity(DecodeApiPointer(ApiSlot_CertVerifyTimeValidity));
  Result := ApiTarget(Time, Info);
end;

function CryptHashCertificate2(Algorithm: PWideChar; Flags: DWORD;
  Reserved: Pointer; Encoded: PByte; EncodedSize: DWORD; Hash: PByte;
  var HashSize: DWORD): BOOL; stdcall;
var
  ApiTarget: TResolved_CryptHashCertificate2;
begin
  ApiTarget := TResolved_CryptHashCertificate2(DecodeApiPointer(ApiSlot_CryptHashCertificate2));
  Result := ApiTarget(Algorithm, Flags, Reserved, Encoded, EncodedSize, Hash, HashSize);
end;
{ POINTER WRAPPERS 1 END }

procedure Wipe(var Bytes: TBytes);
begin
  if Length(Bytes) > 0 then FillChar(Bytes[0], Length(Bytes), 0);
  Bytes := nil;
end;

function InsideSpan(Base: Pointer; Length: NativeUInt; Data: Pointer;
  Count: DWORD): Boolean;
var Start, Offset: NativeUInt;
begin
  Result := False;
  if (Length=0) or (Base=nil) or (Data=nil) then Exit;
  Start := NativeUInt(Base);
  if NativeUInt(Data)<Start then Exit;
  Offset := NativeUInt(Data)-Start;
  Result := (Offset<=Length) and (NativeUInt(Count)<=Length-Offset);
end;
function Inside(const Bytes: TBytes; Data: Pointer; Count: DWORD): Boolean;
begin
  Result := (Length(Bytes)>0) and InsideSpan(@Bytes[0],Length(Bytes),Data,Count);
end;

function NativeTlsLayoutValid: Boolean;
var
  Handle: TSecurityHandle;
  Buffer: TSecBuffer;
  Description: TSecBufferDesc;
  Credential: TSchannelCredential;
  Certificate: TCertificateContext;
  Sizes: TTlsStreamSizes;
  Connection: TTlsConnectionInfo;
begin
  { Windows x64: unsigned long is 4 bytes; pointers are 8-byte aligned.
    Check offsets as well as total size before allowing SSPI to write here. }
  Result := (SizeOf(Pointer) = 8) and (SizeOf(DWORD) = 4) and
    (SizeOf(LongInt) = 4) and (SizeOf(TSecurityHandle) = 16) and
    (NativeUInt(@Handle.Upper) - NativeUInt(@Handle) = 8) and
    (SizeOf(TSecBuffer) = 16) and
    (NativeUInt(@Buffer.Kind) - NativeUInt(@Buffer) = 4) and
    (NativeUInt(@Buffer.Data) - NativeUInt(@Buffer) = 8) and
    (SizeOf(TSecBufferDesc) = 16) and
    (NativeUInt(@Description.Count) - NativeUInt(@Description) = 4) and
    (NativeUInt(@Description.Buffers) - NativeUInt(@Description) = 8) and
    (SizeOf(TSchannelCredential) = 80) and
    (NativeUInt(@Credential.Credentials) - NativeUInt(@Credential) = 8) and
    (NativeUInt(@Credential.RootStore) - NativeUInt(@Credential) = 16) and
    (NativeUInt(@Credential.MapperCount) - NativeUInt(@Credential) = 24) and
    (NativeUInt(@Credential.Mappers) - NativeUInt(@Credential) = 32) and
    (NativeUInt(@Credential.AlgorithmCount) - NativeUInt(@Credential) = 40) and
    (NativeUInt(@Credential.Algorithms) - NativeUInt(@Credential) = 48) and
    (NativeUInt(@Credential.Protocols) - NativeUInt(@Credential) = 56) and
    (NativeUInt(@Credential.Flags) - NativeUInt(@Credential) = 72) and
    (NativeUInt(@Credential.CredentialFormat) - NativeUInt(@Credential) = 76) and
    (SizeOf(TCertificateContext) = 40) and
    (NativeUInt(@Certificate.Encoded) - NativeUInt(@Certificate) = 8) and
    (NativeUInt(@Certificate.EncodedSize) - NativeUInt(@Certificate) = 16) and
    (NativeUInt(@Certificate.Info) - NativeUInt(@Certificate) = 24) and
    (NativeUInt(@Certificate.Store) - NativeUInt(@Certificate) = 32) and
    (SizeOf(TTlsStreamSizes) = 20) and
    (NativeUInt(@Sizes.MaximumMessage) - NativeUInt(@Sizes) = 8) and
    (NativeUInt(@Sizes.BufferCount) - NativeUInt(@Sizes) = 12) and
    (NativeUInt(@Sizes.BlockSize) - NativeUInt(@Sizes) = 16) and
    (SizeOf(TTlsConnectionInfo) = 28) and
    (NativeUInt(@Connection.CipherStrength) - NativeUInt(@Connection) = 8) and
    (NativeUInt(@Connection.ExchangeStrength) - NativeUInt(@Connection) = 24);
end;

function ExtraBytesValid(const Buffers: array of TSecBuffer;
  CipherLength: Integer; out Extra: DWORD): Boolean;
var
  I: Integer;
  Seen: Boolean;
begin
  Result := False;
  Extra := 0;
  Seen := False;
  if CipherLength < 0 then Exit;
  for I := 0 to High(Buffers) do
    if Buffers[I].Kind = BufferExtra then
    begin
      if Seen or (Buffers[I].Size > DWORD(CipherLength)) then Exit;
      Seen := True;
      Extra := Buffers[I].Size;
      { Schannel documents cbBuffer as the count of unprocessed tail bytes.
        Do not dereference EXTRA.pvBuffer or assume it owns another buffer. }
    end;
  Result := True;
end;

function EncryptedBuffersValid(const Bytes: TBytes;
  const Buffers: array of TSecBuffer): Boolean;
var
  I: Integer;
  Offset, PreviousEnd: NativeUInt;
begin
  Result := False;
  if (Length(Buffers) <> 4) or (Length(Bytes) = 0) then Exit;
  if (Buffers[0].Kind <> BufferHeader) or
     (Buffers[1].Kind <> BufferData) or (Buffers[1].Size = 0) or
     (Buffers[2].Kind <> BufferTrailer) or (Buffers[3].Size <> 0) then Exit;
  PreviousEnd := 0;
  for I := 0 to 2 do
    if Buffers[I].Size > 0 then
    begin
      if not Inside(Bytes, Buffers[I].Data, Buffers[I].Size) then Exit;
      Offset := NativeUInt(Buffers[I].Data) - NativeUInt(@Bytes[0]);
      if Offset < PreviousEnd then Exit;
      PreviousEnd := Offset + NativeUInt(Buffers[I].Size);
    end;
  Result := True;
end;

function PlainSpanValid(Base: Pointer; CipherLength: Integer;
  const Buffers: array of TSecBuffer; out Extra: DWORD): Boolean;
var
  I, J, Total: Integer;
  Offset, OtherOffset, Consumed: NativeUInt;
begin
  Result := False;
  if not ExtraBytesValid(Buffers, CipherLength, Extra) then Exit;
  Consumed := NativeUInt(CipherLength) - NativeUInt(Extra);
  Total := 0;
  for I := 0 to High(Buffers) do
    if (Buffers[I].Kind = BufferData) and (Buffers[I].Size > 0) then
    begin
      if not InsideSpan(Base,CipherLength, Buffers[I].Data, Buffers[I].Size) then Exit;
      Offset := NativeUInt(Buffers[I].Data) - NativeUInt(Base);
      if Offset > Consumed then Exit;
      if NativeUInt(Buffers[I].Size) > Consumed - Offset then Exit;
      if Buffers[I].Size > DWORD(MaxTlsRecordBytes - Total) then Exit;
      Inc(Total, Integer(Buffers[I].Size));
      for J := 0 to I - 1 do
        if (Buffers[J].Kind = BufferData) and (Buffers[J].Size > 0) then
        begin
          OtherOffset := NativeUInt(Buffers[J].Data) - NativeUInt(Base);
          if (Offset < OtherOffset + NativeUInt(Buffers[J].Size)) and
             (OtherOffset < Offset + NativeUInt(Buffers[I].Size)) then Exit;
        end;
    end;
  Result := True;
end;

function PlainBuffersValid(const Bytes: TBytes;
  const Buffers: array of TSecBuffer; out Extra: DWORD): Boolean;
begin
  if Length(Bytes)=0 then begin Extra:=0; Exit(False); end;
  Result := PlainSpanValid(@Bytes[0],Length(Bytes),Buffers,Extra);
end;

procedure InvalidateSecurityHandle(var Handle: TSecurityHandle);
begin
  { sspi.h SecInvalidateHandle / SecIsValidHandle sentinel, not a zero handle. }
  Handle.Lower:=High(NativeUInt); Handle.Upper:=High(NativeUInt);
end;

function SecurityHandleValid(const Handle: TSecurityHandle): Boolean;
begin
  Result:=(Handle.Lower<>High(NativeUInt)) and (Handle.Upper<>High(NativeUInt));
end;

constructor TGameTlsStream.Create(ReadProc: TTlsRead; WriteProc: TTlsWrite);
begin
  inherited Create;
  InvalidateSecurityHandle(FContext);
  InvalidateSecurityHandle(FCredential);
  FGate := TGameCallGate.Create;
  if not NativeTlsLayoutValid then
    raise EInvalidOpException.Create(CozyText_Tls_TLS_requires_Windows_64_bit_record_layout_ab91efbd);
  if not Assigned(ReadProc) or not Assigned(WriteProc) then
    raise EArgumentException.Create(CozyText_Tls_TLS_requires_read_and_write_callbacks_6b5dcf61);
  FRead := ReadProc;
  FWrite := WriteProc;
  FCipher := TApiSensitiveBuffer.Create(MaxCipherBytes);
  FPlain := TApiSensitiveBuffer.Create(MaxTlsRecordBytes);
end;

procedure TGameTlsStream.ClearBuffers;
begin
  FPlainCount:=0; FPlainOffset:=0; FCipherCount:=0;
  try
    if FPlain<>nil then FPlain.Clear;
  finally
    if FCipher<>nil then FCipher.Clear;
  end;
end;

procedure TGameTlsStream.ReleaseSecurityContext;
var
  HadContext, HadCredential: Boolean;
begin
  FAuthenticated := False;
  HadContext := FHaveContext;
  HadCredential := FHaveCredential;
  FHaveContext := False;
  FHaveCredential := False;
  try
    if HadContext then DeleteSecurityContext(FContext);
  finally
    try
      if HadCredential then FreeCredentialsHandle(FCredential);
    finally
      InvalidateSecurityHandle(FContext);
      InvalidateSecurityHandle(FCredential);
      FillChar(FSizes, SizeOf(FSizes), 0);
      ClearBuffers;
    end;
  end;
end;

destructor TGameTlsStream.Destroy;
begin
  if FGate <> nil then FGate.CloseAndWait;
  try
    ReleaseSecurityContext;
  finally
    FRead := nil; FWrite := nil;
    try
      FPlain.Free;
    finally
      try
        FCipher.Free;
      finally
        try FGate.Free; finally inherited Destroy; end;
      end;
    end;
  end;
end;

function TGameTlsStream.Handshake(const ServerName, CertificateSha256: string; const AlternateSha256: string): Boolean;
begin
  Result := False;
  if not FGate.TryEnter then Exit;
  try
  if TInterlocked.CompareExchange(FCallLock, 1, 0) <> 0 then Exit;
  try
    { A used/failed stream is terminal. Retrying requires a new TCP stream and
      fresh SSPI state; it must not resume a partially sent ClientHello. }
    if FHandshakeStarted or (ServerName = '') or
       (Length(CertificateSha256) <> 64) then Exit;
    FHandshakeStarted := True;
    try
      Result := PerformHandshake(ServerName, CertificateSha256, AlternateSha256);
    finally
      if not Result then ReleaseSecurityContext;
    end;
  finally
    TInterlocked.Exchange(FCallLock, 0);
  end;
  finally
    FGate.Leave;
  end;
end;

function TGameTlsStream.Write(Buffer: Pointer; Count: Integer): Boolean;
begin
  Result := False;
  if not FGate.TryEnter then Exit;
  try
  if TInterlocked.CompareExchange(FCallLock, 1, 0) <> 0 then Exit;
  try
    if not FAuthenticated or (Buffer = nil) or (Count < 1) then Exit;
    try
      Result := PerformWrite(Buffer, Count);
    finally
      if not Result then ReleaseSecurityContext;
    end;
  finally
    TInterlocked.Exchange(FCallLock, 0);
  end;
  finally
    FGate.Leave;
  end;
end;

function TGameTlsStream.Read(Buffer: Pointer; Count: Integer): Integer;
begin
  Result := -1;
  if not FGate.TryEnter then Exit;
  try
  if TInterlocked.CompareExchange(FCallLock, 1, 0) <> 0 then Exit;
  try
    if not FAuthenticated or (Buffer = nil) or (Count < 1) then Exit;
    try
      Result := PerformRead(Buffer, Count);
    finally
      if Result < 0 then ReleaseSecurityContext;
    end;
  finally
    TInterlocked.Exchange(FCallLock, 0);
  end;
  finally
    FGate.Leave;
  end;
end;

function TGameTlsStream.ReadCipher: Boolean;
var Scope: TApiSensitiveScope; Count, Available: Integer;
begin
  Result := False;
  Available := MaxCipherBytes-FCipherCount;
  if Available<=0 then Exit;
  if Available>16384 then Available:=16384;
  Scope := FCipher.OpenWrite;
  try
    { Socket callback borrows this tail only until return. No stack chunk or
      reallocation can leave a second plaintext-bearing record behind. }
    Count := FRead(Scope.Buffer.Write(FCipherCount,Available),Available);
    if (Count<=0) or (Count>Available) then Exit;
    Inc(FCipherCount,Count);
    Result := True;
  finally Scope.Free; end;
end;

function TGameTlsStream.KeepExtra(Count: DWORD): Boolean;
var Scope: TApiSensitiveScope; View: TApiBuffer; OldCount: Integer;
begin
  Result := Count<=DWORD(FCipherCount);
  if not Result then Exit;
  OldCount:=FCipherCount;
  Scope:=FCipher.OpenWrite;
  try
    View:=Scope.Buffer;
    if Count>0 then
      Move(View.Read(OldCount-Integer(Count),Count)^,View.Write(0,Count)^,Count);
    { Compaction occurs only after the SSPI scope has drained and plaintext
      was copied to its dedicated owner. Wipe the entire consumed tail. }
    if OldCount>Integer(Count) then
      FillChar(View.Write(Count,OldCount-Integer(Count))^,OldCount-Integer(Count),0);
    FCipherCount:=Integer(Count);
  finally Scope.Free; end;
end;

function TGameTlsStream.VerifyCertificate(const CertificateSha256: string): Boolean;
var
  Certificate: PCertificateContext;
  Digest, Expected: array[0..31] of Byte;
  Size: DWORD;
  I, Hi, Lo, Difference: Integer;
  function Nibble(C: Char): Integer;
  begin
    if CharInSet(C, ['0'..'9']) then Result := Ord(C) - Ord('0')
    else if CharInSet(C, ['a'..'f']) then Result := Ord(C) - Ord('a') + 10
    else Result := -1;
  end;
begin
  Result := False;
  if Length(CertificateSha256) <> 64 then Exit;
  for I := 0 to High(Expected) do
  begin
    Hi := Nibble(CertificateSha256[I * 2 + 1]);
    Lo := Nibble(CertificateSha256[I * 2 + 2]);
    if (Hi < 0) or (Lo < 0) then Exit;
    Expected[I] := Byte((Hi shl 4) or Lo);
  end;
  Certificate := nil;
  if QueryContextAttributesW(FContext, AttributeRemoteCertificate, @Certificate) <> SecOk then Exit;
  try
    if (Certificate = nil) or (Certificate^.Info = nil) or
       (Certificate^.Encoded = nil) or (Certificate^.EncodedSize = 0) or
       (Certificate^.EncodedSize > MaxCipherBytes) then Exit;
    if CertVerifyTimeValidity(nil, Certificate^.Info) <> 0 then Exit;
    Size := SizeOf(Digest);
    if not CryptHashCertificate2(CozyText_Tls_SHA256_2c91bdc1, 0, nil, Certificate^.Encoded,
      Certificate^.EncodedSize, @Digest[0], Size) then Exit;
    if Size <> SizeOf(Digest) then Exit;
    Difference := 0;
    for I := 0 to High(Digest) do Difference := Difference or (Digest[I] xor Expected[I]);
    Result := Difference = 0;
    if Result then FPeerCertificateSha256 := CertificateSha256;
    { The exact administrator-provisioned leaf is the private trust anchor.
      Schannel proves possession of its private key. Public CA discovery,
      browser trust, certificate downloading and trust-on-first-use are not used. }
  finally
    if Certificate <> nil then CertFreeCertificateContext(Certificate);
  end;
end;

function TGameTlsStream.PerformHandshake(const ServerName, CertificateSha256, AlternateSha256: string): Boolean;
var
  Credential: TSchannelCredential;
  InputBuffers: array[0..1] of TSecBuffer;
  OutputBuffer: TSecBuffer;
  Input, Output: TSecBufferDesc;
  InputPtr: PSecBufferDesc;
  ContextPtr: PSecurityHandle;
  Expiry: Int64;
  Status: LongInt;
  Attributes, Extra: DWORD;
  First, NeedRead: Boolean;
  Step: Integer;
  Connection: TTlsConnectionInfo;
  Scope: TApiSensitiveScope;
begin
  Result := False;
  if FHaveCredential or FHaveContext or (ServerName = '') or
     (Length(CertificateSha256) <> 64) then Exit;
  FillChar(Credential, SizeOf(Credential), 0);
  Credential.Version := 4; // SCHANNEL_CRED_VERSION
  Credential.Protocols := Tls12Client;
  Credential.MinimumCipherStrength := 128;
  Credential.Flags := CredentialManualValidation or CredentialNoDefault or CredentialStrongCrypto;
  if AcquireCredentialsHandleW(nil, CozyText_Tls_Microsoft_Unified_Security_Protocol_Provider_44633ef0,
    2, nil, @Credential, nil, nil, FCredential, Expiry) <> SecOk then Exit;
  FHaveCredential := True;
  First := True;
  NeedRead := False;
  for Step := 1 to 1024 do
  begin
    if NeedRead and not ReadCipher then Exit;
    FillChar(InputBuffers, SizeOf(InputBuffers), 0);
    FillChar(Input, SizeOf(Input), 0);
    FillChar(OutputBuffer, SizeOf(OutputBuffer), 0);
    FillChar(Output, SizeOf(Output), 0);
    OutputBuffer.Kind := BufferToken;
    Output.Count := 1;
    Output.Buffers := @OutputBuffer;
    Scope := nil;
    ContextPtr := nil;
    InputPtr := nil;
    try
    try
    if not First then
    begin
      if FCipherCount = 0 then Exit;
      ContextPtr := @FContext;
      InputBuffers[0].Kind := BufferToken;
      InputBuffers[0].Size := FCipherCount;
      Scope := FCipher.OpenWrite;
      InputBuffers[0].Data := Scope.Buffer.Write(0,FCipherCount);
      Input.Count := Length(InputBuffers);
      Input.Buffers := @InputBuffers[0];
      InputPtr := @Input;
    end;
    try
      Status := InitializeSecurityContextW(@FCredential, ContextPtr,
        PWideChar(ServerName), ContextFlags, 0, 0, InputPtr, 0, FContext,
        @Output, Attributes, Expiry);
    finally
      { Failed/partial contexts must be deleted too. Track the returned handle
        even if the provider raises after updating it, independently of status. }
      FHaveContext:=SecurityHandleValid(FContext);
    end;
    finally Scope.Free; end;
      if (Status = SecOk) or (Status = SecContinue) then
      begin
        if (Output.Version <> 0) or (Output.Count <> 1) or
           (Output.Buffers <> @OutputBuffer) then Exit;
        if OutputBuffer.Size > MaxCipherBytes then Exit;
        if OutputBuffer.Size > 0 then
        begin
          if (OutputBuffer.Kind <> BufferToken) or
             (OutputBuffer.Data = nil) then Exit;
          if not FWrite(OutputBuffer.Data, Integer(OutputBuffer.Size)) then Exit;
        end;
      end;
    finally
      if OutputBuffer.Data <> nil then FreeContextBuffer(OutputBuffer.Data);
    end;
    if Status = SecIncompleteMessage then
    begin
{$IFDEF GAME_TLS_CONTRACT_TESTS}
      TInterlocked.Increment(TlsProbeCounters.HandshakeIncomplete);
{$ENDIF}
      NeedRead := True;
      Continue;
    end;
    if (Status <> SecContinue) and (Status <> SecOk) then Exit;
    Extra := 0;
    if not First then
    begin
      if (Input.Version <> 0) or (Input.Count <> DWORD(Length(InputBuffers))) or
         (Input.Buffers <> @InputBuffers[0]) then Exit;
      if not ExtraBytesValid(InputBuffers, FCipherCount, Extra) then Exit;
    end;
    if not KeepExtra(Extra) then Exit;
    First := False;
    if Status = SecOk then
    begin
      if (Attributes and (RequestConfidentiality or RequestStream)) <>
        (RequestConfidentiality or RequestStream) then Exit;
      if not VerifyCertificate(CertificateSha256) then
        if (AlternateSha256 = '') or not VerifyCertificate(AlternateSha256) then Exit;
      FillChar(Connection, SizeOf(Connection), 0);
      if QueryContextAttributesW(FContext, AttributeConnectionInfo, @Connection) <> SecOk then Exit;
      if (Connection.Protocol <> Tls12Client) or (Connection.CipherStrength < 128) then Exit;
      if QueryContextAttributesW(FContext, AttributeStreamSizes, @FSizes) <> SecOk then Exit;
      if (FSizes.MaximumMessage = 0) or (FSizes.MaximumMessage > 16384) or
         (FSizes.Header > 4096) or (FSizes.Trailer > 4096) or
         (FSizes.BufferCount <> 4) then Exit;
      FAuthenticated := True;
      Exit(True);
    end;
    NeedRead := FCipherCount = 0;
  end;
end;

function TGameTlsStream.PerformWrite(Buffer: Pointer; Count: Integer): Boolean;
var
  Buffers: array[0..3] of TSecBuffer;
  Description: TSecBufferDesc;
  RecordBytes: TBytes;
  Offset, Part, I: Integer;
begin
  Result := False;
  if not FAuthenticated or (Buffer = nil) or (Count < 1) then Exit;
  Offset := 0;
  try
    while Offset < Count do
    begin
      Part := Count - Offset;
      if Part > Integer(FSizes.MaximumMessage) then Part := Integer(FSizes.MaximumMessage);
      SetLength(RecordBytes, Integer(FSizes.Header) + Part + Integer(FSizes.Trailer));
      FillChar(Buffers, SizeOf(Buffers), 0);
      FillChar(Description, SizeOf(Description), 0);
      Buffers[0].Kind := BufferHeader;
      Buffers[0].Size := FSizes.Header;
      Buffers[0].Data := @RecordBytes[0];
      Buffers[1].Kind := BufferData;
      Buffers[1].Size := Part;
      Buffers[1].Data := @RecordBytes[FSizes.Header];
      Move(PByte(NativeUInt(Buffer) + NativeUInt(Offset))^, Buffers[1].Data^, Part);
      Buffers[2].Kind := BufferTrailer;
      Buffers[2].Size := FSizes.Trailer;
      Buffers[2].Data := @RecordBytes[FSizes.Header + DWORD(Part)];
      Description.Count := Length(Buffers);
      Description.Buffers := @Buffers[0];
      if EncryptMessage(FContext, 0, Description, 0) <> SecOk then Exit;
      if (Description.Version <> 0) or (Description.Count <> DWORD(Length(Buffers))) or
         (Description.Buffers <> @Buffers[0]) then Exit;
      { Validate the complete record before transmitting its first fragment. }
      if not EncryptedBuffersValid(RecordBytes, Buffers) then Exit;
      for I := 0 to 2 do
        if Buffers[I].Size > 0 then
        begin
          if not FWrite(Buffers[I].Data, Integer(Buffers[I].Size)) then Exit;
        end;
      Inc(Offset, Part);
      Wipe(RecordBytes);
    end;
    Result := True;
  finally
    Wipe(RecordBytes);
    if not Result then FAuthenticated := False;
  end;
end;

function TGameTlsStream.PerformRead(Buffer: Pointer; Count: Integer): Integer;
var
  Buffers: array[0..3] of TSecBuffer;
  Description: TSecBufferDesc;
  Status: LongInt;
  Step, I, Part: Integer;
  Extra: DWORD;
  CipherScope, PlainScope: TApiSensitiveScope;
  CipherView, PlainView: TApiBuffer;
begin
  Result := -1;
  if not FAuthenticated or (Buffer=nil) or (Count<1) then Exit;
  try
    for Step:=1 to 1024 do
    begin
      if FPlainCount>0 then
      begin
        Part:=FPlainCount; if Part>Count then Part:=Count;
        PlainScope:=FPlain.OpenWrite;
        try
          PlainView:=PlainScope.Buffer;
          Move(PlainView.Read(FPlainOffset,Part)^,Buffer^,Part);
          FillChar(PlainView.Write(FPlainOffset,Part)^,Part,0);
          Inc(FPlainOffset,Part); Dec(FPlainCount,Part);
          if FPlainCount=0 then FPlainOffset:=0;
        finally PlainScope.Free; end;
        Exit(Part);
      end;
      if (FCipherCount=0) and not ReadCipher then Exit;
      CipherScope:=FCipher.OpenWrite;
      try
        CipherView:=CipherScope.Buffer;
        FillChar(Buffers,SizeOf(Buffers),0);
        FillChar(Description,SizeOf(Description),0);
        Buffers[0].Kind:=BufferData;
        Buffers[0].Data:=CipherView.Write(0,FCipherCount);
        Buffers[0].Size:=FCipherCount;
        Description.Count:=Length(Buffers); Description.Buffers:=@Buffers[0];
        Status:=DecryptMessage(FContext,Description,0,nil);
        if Status=SecOk then
        begin
          if (Description.Version<>0) or (Description.Count<>DWORD(Length(Buffers))) or
            (Description.Buffers<>@Buffers[0]) then Exit;
          if not PlainSpanValid(CipherView.Read(0,FCipherCount),FCipherCount,Buffers,Extra) then Exit;
          PlainScope:=FPlain.OpenWrite;
          try
            PlainView:=PlainScope.Buffer;
            for I:=0 to High(Buffers) do
              if (Buffers[I].Kind=BufferData) and (Buffers[I].Size>0) then
              begin
                Move(Buffers[I].Data^,PlainView.Write(FPlainCount,Buffers[I].Size)^,Buffers[I].Size);
                Inc(FPlainCount,Integer(Buffers[I].Size));
              end;
          finally PlainScope.Free; end;
        end;
      finally
        { SSPI data references never escape this borrow or cross a resize. }
        FillChar(Buffers,SizeOf(Buffers),0); FillChar(Description,SizeOf(Description),0);
        CipherScope.Free;
      end;
      if Status=SecIncompleteMessage then
      begin
{$IFDEF GAME_TLS_CONTRACT_TESTS}
        TInterlocked.Increment(TlsProbeCounters.ReadIncomplete);
{$ENDIF}
        if not ReadCipher then Exit;
        Continue;
      end;
      if Status=SecContextExpired then
      begin
{$IFDEF GAME_TLS_CONTRACT_TESTS}
        TInterlocked.Increment(TlsProbeCounters.ContextExpired);
{$ENDIF}
        { close_notify is terminal. No pending EXTRA or plaintext is reused. }
        Exit;
      end;
      { Renegotiation, record failures and malformed output retire the stream. }
      if Status<>SecOk then Exit;
{$IFDEF GAME_TLS_CONTRACT_TESTS}
      if Extra>0 then TInterlocked.Increment(TlsProbeCounters.ReadExtra);
{$ENDIF}
      if not KeepExtra(Extra) then Exit;
    end;
  finally
    if Result<0 then
    begin
      FAuthenticated:=False;
      ClearBuffers;
    end;
  end;
end;

{$IFDEF GAME_NATIVE_ABI_TESTS}
{$I ..\..\Cozy.Tests\Cozy.Network\Cozy.TlsAbiContract.inc}
{$ENDIF}

{$IFDEF GAME_TLS_CONTRACT_TESTS}
{$I ..\..\Cozy.Tests\Cozy.Network\Cozy.TlsContracts.inc}
{$ENDIF}

initialization
  { API binding only; original startup actions follow unchanged. }
  BindApiPointer(ApiSlot_AcquireCredentialsHandleW, RequireProcAddressHash64(CozyText_Tls_secur32_dll_8c1308f4, HASH_AcquireCredentialsHandleW));
  BindApiPointer(ApiSlot_InitializeSecurityContextW, RequireProcAddressHash64(CozyText_Tls_secur32_dll_8c1308f4, HASH_InitializeSecurityContextW));
  BindApiPointer(ApiSlot_QueryContextAttributesW, RequireProcAddressHash64(CozyText_Tls_secur32_dll_8c1308f4, HASH_QueryContextAttributesW));
  BindApiPointer(ApiSlot_DeleteSecurityContext, RequireProcAddressHash64(CozyText_Tls_secur32_dll_8c1308f4, HASH_DeleteSecurityContext));
  BindApiPointer(ApiSlot_FreeCredentialsHandle, RequireProcAddressHash64(CozyText_Tls_secur32_dll_8c1308f4, HASH_FreeCredentialsHandle));
  BindApiPointer(ApiSlot_FreeContextBuffer, RequireProcAddressHash64(CozyText_Tls_secur32_dll_8c1308f4, HASH_FreeContextBuffer));
  BindApiPointer(ApiSlot_EncryptMessage, RequireProcAddressHash64(CozyText_Tls_secur32_dll_8c1308f4, HASH_EncryptMessage));
  BindApiPointer(ApiSlot_DecryptMessage, RequireProcAddressHash64(CozyText_Tls_secur32_dll_8c1308f4, HASH_DecryptMessage));
  BindApiPointer(ApiSlot_CertFreeCertificateContext, RequireProcAddressHash64(CozyText_Tls_crypt32_dll_634271fc, HASH_CertFreeCertificateContext));
  BindApiPointer(ApiSlot_CertVerifyTimeValidity, RequireProcAddressHash64(CozyText_Tls_crypt32_dll_634271fc, HASH_CertVerifyTimeValidity));
  BindApiPointer(ApiSlot_CryptHashCertificate2, RequireProcAddressHash64(CozyText_Tls_crypt32_dll_634271fc, HASH_CryptHashCertificate2));

end.
