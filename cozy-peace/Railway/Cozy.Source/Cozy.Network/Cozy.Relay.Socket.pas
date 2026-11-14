unit Cozy.Relay.Socket;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Network,
{$IF (Defined(GAME_RELAY_SOCKET_CONTRACT_TESTS))}
  Cozy.Strings.TestsNetwork,
{$ENDIF}

  Winapi.Windows, Winapi.WinSock2, System.SysUtils, System.SyncObjs, Cozy.Tls;

type
  TRelaySocketClient = class
  private
    FSock: TSocket;
    FOperationLock: TCriticalSection;
    FCloseRequested: Integer;
    FCancelled: TFunc<Boolean>;
    FBuffer: UTF8String;
    FPeerCertificateSha256: string;
    FWSAStarted: Boolean;
    FRequestTimeoutMs: Cardinal;
    FMaxLineBytes: Integer;
    FDeadline: UInt64;
    FTls: TGameTlsStream;
    function WaitSocket(ForWrite: Boolean; PhaseDeadline: UInt64 = 0): Boolean;
    procedure CloseCore;
    procedure CloseSocket;
    function GetPeerCertificateSha256: string;
    function ConnectTCP(const Host: string; Port: Word): Boolean;
    function RawWrite(Buffer: Pointer; Count: Integer): Boolean;
    function RawRead(Buffer: Pointer; Count: Integer): Integer;
    function RemainingTimeout(DefaultMs: Cardinal): Cardinal;
    function ApplyTimeout(Option: Integer; DefaultMs: Cardinal): Boolean;
  public
    { One deadline bounds DNS, connect, TLS, send and receive together.
      Zero selects the secure transport default of ten seconds. }
    constructor Create(RequestTimeoutMs: Cardinal = 0; MaxLineBytes: Integer = 0;
      const Cancelled: TFunc<Boolean> = nil);
    destructor Destroy; override;
    function ConnectTLS(const Host: string; Port: Word;
      const ServerName, CertificateSha256: string; const AlternateSha256: string = ''): Boolean;
    property PeerCertificateSha256: string read GetPeerCertificateSha256;
    { Close may cancel a concurrent operation; it waits for that operation to
      release its TLS/socket ownership. Do not Destroy until callers have joined.
      Explicit Close is terminal. Create a new client for another request. }
    procedure Close;
    function SendLine(const Text: string): Boolean;
    function ReceiveLine(out Line: string): Boolean;
    function IsConnected: Boolean;
  end;

{$IFDEF GAME_RELAY_SOCKET_CONTRACT_TESTS}
procedure RunRelaySocketContractTests;
{$ENDIF}

implementation

uses Cozy.Clock,
  System.Classes, Cozy.ProtocolJson, Cozy.Relay.Config,
  Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer;

{ Private API pointers: initialized before application code starts. }
var
  ResolverCount: Integer;

  ApiSlot_CloseHandle: TEncodedApiPointer;
  ApiSlot_CreateEvent: TEncodedApiPointer;
  ApiSlot_SetEvent: TEncodedApiPointer;
  ApiSlot_WaitForSingleObject: TEncodedApiPointer;
  ApiSlot_WSAStartup: TEncodedApiPointer;
  ApiSlot_WSACleanup: TEncodedApiPointer;
  ApiSlot_WSAGetLastError: TEncodedApiPointer;
  ApiSlot_GetAddrInfoExW: TEncodedApiPointer;
  ApiSlot_FreeAddrInfoExW: TEncodedApiPointer;
  ApiSlot_ioctlsocket: TEncodedApiPointer;
  ApiSlot_socket: TEncodedApiPointer;
  ApiSlot_connect: TEncodedApiPointer;
  ApiSlot_select: TEncodedApiPointer;
  ApiSlot_setsockopt: TEncodedApiPointer;
  ApiSlot_getsockopt: TEncodedApiPointer;
  ApiSlot_shutdown: TEncodedApiPointer;
  ApiSlot_closesocket: TEncodedApiPointer;
  ApiSlot_send: TEncodedApiPointer;
  ApiSlot_recv: TEncodedApiPointer;


const
  { ioctlsocket expects a signed Windows long, also in Win64.
    FIONBIO is the 32-bit bit pattern $8004667E. }
  SocketNonBlockingCommand: Longint = -2147195266;

const
  MaxResolvedCandidates = 8;
  MaxResolverEntries = 64;
  MaxOutstandingResolvers = 4;
  MaxConnectAttemptMs = 1000;
  NameSpaceDns = 12;

type
  { Native Windows ADDRINFOEXW ABI. Pointer-sized fields keep Win64 alignment;
    sockaddr data is copied, never retained after FreeAddrInfoExW. }
  PRelayAddrInfoEx = ^TRelayAddrInfoEx;
  TRelayAddrInfoEx = record
    Flags, Family, SocketType, Protocol: Integer;
    AddressLength: NativeUInt;
    CanonicalName: PWideChar;
    Address, Blob: Pointer;
    BlobLength: NativeUInt;
    Provider: PGUID;
    Next: PRelayAddrInfoEx;
  end;
  TRelayAddress = record
    Family, Length: Integer;
    Bytes: array[0..127] of Byte;
  end;
  TRelayAddresses = array of TRelayAddress;
  TApiGetAddrInfoExW = function(Name, Service: PWideChar; NameSpace: DWORD;
    Provider: PGUID; Hints: PRelayAddrInfoEx; var Addresses: PRelayAddrInfoEx;
    Timeout: Pointer; Overlapped: POverlapped; Completion: Pointer;
    CancelHandle: Pointer): Integer; stdcall;
  TApiFreeAddrInfoExW = procedure(Addresses: PRelayAddrInfoEx); stdcall;

  IHostResolution = interface
    ['{4764C7A1-6743-48F8-96BF-84B2C46EA130}']
    procedure Resolve;
    procedure Cancel;
    function Wait(Timeout: Cardinal): Boolean;
    function Done: Boolean;
    function Addresses: TRelayAddresses;
  end;

  THostResolution = class(TInterfacedObject, IHostResolution)
  private
    FHost, FService: string;
    FDone: THandle;
    FDeadline: UInt64;
    FCancelled: Integer;
    FAddresses: TRelayAddresses;
    FSucceeded, FAdmitted: Boolean;
  public
    constructor Create(const Host: string; Port: Word; Deadline: UInt64);
    destructor Destroy; override;
    procedure Resolve;
    procedure Cancel;
    function Wait(Timeout: Cardinal): Boolean;
    function Done: Boolean;
    function Addresses: TRelayAddresses;
  end;

  TResolverThread = class(TThread)
  private
    FState: IHostResolution;
  protected
    procedure Execute; override;
  public
    constructor Create(const State: IHostResolution);
  end;

{$IFDEF GAME_RELAY_SOCKET_CONTRACT_TESTS}
var
  SocketTestResolveMode: Integer;
  SocketTestFreeCalls: Integer;
  SocketTestResult: PRelayAddrInfoEx;
  SocketTestEntered, SocketTestRelease: THandle;
  SocketTestOwner: IHostResolution;
function SocketTestResolve(var Addresses: PRelayAddrInfoEx): Integer; forward;
{$ENDIF}

{ POINTER WRAPPERS 1 BEGIN }

function CloseHandle(Handle: THandle): BOOL; stdcall;
var
  ApiTarget: TApiCloseHandle;
begin
  ApiTarget := TApiCloseHandle(DecodeApiPointer(ApiSlot_CloseHandle));
  Result := ApiTarget(Handle);
end;

function CreateEvent(Attributes: PSecurityAttributes; ManualReset, InitialState: BOOL;
    Name: PWideChar): THandle; stdcall;
var
  ApiTarget: TApiCreateEvent;
begin
  ApiTarget := TApiCreateEvent(DecodeApiPointer(ApiSlot_CreateEvent));
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

function WSAStartup(Version: Word; var Data: TWSAData): Integer; stdcall;
var
  ApiTarget: TApiWSAStartup;
begin
  ApiTarget := TApiWSAStartup(DecodeApiPointer(ApiSlot_WSAStartup));
  Result := ApiTarget(Version, Data);
end;

function WSACleanup: Integer; stdcall;
var
  ApiTarget: TApiWSACleanup;
begin
  ApiTarget := TApiWSACleanup(DecodeApiPointer(ApiSlot_WSACleanup));
  Result := ApiTarget();
end;

function WSAGetLastError: Integer; stdcall;
var
  ApiTarget: TApiWSAGetLastError;
begin
  ApiTarget := TApiWSAGetLastError(DecodeApiPointer(ApiSlot_WSAGetLastError));
  Result := ApiTarget();
end;

function GetAddrInfoExW(Name, Service: PWideChar; NameSpace: DWORD;
  Provider: PGUID; Hints: PRelayAddrInfoEx; var Addresses: PRelayAddrInfoEx;
  Timeout: Pointer; Overlapped: POverlapped; Completion: Pointer;
  CancelHandle: Pointer): Integer; stdcall;
var ApiTarget: TApiGetAddrInfoExW;
begin
{$IFDEF GAME_RELAY_SOCKET_CONTRACT_TESTS}
  if SocketTestResolveMode <> 0 then
    Exit(SocketTestResolve(Addresses));
{$ENDIF}
  ApiTarget := TApiGetAddrInfoExW(DecodeApiPointer(ApiSlot_GetAddrInfoExW));
  Result := ApiTarget(Name, Service, NameSpace, Provider, Hints, Addresses,
    Timeout, Overlapped, Completion, CancelHandle);
end;

procedure FreeAddrInfoExW(Addresses: PRelayAddrInfoEx); stdcall;
var ApiTarget: TApiFreeAddrInfoExW;
begin
{$IFDEF GAME_RELAY_SOCKET_CONTRACT_TESTS}
  if SocketTestResolveMode <> 0 then
  begin Inc(SocketTestFreeCalls); Exit; end;
{$ENDIF}
  ApiTarget := TApiFreeAddrInfoExW(DecodeApiPointer(ApiSlot_FreeAddrInfoExW));
  ApiTarget(Addresses);
end;

function ioctlsocket(Socket: TSocket; Command: LongInt; var Argument: Cardinal): Integer; stdcall;
var
  ApiTarget: TApiIoctlsocket;
begin
  ApiTarget := TApiIoctlsocket(DecodeApiPointer(ApiSlot_ioctlsocket));
  Result := ApiTarget(Socket, Command, Argument);
end;

function socket(AddressFamily, SocketType, Protocol: Integer): TSocket; stdcall;
var
  ApiTarget: TApiSocket;
begin
  ApiTarget := TApiSocket(DecodeApiPointer(ApiSlot_socket));
  Result := ApiTarget(AddressFamily, SocketType, Protocol);
end;

function connect(Socket: TSocket; const Address: TSockAddr; AddressLength: Integer): Integer; stdcall;
var
  ApiTarget: TApiConnect;
begin
  ApiTarget := TApiConnect(DecodeApiPointer(ApiSlot_connect));
  Result := ApiTarget(Socket, Address, AddressLength);
end;

function select(Count: Integer; ReadSet, WriteSet, ErrorSet, Timeout: Pointer): Integer; stdcall;
var
  ApiTarget: TApiSelect;
begin
  ApiTarget := TApiSelect(DecodeApiPointer(ApiSlot_select));
  Result := ApiTarget(Count, ReadSet, WriteSet, ErrorSet, Timeout);
end;

function setsockopt(Socket: TSocket; Level, Option: Integer; Value: PAnsiChar;
    ValueLength: Integer): Integer; stdcall;
var
  ApiTarget: TApiSetsockopt;
begin
  ApiTarget := TApiSetsockopt(DecodeApiPointer(ApiSlot_setsockopt));
  Result := ApiTarget(Socket, Level, Option, Value, ValueLength);
end;

function getsockopt(Socket: TSocket; Level, Option: Integer; Value: PAnsiChar;
    var ValueLength: Integer): Integer; stdcall;
var
  ApiTarget: TApiGetsockopt;
begin
  ApiTarget := TApiGetsockopt(DecodeApiPointer(ApiSlot_getsockopt));
  Result := ApiTarget(Socket, Level, Option, Value, ValueLength);
end;

function shutdown(Socket: TSocket; How: Integer): Integer; stdcall;
var
  ApiTarget: TApiShutdown;
begin
  ApiTarget := TApiShutdown(DecodeApiPointer(ApiSlot_shutdown));
  Result := ApiTarget(Socket, How);
end;

function CloseNativeSocket(Socket: TSocket): Integer; stdcall;
var
  ApiTarget: TApiClosesocket;
begin
  ApiTarget := TApiClosesocket(DecodeApiPointer(ApiSlot_closesocket));
  Result := ApiTarget(Socket);
end;

function send(Socket: TSocket; const Buffer; Length, Flags: Integer): Integer; stdcall;
var
  ApiTarget: TApiSend;
begin
  ApiTarget := TApiSend(DecodeApiPointer(ApiSlot_send));
  Result := ApiTarget(Socket, Buffer, Length, Flags);
end;

function recv(Socket: TSocket; var Buffer; Length, Flags: Integer): Integer; stdcall;
var
  ApiTarget: TApiRecv;
begin
  ApiTarget := TApiRecv(DecodeApiPointer(ApiSlot_recv));
  Result := ApiTarget(Socket, Buffer, Length, Flags);
end;
{ POINTER WRAPPERS 1 END }

function CopyResolvedAddresses(Head: PRelayAddrInfoEx): TRelayAddresses;
var Entry: PRelayAddrInfoEx; Candidate: TRelayAddress; Seen, I: Integer;
    Duplicate: Boolean;
begin
  Result := nil; Entry := Head; Seen := 0;
  while (Entry <> nil) and (Seen < MaxResolverEntries) and
    (Length(Result) < MaxResolvedCandidates) do
  begin
    Inc(Seen);
    if (((Entry^.Family = AF_INET) and (Entry^.AddressLength = 16)) or
        ((Entry^.Family = AF_INET6) and (Entry^.AddressLength = 28))) and
      (Entry^.SocketType = SOCK_STREAM) and
      ((Entry^.Protocol = 0) or (Entry^.Protocol = IPPROTO_TCP)) and
      (Entry^.Address <> nil) then
    begin
      FillChar(Candidate, SizeOf(Candidate), 0);
      Candidate.Family := Entry^.Family; Candidate.Length := Integer(Entry^.AddressLength);
      Move(Entry^.Address^, Candidate.Bytes[0], Candidate.Length);
      { Reject malformed provider output; the family must agree with sockaddr. }
      if PWord(@Candidate.Bytes[0])^ = Candidate.Family then
      begin
        Duplicate := False;
        for I := 0 to High(Result) do
          if (Result[I].Family = Candidate.Family) and
            (Result[I].Length = Candidate.Length) and
            CompareMem(@Result[I].Bytes[0], @Candidate.Bytes[0], Candidate.Length) then
            Duplicate := True;
        if not Duplicate then
        begin
          SetLength(Result, Length(Result) + 1);
          Result[High(Result)] := Candidate;
        end;
      end;
    end;
    Entry := Entry^.Next;
  end;
end;

constructor THostResolution.Create(const Host: string; Port: Word; Deadline: UInt64);
var Current: Integer;
begin
  inherited Create;
  repeat
    Current := TInterlocked.CompareExchange(ResolverCount, 0, 0);
    if Current >= MaxOutstandingResolvers then
      raise EInvalidOpException.Create(CozyText_Relay_Socket_DNS_RESOLVER_CAPACITY_0254f2e1);
  until TInterlocked.CompareExchange(ResolverCount, Current + 1, Current) = Current;
  FAdmitted := True;
  FHost := Host; FService := UIntToStr(Port); FDeadline := Deadline;
  FDone := CreateEvent(nil, True, False, nil);
  if FDone = 0 then RaiseLastOSError;
end;

destructor THostResolution.Destroy;
begin
  if FDone <> 0 then CloseHandle(FDone);
  if FAdmitted then TInterlocked.Decrement(ResolverCount);
  inherited Destroy;
end;

procedure THostResolution.Cancel;
begin
  TInterlocked.Exchange(FCancelled, 1);
end;

procedure THostResolution.Resolve;
var Data: TWSAData; Hints: TRelayAddrInfoEx; Results: PRelayAddrInfoEx;
    Error: Integer;
begin
  Results := nil;
  try
    { The synchronous provider call runs only on an admitted owned worker.
      The caller still leaves at its own deadline/cancellation; this worker
      retains its strings, result and Winsock reference until the API returns.
      Do not use asynchronous DNS cancellation to recycle admission: Windows
      can report cancellation while a legacy provider is still running. }
    if (TInterlocked.CompareExchange(FCancelled, 0, 0) <> 0) or
      (CozyTick >= FDeadline) then Exit;
    if WSAStartup($0202, Data) <> 0 then Exit;
    try
      FillChar(Hints, SizeOf(Hints), 0);
      Hints.Family := AF_UNSPEC; Hints.SocketType := SOCK_STREAM;
      Hints.Protocol := IPPROTO_TCP;
      if (TInterlocked.CompareExchange(FCancelled, 0, 0) <> 0) or
        (CozyTick >= FDeadline) then Exit;
      { No overlapped state, cancellation handle or provider timeout. Only
        the calling request has a deadline; abandoned provider work remains
        admitted until actual return, with at most four owned workers. }
      Error := GetAddrInfoExW(PWideChar(FHost), PWideChar(FService), NameSpaceDns,
        nil, @Hints, Results, nil, nil, nil, nil);
      if (Error <> 0) or (TInterlocked.CompareExchange(FCancelled, 0, 0) <> 0) or
        (CozyTick >= FDeadline) then Exit;
      FAddresses := CopyResolvedAddresses(Results);
      FSucceeded := Length(FAddresses) > 0;
    finally
      if Results <> nil then FreeAddrInfoExW(Results);
      WSACleanup;
    end;
  finally
    SetEvent(FDone);
  end;
end;

function THostResolution.Wait(Timeout: Cardinal): Boolean;
begin
  Result := (WaitForSingleObject(FDone, Timeout) = WAIT_OBJECT_0) and FSucceeded;
end;

function THostResolution.Done: Boolean;
begin
  Result := WaitForSingleObject(FDone, 0) = WAIT_OBJECT_0;
end;

function THostResolution.Addresses: TRelayAddresses;
begin
  if not Done then raise EInvalidOpException.Create(CozyText_Relay_Socket_DNS_NOT_COMPLETE_51a87470);
  Result := Copy(FAddresses);
end;

constructor TResolverThread.Create(const State: IHostResolution);
begin
  inherited Create(True);
  FState := State;
  FreeOnTerminate := True;
end;

procedure TResolverThread.Execute;
begin
  FState.Resolve;
end;

constructor TRelaySocketClient.Create(RequestTimeoutMs: Cardinal; MaxLineBytes: Integer;
  const Cancelled: TFunc<Boolean>);
begin
  inherited Create;
  FSock := INVALID_SOCKET; FCancelled := Cancelled;
  FOperationLock := TCriticalSection.Create;
  if RequestTimeoutMs > 0 then FRequestTimeoutMs := RequestTimeoutMs
  else FRequestTimeoutMs := 10000;
  if (MaxLineBytes < 0) or (MaxLineBytes > MAX_INPUT_BUFFER) then
    raise EArgumentOutOfRangeException.Create(CozyText_Relay_Socket_RELAY_LINE_LIMIT_e5c24e34);
  if MaxLineBytes > 0 then FMaxLineBytes := MaxLineBytes
  else FMaxLineBytes := MAX_INPUT_BUFFER;
end;

destructor TRelaySocketClient.Destroy;
begin
  Close;
  FOperationLock.Free;
  inherited Destroy;
end;

function TRelaySocketClient.RemainingTimeout(DefaultMs: Cardinal): Cardinal;
var
  NowTick, Left: UInt64;
begin
  Result := DefaultMs;
  if TInterlocked.CompareExchange(FCloseRequested, 0, 0) <> 0 then Exit(0);
  if Assigned(FCancelled) and FCancelled() then Exit(0);
  if FDeadline = 0 then Exit;
  NowTick := CozyTick;
  if NowTick >= FDeadline then Exit(0);
  Left := FDeadline - NowTick;
  if Left < UInt64(Result) then Result := Cardinal(Left);
end;

function TRelaySocketClient.ApplyTimeout(Option: Integer; DefaultMs: Cardinal): Boolean;
var
  Timeout: Cardinal;
begin
  Timeout := RemainingTimeout(DefaultMs);
  Result := (Timeout > 0) and
    (setsockopt(FSock, SOL_SOCKET, Option,
      PAnsiChar(@Timeout), SizeOf(Timeout)) = 0);
end;

function TRelaySocketClient.ConnectTCP(const Host: string; Port: Word): Boolean;
var
  Data: TWSAData;
  State: IHostResolution;
  Resolver: TResolverThread;
  Candidates: TRelayAddresses;
  Candidate: TRelayAddress;
  Mode, Timeout: Cardinal;
  AttemptDeadline: UInt64;
  Error, ErrorSize, Enabled: Integer;
begin
  Result := False; State := nil;
  CloseCore;
  FDeadline := CozyTick + UInt64(FRequestTimeoutMs);
  if (Host = '') or (Length(Host) > 253) or (Pos(#0, Host) <> 0) or
    (Port = 0) or (RemainingTimeout(1) = 0) then Exit;
  if WSAStartup($0202, Data) <> 0 then Exit;
  FWSAStarted := True;
  try
    if RemainingTimeout(1) = 0 then Exit;
    State := THostResolution.Create(Host, Port, FDeadline);
    Resolver := TResolverThread.Create(State);
    try
      Resolver.Start;
    except
      Resolver.FreeOnTerminate := False;
      Resolver.Free;
      raise;
    end;
    repeat
      Timeout := RemainingTimeout(25);
      if Timeout = 0 then Exit;
      if State.Wait(Timeout) then Break;
      if State.Done then Exit;
    until False;
    if RemainingTimeout(1) = 0 then Exit;
    Candidates := State.Addresses;
    State := nil;
    for Candidate in Candidates do
    begin
      if RemainingTimeout(1) = 0 then Exit;
      FSock := socket(Candidate.Family, SOCK_STREAM, IPPROTO_TCP);
      if FSock = INVALID_SOCKET then Continue;
      Mode := 1;
      if ioctlsocket(FSock, SocketNonBlockingCommand, Mode) <> 0 then
      begin CloseSocket; Continue; end;
      if RemainingTimeout(1) = 0 then Exit;
      AttemptDeadline := CozyTick + UInt64(RemainingTimeout(MaxConnectAttemptMs));
      if connect(FSock, PSockAddr(@Candidate.Bytes[0])^, Candidate.Length) = SOCKET_ERROR then
      begin
        Error := WSAGetLastError;
        if (Error <> WSAEWOULDBLOCK) and (Error <> WSAEINPROGRESS) then
        begin CloseSocket; Continue; end;
        if not WaitSocket(True, AttemptDeadline) then
        begin CloseSocket; Continue; end;
        Error := 0; ErrorSize := SizeOf(Error);
        if (RemainingTimeout(1) = 0) or
          (getsockopt(FSock, SOL_SOCKET, SO_ERROR, PAnsiChar(@Error), ErrorSize) <> 0) or
          (Error <> 0) then
        begin CloseSocket; Continue; end;
      end;
      { Address fallback ends at TCP success. A TLS pin failure never triggers
        a different identity, a relaxed policy or an extra address retry. }
      if not ApplyTimeout(SO_RCVTIMEO, 45000) then Exit;
      if not ApplyTimeout(SO_SNDTIMEO, 15000) then Exit;
      Enabled := 1;
      if (RemainingTimeout(1) = 0) or
        (setsockopt(FSock, IPPROTO_TCP, TCP_NODELAY,
          PAnsiChar(@Enabled), SizeOf(Enabled)) <> 0) then Exit;
      Result := RemainingTimeout(1) > 0;
      Exit;
    end;
  finally
    if State <> nil then State.Cancel;
    State := nil;
    if not Result then CloseCore;
  end;
end;

procedure TRelaySocketClient.CloseSocket;
var OwnedSocket: TSocket;
begin
  OwnedSocket := FSock; FSock := INVALID_SOCKET;
  if OwnedSocket <> INVALID_SOCKET then
  begin
    shutdown(OwnedSocket, SD_BOTH);
    CloseNativeSocket(OwnedSocket);
  end;
end;

procedure TRelaySocketClient.CloseCore;
begin
  FreeAndNil(FTls);
  CloseSocket;
  FBuffer := ''; FPeerCertificateSha256 := '';
  FDeadline := 0;
  if FWSAStarted then
  begin
    WSACleanup;
    FWSAStarted := False;
  end;
end;

procedure TRelaySocketClient.Close;
begin
  TInterlocked.Exchange(FCloseRequested, 1);
  if FOperationLock = nil then Exit;
  FOperationLock.Acquire;
  try CloseCore; finally FOperationLock.Release; end;
end;

function TRelaySocketClient.GetPeerCertificateSha256: string;
begin
  FOperationLock.Acquire;
  try Result := FPeerCertificateSha256; finally FOperationLock.Release; end;
end;

function TRelaySocketClient.ConnectTLS(const Host: string; Port: Word;
  const ServerName, CertificateSha256: string; const AlternateSha256: string): Boolean;
begin
  Result := False;
  FOperationLock.Acquire;
  try
    if not ConnectTCP(Host, Port) then Exit;
    try
      if RemainingTimeout(1) = 0 then Exit;
      FTls := TGameTlsStream.Create(RawRead, RawWrite);
      FPeerCertificateSha256 := '';
      Result := FTls.Handshake(ServerName, CertificateSha256, AlternateSha256) and
        (RemainingTimeout(1) > 0);
      if Result then FPeerCertificateSha256 := FTls.PeerCertificateSha256;
    finally
      if not Result then CloseCore;
    end;
  finally FOperationLock.Release; end;
end;

function TRelaySocketClient.WaitSocket(ForWrite: Boolean; PhaseDeadline: UInt64): Boolean;
var Ready, Errors: TFDSet; WaitTime: TTimeVal; Timeout: Cardinal; Count: Integer; NowTick: UInt64;
begin
  Result := False;
  repeat
    Timeout := RemainingTimeout(25);
    if (Timeout = 0) or (FSock = INVALID_SOCKET) then Exit;
    if PhaseDeadline <> 0 then
    begin
      NowTick := CozyTick;
      if NowTick >= PhaseDeadline then Exit;
      if PhaseDeadline - NowTick < Timeout then Timeout := Cardinal(PhaseDeadline - NowTick);
    end;
    FillChar(Ready, SizeOf(Ready), 0); FillChar(Errors, SizeOf(Errors), 0);
    Ready.fd_count := 1; Ready.fd_array[0] := FSock;
    Errors.fd_count := 1; Errors.fd_array[0] := FSock;
    WaitTime.tv_sec := 0; WaitTime.tv_usec := Timeout * 1000;
    if ForWrite then Count := select(0, nil, @Ready, @Errors, @WaitTime)
    else Count := select(0, @Ready, nil, @Errors, @WaitTime);
    if Count < 0 then Exit;
    if Errors.fd_count <> 0 then Exit;
    if (Count > 0) and (Ready.fd_count <> 0) then
      Exit((RemainingTimeout(1) > 0) and
        ((PhaseDeadline = 0) or (CozyTick < PhaseDeadline)));
  until False;
end;

function TRelaySocketClient.RawWrite(Buffer: Pointer; Count: Integer): Boolean;
var Sent, TotalSent, Error: Integer;
begin
  Result := False;
  if (FSock = INVALID_SOCKET) or (Buffer = nil) or (Count < 1) then Exit;
  TotalSent := 0;
  while TotalSent < Count do
  begin
    if not WaitSocket(True) then Exit;
    Sent := send(FSock, PByte(NativeUInt(Buffer) + NativeUInt(TotalSent))^,
      Count - TotalSent, 0);
    if Sent = SOCKET_ERROR then
    begin
      Error := WSAGetLastError;
      if Error = WSAEWOULDBLOCK then Continue;
      Exit;
    end;
    if Sent <= 0 then Exit;
    Inc(TotalSent, Sent);
  end;
  Result := RemainingTimeout(1) > 0;
end;

function TRelaySocketClient.RawRead(Buffer: Pointer; Count: Integer): Integer;
var Error: Integer;
begin
  Result := -1;
  if (FSock = INVALID_SOCKET) or (Buffer = nil) or (Count < 1) then Exit;
  repeat
    if not WaitSocket(False) then Exit(-1);
    Result := recv(FSock, Buffer^, Count, 0);
    if Result <> SOCKET_ERROR then Break;
    Error := WSAGetLastError;
    if Error <> WSAEWOULDBLOCK then Exit(-1);
  until False;
  if RemainingTimeout(1) = 0 then Result := -1;
end;

function TRelaySocketClient.SendLine(const Text: string): Boolean;
var
  Data: UTF8String;
begin
  Result := False;
  FOperationLock.Acquire;
  try
    try
      if (FSock = INVALID_SOCKET) or (FTls = nil) or (RemainingTimeout(1) = 0) then Exit;
    if (Pos(#10, Text) > 0) or (Pos(#13, Text) > 0) then Exit;
    Data := UTF8String(Text);
    if (Length(Data) < 1) or (Length(Data) > FMaxLineBytes) then Exit;
    Data := Data + AnsiChar(#10);
    Result := FTls.Write(PAnsiChar(Data), Length(Data)) and
      (RemainingTimeout(1) > 0);
    if Result then FPeerCertificateSha256 := FTls.PeerCertificateSha256;
  finally
      if not Result then CloseCore;
    end;
  finally FOperationLock.Release; end;
end;

function TRelaySocketClient.ReceiveLine(out Line: string): Boolean;
var
  RecvBuffer: array[0..4095] of AnsiChar;
  Chunk, RawLine: UTF8String;
  Received, P: Integer;
begin
  Result := False;
  Line := '';
  FOperationLock.Acquire;
  try
    try
      if (FSock = INVALID_SOCKET) or (FTls = nil) or (RemainingTimeout(1) = 0) then Exit;
    while True do
    begin
      P := Pos(UTF8String(#10), FBuffer);
      if P > 0 then
      begin
        if (P - 1 > FMaxLineBytes) or (RemainingTimeout(1) = 0) then Exit;
        RawLine := Copy(FBuffer, 1, P - 1);
        Delete(FBuffer, 1, P);
        if (Length(RawLine) > 0) and (RawLine[Length(RawLine)] = AnsiChar(#13)) then
          SetLength(RawLine, Length(RawLine) - 1);
        Line := DecodeProtocolUTF8(RawLine);
        if RemainingTimeout(1) = 0 then begin Line := ''; Exit; end;
        Result := True;
        Exit;
      end;
      if Length(FBuffer) > FMaxLineBytes then Exit;
      if RemainingTimeout(1) = 0 then Exit;
      Received := FTls.Read(@RecvBuffer[0], SizeOf(RecvBuffer));
      if (Received <= 0) or (RemainingTimeout(1) = 0) then Exit;
      SetString(Chunk, PAnsiChar(@RecvBuffer[0]), Received);
      FBuffer := FBuffer + Chunk;
      { At most one receive chunk can be pending beyond the line bound. }
      if Length(FBuffer) > FMaxLineBytes + SizeOf(RecvBuffer) then Exit;
    end;
  finally
      if not Result then CloseCore;
    end;
  finally FOperationLock.Release; end;
end;

function TRelaySocketClient.IsConnected: Boolean;
begin
  FOperationLock.Acquire;
  try
    Result := (FSock <> INVALID_SOCKET) and (FTls <> nil) and
      (TInterlocked.CompareExchange(FCloseRequested, 0, 0) = 0);
  finally FOperationLock.Release; end;
end;

{$IFDEF GAME_RELAY_SOCKET_CONTRACT_TESTS}
{$I ..\..\Cozy.Tests\Cozy.Network\Cozy.RelaySocketContracts.inc}
{$ENDIF}

initialization
  { API binding only; original startup actions follow unchanged. }

  BindApiPointer(ApiSlot_CloseHandle, RequireProcAddressHash64(CozyText_Relay_Socket_kernel32_dll_542befce, HASH_CloseHandle));
  BindApiPointer(ApiSlot_CreateEvent, RequireProcAddressHash64(CozyText_Relay_Socket_kernel32_dll_542befce, HASH_CreateEventW));
  BindApiPointer(ApiSlot_SetEvent, RequireProcAddressHash64(CozyText_Relay_Socket_kernel32_dll_542befce, HASH_SetEvent));
  BindApiPointer(ApiSlot_WaitForSingleObject, RequireProcAddressHash64(CozyText_Relay_Socket_kernel32_dll_542befce, HASH_WaitForSingleObject));
  BindApiPointer(ApiSlot_WSAStartup, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_WSAStartup));
  BindApiPointer(ApiSlot_WSACleanup, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_WSACleanup));
  BindApiPointer(ApiSlot_WSAGetLastError, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_WSAGetLastError));
  BindApiPointer(ApiSlot_GetAddrInfoExW, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_GetAddrInfoExW));
  BindApiPointer(ApiSlot_FreeAddrInfoExW, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_FreeAddrInfoExW));
  BindApiPointer(ApiSlot_ioctlsocket, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_ioctlsocket));
  BindApiPointer(ApiSlot_socket, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_socket));
  BindApiPointer(ApiSlot_connect, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_connect));
  BindApiPointer(ApiSlot_select, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_select));
  BindApiPointer(ApiSlot_setsockopt, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_setsockopt));
  BindApiPointer(ApiSlot_getsockopt, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_getsockopt));
  BindApiPointer(ApiSlot_shutdown, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_shutdown));
  BindApiPointer(ApiSlot_closesocket, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_closesocket));
  BindApiPointer(ApiSlot_send, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_send));
  BindApiPointer(ApiSlot_recv, RequireProcAddressHash64(CozyText_Relay_Socket_ws2_32_dll_7e077a44, HASH_recv));

end.
