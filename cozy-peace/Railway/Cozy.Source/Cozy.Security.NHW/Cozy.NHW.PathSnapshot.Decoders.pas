unit Cozy.NHW.PathSnapshot.Decoders;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows, System.SysUtils, System.Classes;

const
  AF_INET_VALUE = 2;
  AF_INET6_VALUE = 23;
  MAX_ADAPTERS = 256;
  MAX_DNS_NODES = 64;
  MAX_CATALOG_ENTRIES = 512;

type
  // Windows x64 prefix of IP_ADAPTER_ADDRESSES_LH through Ipv6IfIndex.
  // Natural Win64 record alignment; SizeOf must be 112, offsets checked.
  PAdapterPrefix = ^TAdapterPrefix;
  TAdapterPrefix = record
    Length: Cardinal;
    IfIndex: Cardinal;
    Next: PAdapterPrefix;
    AdapterName: PAnsiChar;
    FirstUnicast: Pointer;
    FirstAnycast: Pointer;
    FirstMulticast: Pointer;
    FirstDNS: Pointer;
    DnsSuffix: PWideChar;
    Description: PWideChar;
    FriendlyName: PWideChar;
    Physical: array[0..7] of Byte;
    PhysicalLength: Cardinal;
    Flags: Cardinal;
    MTU: Cardinal;
    IfType: Cardinal;
    OperStatus: Cardinal;
    Ipv6IfIndex: Cardinal;
  end;

  TSocketAddress = record
    Address: Pointer;
    Length: LongInt;
  end;
  PDnsNode = ^TDnsNode;
  TDnsNode = record
    Length: Cardinal;
    Reserved: Cardinal;
    Next: PDnsNode;
    Socket: TSocketAddress;
  end;

  TProtocolChain = record
    ChainLen: LongInt;
    ChainEntries: array[0..6] of Cardinal;
  end;
  PProtocolInfo = ^TProtocolInfo;
  TProtocolInfo = record
    ServiceFlags: array[0..3] of Cardinal;
    ProviderFlags: Cardinal;
    ProviderId: TGUID;
    CatalogEntryId: Cardinal;
    Chain: TProtocolChain;
    ProtocolFields: array[0..8] of LongInt;
    MessageSize: Cardinal;
    ProviderReserved: Cardinal;
    ProtocolName: array[0..255] of WideChar;
  end;

function InBuffer(const Data: TBytes; P: Pointer; Required: NativeUInt): Boolean;
function ReadBufferName(const Data: TBytes; P: PAnsiChar; out Value: string): Boolean;
function HexAt(P: Pointer; N: Integer): string;
function AddressKey(const Data: TBytes; const Node: TDnsNode; out Key: string): Boolean;
// Caller validates the response size and owns all-or-nothing output cleanup.
function ParseAdapterSnapshots(const Data: TBytes; DNSServers, Interfaces: TStringList): Boolean;
function ParseWinsockCatalog(const Data: TBytes; Status: LongInt; Providers: TStringList): Boolean;

implementation

function InBuffer(const Data: TBytes; P: Pointer; Required: NativeUInt): Boolean;
var StartAt, V, Bytes: NativeUInt;
begin
  Result := False;
  if (Length(Data) = 0) or (P = nil) then Exit;
  StartAt := NativeUInt(@Data[0]);
  V := NativeUInt(P);
  Bytes := NativeUInt(Length(Data));
  if (V < StartAt) or (V - StartAt > Bytes) then Exit;
  Result := Required <= Bytes - (V - StartAt);
end;

function ReadBufferName(const Data: TBytes; P: PAnsiChar;
  out Value: string): Boolean;
var I: Integer;
begin
  Result := False;
  Value := '';
  if (P = nil) or (NativeUInt(P) > High(NativeUInt) - 127) then Exit;
  for I := 0 to 127 do
  begin
    if not InBuffer(Data, Pointer(NativeUInt(P) + NativeUInt(I)), 1) then Exit;
    if P[I] = #0 then
    begin
      Result := I > 0;
      Exit;
    end;
    Value := Value + Char(P[I]);
  end;
end;

function HexAt(P: Pointer; N: Integer): string;
var I: Integer;
    B: PByte;
begin
  Result := '';
  B := PByte(P);
  for I := 0 to N - 1 do
    Result := Result + IntToHex(B[I], 2);
end;

function AddressKey(const Data: TBytes; const Node: TDnsNode;
  out Key: string): Boolean;
var Family: Word;
    Sock: Pointer;
begin
  Result := False;
  Key := '';
  Sock := Node.Socket.Address;
  if (Node.Socket.Length < 2) or (Node.Socket.Length > 128) or
     not InBuffer(Data, Sock, NativeUInt(Node.Socket.Length)) then Exit;
  Family := PWord(Sock)^;
  if (Family = AF_INET_VALUE) and (Node.Socket.Length >= 16) then
    Key := '4:' + HexAt(Pointer(NativeUInt(Sock) + 4), 4)
  else if (Family = AF_INET6_VALUE) and (Node.Socket.Length >= 28) then
    Key := '6:' + HexAt(Pointer(NativeUInt(Sock) + 8), 16)
  else
    Exit;
  Result := True;
end;

function ParseAdapterSnapshots(const Data: TBytes;
  DNSServers, Interfaces: TStringList): Boolean;
var
  AdaptersCount, NodeCount: Integer;
  Adapter: PAdapterPrefix;
  Node: PDnsNode;
  AdapterKey, AddrKey: string;
  Addresses: TStringList;
begin
  Result := False;
  Addresses := TStringList.Create;
  try
    Addresses.Sorted := True;
    Addresses.Duplicates := dupIgnore;
    Adapter := PAdapterPrefix(@Data[0]);
    AdaptersCount := 0;
    while Adapter <> nil do
    begin
      Inc(AdaptersCount);
      if (AdaptersCount > MAX_ADAPTERS) or
         (not InBuffer(Data, Adapter, SizeOf(TAdapterPrefix))) or
         (Adapter^.Length < SizeOf(TAdapterPrefix)) or
         (Adapter^.OperStatus > 7) then Exit;
      if not ReadBufferName(Data, Adapter^.AdapterName, AdapterKey) then Exit;
      Interfaces.Add(AdapterKey + ':' + IntToStr(Adapter^.OperStatus));
      Addresses.Clear;
      Node := PDnsNode(Adapter^.FirstDNS);
      NodeCount := 0;
      while Node <> nil do
      begin
        Inc(NodeCount);
        if (NodeCount > MAX_DNS_NODES) or
           (not InBuffer(Data, Node, SizeOf(TDnsNode))) or
           (Node^.Length < SizeOf(TDnsNode)) then Exit;
        if not AddressKey(Data, Node^, AddrKey) then Exit;
        Addresses.Add(AddrKey);
        Node := Node^.Next;
      end;
      if Addresses.Count = 0 then
        DNSServers.Add(AdapterKey + ':<none>')
      else
        for NodeCount := 0 to Addresses.Count - 1 do
          DNSServers.Add(AdapterKey + ':' + Addresses[NodeCount]);
      Adapter := Adapter^.Next;
    end;
    Result := True;
  finally
    Addresses.Free;
  end;
end;

function ParseWinsockCatalog(const Data: TBytes; Status: LongInt;
  Providers: TStringList): Boolean;
var
  I, J: Integer;
  Item: PProtocolInfo;
  Key: string;
begin
  Result := False;
    if (Status < 0) or (Status > MAX_CATALOG_ENTRIES) then Exit;
    if NativeUInt(Status) > NativeUInt(Length(Data)) div SizeOf(TProtocolInfo) then Exit;
    for I := 0 to Status - 1 do
    begin
      Item := PProtocolInfo(NativeUInt(@Data[0]) + NativeUInt(I) * SizeOf(TProtocolInfo));
      if (Item^.Chain.ChainLen < 0) or (Item^.Chain.ChainLen > 7) then Exit;
      Key := GUIDToString(Item^.ProviderId) + '/' +
        IntToStr(Item^.CatalogEntryId) + '/' + IntToStr(Item^.ProviderFlags) +
        '/' + IntToStr(Item^.Chain.ChainLen) + '/' +
        IntToStr(Item^.ProtocolFields[1]) + '/' +
        IntToStr(Item^.ProtocolFields[4]) + '/' +
        IntToStr(Item^.ProtocolFields[5]) + '/' +
        IntToHex(Item^.ServiceFlags[0], 8) + '/' +
        IntToHex(Item^.ServiceFlags[1], 8) + '/' +
        IntToHex(Item^.ServiceFlags[2], 8) + '/' +
        IntToHex(Item^.ServiceFlags[3], 8);
      for J := 0 to Item^.Chain.ChainLen - 1 do
        Key := Key + '/' + IntToStr(Item^.Chain.ChainEntries[J]);
      Providers.Add(Key);
    end;
    Result := True;
end;

end.
