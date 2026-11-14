var
  PathBadDNS10N, PathBadValues10N, PathBadCatalog10N, PathRaiseCatalog10N: Boolean;
  PathCleanupCalls10N: Integer;
function PathAdaptersMock10N(Family, Flags: Cardinal; Reserved, AdapterAddresses: Pointer;
  var Size: Cardinal): Cardinal; stdcall;
var A: PAdapterPrefix; Name: PAnsiChar;
begin
  Result := 87;
  if (Family <> 0) or (Flags = 0) or (Reserved <> nil) or
     (AdapterAddresses = nil) or (Size < 512) then Exit;
  FillChar(AdapterAddresses^, 512, 0); A := PAdapterPrefix(AdapterAddresses);
  A^.Length := SizeOf(TAdapterPrefix); A^.OperStatus := 1;
  Name := PAnsiChar(NativeUInt(AdapterAddresses) + 256);
  Name[0] := 't'; Name[1] := 'e'; Name[2] := 's'; Name[3] := 't'; Name[4] := #0;
  A^.AdapterName := Name;
  if PathBadDNS10N then A^.FirstDNS := Pointer(NativeUInt(AdapterAddresses)+Size);
  Result := 0;
end;
function PathOpenMock10N(Key: HKEY; SubKey: PWideChar; Options, Access: Cardinal;
  var Opened: HKEY): LongInt; stdcall;
begin
  Opened := 1;
  if (Key = 0) or (SubKey = nil) or (Options <> 0) or (Access = 0) then Exit(87);
  Result := 0;
end;
function PathEnumKeyMock10N(Key: HKEY; Index: Cardinal; Name: PWideChar;
  var NameChars: Cardinal; Reserved: Pointer; ClassName: PWideChar;
  ClassLength: PCardinal; LastWritten: PFileTime): LongInt; stdcall;
begin
  Result := ERROR_NO_MORE_ITEMS_VALUE;
end;
function PathEnumValueMock10N(Key: HKEY; Index: Cardinal; Name: PWideChar;
  var NameChars: Cardinal; Reserved: Pointer; ValueType: PCardinal;
  ValueData: Pointer; var DataLength: Cardinal): LongInt; stdcall;
begin
  if Index > 0 then
  begin
    if PathBadValues10N then Exit(5);
    Exit(ERROR_NO_MORE_ITEMS_VALUE);
  end;
  if (Key = 0) or (Name = nil) or (NameChars < 2) or
    (ValueData = nil) or (DataLength < 1) or (Reserved <> nil) then Exit(87);
  Name[0] := 'v'; Name[1] := #0; NameChars := 1;
  ValueType^ := 3; PByte(ValueData)^ := 11; DataLength := 1; Result := 0;
end;
function PathCloseMock10N(Key: HKEY): LongInt; stdcall;
begin if Key = 0 then Result := 87 else Result := 0; end;
function PathStartMock10N(Version: Word; Data: Pointer): LongInt; stdcall;
begin if (Version <> $202) or (Data = nil) then Result := 87 else Result := 0; end;
function PathCleanMock10N: LongInt; stdcall;
begin Inc(PathCleanupCalls10N); Result := 0; end;
function PathCatalogMock10N(Protocols, Buffer: Pointer; var BufferLength: Cardinal;
  var ErrorCode: LongInt): LongInt; stdcall;
var P: PProtocolInfo;
begin
  ErrorCode := 0;
  if PathRaiseCatalog10N then raise EReadError.Create('Native10N injected API failure');
  if (Protocols <> nil) or (Buffer = nil) or
     (BufferLength < 2 * SizeOf(TProtocolInfo)) then Exit(-1);
  FillChar(Buffer^, 2 * SizeOf(TProtocolInfo), 0);
  P := PProtocolInfo(Buffer); P^.CatalogEntryId := 1; P^.Chain.ChainLen := 1;
  P^.Chain.ChainEntries[0] := 1;
  P := PProtocolInfo(NativeUInt(Buffer)+SizeOf(TProtocolInfo));
  P^.CatalogEntryId := 2;
  if PathBadCatalog10N then P^.Chain.ChainLen := 8;
  Result := 2;
end;
function TestPathNative10N(out Failure: string; out Checks: Integer): Boolean;
var DNS, Ifaces, Policies, Providers: TStringList;
    OldAdapters: TGetAdaptersAddresses; OldOpen: TRegOpen; OldKey: TRegEnumKey;
    OldValue: TRegEnumValue; OldClose: TRegClose; OldStart: TWSAStartup;
    OldClean: TWSACleanup; OldEnum: TWSCEnumProtocols; OldResolved, Raised: Boolean;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;
begin
  Result := False; Failure := ''; Checks := 0;
  DNS := nil; Ifaces := nil; Policies := nil; Providers := nil;
  OldAdapters := AdaptersAPI; OldOpen := RegOpenAPI; OldKey := RegEnumKeyAPI;
  OldValue := RegEnumValueAPI; OldClose := RegCloseAPI; OldStart := WSStart;
  OldClean := WSClean; OldEnum := WSCEnum; OldResolved := Resolved;
  try
    try
      DNS := TStringList.Create; Ifaces := TStringList.Create;
      Policies := TStringList.Create; Providers := TStringList.Create;
      AdaptersAPI := PathAdaptersMock10N; RegOpenAPI := PathOpenMock10N;
      RegEnumKeyAPI := PathEnumKeyMock10N; RegEnumValueAPI := PathEnumValueMock10N;
      RegCloseAPI := PathCloseMock10N; WSStart := PathStartMock10N;
      WSClean := PathCleanMock10N; WSCEnum := PathCatalogMock10N; Resolved := True;
      PathBadDNS10N := True;
      Check(not TakeAdapterSnapshots(DNS, Ifaces), 'bad DNS node makes adapter capture incomplete');
      Check((DNS.Count = 0) and (Ifaces.Count = 0), 'both outputs cleared after partial adapter success');
      PathBadDNS10N := False;
      Check(TakeAdapterSnapshots(DNS, Ifaces), 'complete adapter capture succeeds');
      Check((DNS.Count = 1) and (Ifaces.Count = 1), 'complete outputs retained');
      Check(not TakeAdapterSnapshots(DNS, DNS) and (DNS.Count = 0), 'aliased outputs rejected');
      Check(not TakeAdapterSnapshots(nil, Ifaces) and (Ifaces.Count = 0), 'nil companion output is safe');
      PathBadValues10N := True;
      Check(not TakeNRPTSnapshot(Policies), 'mid-enumeration registry failure rejected');
      Check(Policies.Count = 0, 'partial policy entries cleared');
      PathBadValues10N := False;
      Check(TakeNRPTSnapshot(Policies) and (Policies.Count > 0), 'complete policy capture succeeds');
      Check(not TakeNRPTSnapshot(nil), 'nil policy list rejected');
      PathCleanupCalls10N := 0; PathBadCatalog10N := True; PathRaiseCatalog10N := False;
      Check(not TakeWinsockCatalogSnapshot(Providers), 'bad second catalog entry rejected');
      Check((Providers.Count = 0) and (PathCleanupCalls10N = 1), 'partial provider list cleared and WSA closed');
      PathBadCatalog10N := False;
      Check(TakeWinsockCatalogSnapshot(Providers) and (Providers.Count = 2), 'complete catalog retained');
      PathRaiseCatalog10N := True; Raised := False;
      try TakeWinsockCatalogSnapshot(Providers); except on E: EReadError do Raised := True; end;
      Check(Raised and (Providers.Count = 0), 'API exception clears wrapper output');
      Check(PathCleanupCalls10N = 3, 'WSA cleanup on failure, success and exception');
      Check(not TakeWinsockCatalogSnapshot(nil), 'nil provider list rejected');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    AdaptersAPI := OldAdapters; RegOpenAPI := OldOpen; RegEnumKeyAPI := OldKey;
    RegEnumValueAPI := OldValue; RegCloseAPI := OldClose; WSStart := OldStart;
    WSClean := OldClean; WSCEnum := OldEnum; Resolved := OldResolved;
    Providers.Free; Policies.Free; Ifaces.Free; DNS.Free;
  end;
end;
