unit Cozy.NHW.KernelTrust.PlatformNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  Cozy.NHW.KernelTrust.Native;

const
  DRIVER_SERVICE_KERNEL = $00000001;
  DRIVER_SERVICE_FILE_SYSTEM = $00000002;

  DRIVER_TRUST_UNKNOWN = 0;
  DRIVER_TRUST_EMBEDDED = 1;
  DRIVER_TRUST_CATALOG = 2;
  DRIVER_TRUST_UNTRUSTED = 3;

type
  TDriverServiceInfo = record
    Name: string;
    ImagePath: string;
    CanonicalPath: string;
    ServiceType: Cardinal;
    StartType: Cardinal;
  end;
  TDriverServiceInfos = TArray<TDriverServiceInfo>;

  TPlatformSecuritySnapshot = record
    DeviceGuardValid: Boolean;
    HypervisorViewValid: Boolean;
    HypervisorPresent: Boolean;
    VirtFirmwareValid: Boolean;
    VirtFirmwareEnabled: Boolean;
    VBSStatus: Cardinal; // Win32_DeviceGuard: 0 off, 1 enabled/not running, 2 running
    DMAProtectionAvailable: Boolean; // AvailableSecurityProperties contains 3
    DMAPropertyObserved: Boolean;
    RequirePlatformSecurityValid: Boolean;
    RequirePlatformSecurityFeatures: Cardinal;
  end;

function CaptureDriverServices(out Services: TDriverServiceInfos): Boolean;
function DriverServiceMatchesModule(const Service: TDriverServiceInfo;
  const Module: TKernelModuleInfo): Boolean;
function FindDriverServiceForModule(const Services: TDriverServiceInfos;
  const Module: TKernelModuleInfo; out Service: TDriverServiceInfo): Boolean;
function DriverServiceKey(const Service: TDriverServiceInfo): string;
function QueryDriverTrustState(const Path: string; out TrustState: Byte): Boolean;
function CapturePlatformSecuritySnapshot(out Snapshot: TPlatformSecuritySnapshot): Boolean;

implementation

uses
  Winapi.ActiveX,
  System.Variants,
  System.Win.ComObj,
  Cozy.NHW.Cancellation,
  Cozy.NHW.WinPointers;

const
  KEY_READ_LOCAL = $00020019;
  REG_SZ_LOCAL = 1;
  REG_EXPAND_SZ_LOCAL = 2;
  REG_DWORD_LOCAL = 4;
  HKEY_LOCAL_MACHINE_VALUE = NativeUInt($80000002);
  SERVICES_PATH = 'SYSTEM\CurrentControlSet\Services';
  DEVICEGUARD_PATH = 'SYSTEM\CurrentControlSet\Control\DeviceGuard';
  SERVICE_ENUM_MAX = 8192;
  SERVICE_NAME_MAX = 1024;
  REG_VALUE_MAX_BYTES = 64 * 1024;
  PF_VIRT_FIRMWARE_ENABLED_LOCAL = 21;

  WTD_UI_NONE = 2;
  WTD_REVOKE_NONE = 0;
  WTD_CHOICE_FILE = 1;
  WTD_STATEACTION_IGNORE = 0;
  WTD_CACHE_ONLY_URL_RETRIEVAL = $00001000;

  DRIVER_ACTION_VERIFY: TGUID = '{F750E6C3-38EE-11D1-85E5-00C04FC295EE}';
  WINTRUST_ACTION_GENERIC_VERIFY_V2: TGUID = '{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}';

type
  TRegOpenKeyExW = function(hKey: HKEY; lpSubKey: PWideChar; ulOptions,
    samDesired: Cardinal; var phkResult: HKEY): LongInt; stdcall;
  TRegEnumKeyExW = function(hKey: HKEY; dwIndex: Cardinal; lpName: PWideChar;
    var lpcchName: Cardinal; lpReserved: PCardinal; lpClass: PWideChar;
    lpcchClass: PCardinal; lpftLastWriteTime: PFileTime): LongInt; stdcall;
  TRegQueryValueExW = function(hKey: HKEY; lpValueName: PWideChar;
    lpReserved, lpType: PCardinal; lpData: PByte; lpcbData: PCardinal): LongInt; stdcall;
  TRegCloseKey = function(hKey: HKEY): LongInt; stdcall;
  TExpandEnvironmentStringsW = function(lpSrc, lpDst: PWideChar;
    nSize: Cardinal): Cardinal; stdcall;
  TIsProcessorFeaturePresent = function(ProcessorFeature: Cardinal): BOOL; stdcall;

  TWinTrustFileInfo = record
    cbStruct: Cardinal;
    pcwszFilePath: PWideChar;
    hFile: THandle;
    pgKnownSubject: PGUID;
  end;

  TWinTrustData = record
    cbStruct: Cardinal;
    pPolicyCallbackData: Pointer;
    pSIPClientData: Pointer;
    dwUIChoice: Cardinal;
    fdwRevocationChecks: Cardinal;
    dwUnionChoice: Cardinal;
    pInfo: Pointer;
    dwStateAction: Cardinal;
    hWVTStateData: THandle;
    pwszURLReference: PWideChar;
    dwProvFlags: Cardinal;
    dwUIContext: Cardinal;
    pSignatureSettings: Pointer;
  end;

  TWinVerifyTrust = function(hwnd: HWND; pgActionID: PGUID;
    pWVTData: Pointer): LongInt; stdcall;

  TCryptCATAdminAcquireContext2 = function(var hCatAdmin: THandle;
    pgSubsystem: PGUID; pwszHashAlgorithm: PWideChar;
    pStrongHashPolicy: Pointer; dwFlags: Cardinal): BOOL; stdcall;
  TCryptCATAdminCalcHashFromFileHandle2 = function(hCatAdmin, hFile: THandle;
    pcbHash: PCardinal; pbHash: PByte; dwFlags: Cardinal): BOOL; stdcall;
  TCryptCATAdminEnumCatalogFromHash = function(hCatAdmin: THandle; pbHash: PByte;
    cbHash, dwFlags: Cardinal; phPrevCatInfo: Pointer): THandle; stdcall;
  TCryptCATAdminReleaseCatalogContext = function(hCatAdmin,
    hCatInfo: THandle; dwFlags: Cardinal): BOOL; stdcall;
  TCryptCATAdminReleaseContext = function(hCatAdmin: THandle;
    dwFlags: Cardinal): BOOL; stdcall;

var
  RegOpenKeyPtr: TRegOpenKeyExW = nil;
  RegEnumKeyPtr: TRegEnumKeyExW = nil;
  RegQueryValuePtr: TRegQueryValueExW = nil;
  RegCloseKeyPtr: TRegCloseKey = nil;
  ExpandEnvPtr: TExpandEnvironmentStringsW = nil;
  IsProcessorFeaturePresentPtr: TIsProcessorFeaturePresent = nil;
  WinVerifyTrustPtr: TWinVerifyTrust = nil;
  CatAcquire2Ptr: TCryptCATAdminAcquireContext2 = nil;
  CatCalcHash2Ptr: TCryptCATAdminCalcHashFromFileHandle2 = nil;
  CatEnumPtr: TCryptCATAdminEnumCatalogFromHash = nil;
  CatReleaseCatalogPtr: TCryptCATAdminReleaseCatalogContext = nil;
  CatReleasePtr: TCryptCATAdminReleaseContext = nil;
  PlatformResolved: Boolean = False;

procedure ResolvePlatformAPIs;
var A, K, W: HMODULE;
begin
  if PlatformResolved then Exit;
  A := WinLoadLibrary('advapi32.dll');
  K := WinModule('kernel32.dll');
  W := WinLoadLibrary('wintrust.dll');
  RegOpenKeyPtr := TRegOpenKeyExW(WinExport(A, 'RegOpenKeyExW'));
  RegEnumKeyPtr := TRegEnumKeyExW(WinExport(A, 'RegEnumKeyExW'));
  RegQueryValuePtr := TRegQueryValueExW(WinExport(A, 'RegQueryValueExW'));
  RegCloseKeyPtr := TRegCloseKey(WinExport(A, 'RegCloseKey'));
  ExpandEnvPtr := TExpandEnvironmentStringsW(WinExport(K, 'ExpandEnvironmentStringsW'));
  IsProcessorFeaturePresentPtr := TIsProcessorFeaturePresent(
    WinExport(K, 'IsProcessorFeaturePresent'));
  WinVerifyTrustPtr := TWinVerifyTrust(WinExport(W, 'WinVerifyTrust'));
  CatAcquire2Ptr := TCryptCATAdminAcquireContext2(
    WinExport(W, 'CryptCATAdminAcquireContext2'));
  CatCalcHash2Ptr := TCryptCATAdminCalcHashFromFileHandle2(
    WinExport(W, 'CryptCATAdminCalcHashFromFileHandle2'));
  CatEnumPtr := TCryptCATAdminEnumCatalogFromHash(
    WinExport(W, 'CryptCATAdminEnumCatalogFromHash'));
  CatReleaseCatalogPtr := TCryptCATAdminReleaseCatalogContext(
    WinExport(W, 'CryptCATAdminReleaseCatalogContext'));
  CatReleasePtr := TCryptCATAdminReleaseContext(
    WinExport(W, 'CryptCATAdminReleaseContext'));
  PlatformResolved := Assigned(RegOpenKeyPtr) and Assigned(RegEnumKeyPtr) and
    Assigned(RegQueryValuePtr) and Assigned(RegCloseKeyPtr);
end;

function QueryRegDword(Key: HKEY; const Name: string; out Value: Cardinal): Boolean;
var T, Bytes: Cardinal;
begin
  Result := False;
  Value := 0;
  if not Assigned(RegQueryValuePtr) then Exit;
  T := 0;
  Bytes := SizeOf(Value);
  if RegQueryValuePtr(Key, PWideChar(Name), nil, @T, @Value, @Bytes) <> ERROR_SUCCESS then Exit;
  Result := (T = REG_DWORD_LOCAL) and (Bytes = SizeOf(Value));
end;

function QueryRegString(Key: HKEY; const Name: string; out Value: string): Boolean;
var T, Bytes, N: Cardinal; B: TBytes; P: PWideChar;
begin
  Result := False;
  Value := '';
  if not Assigned(RegQueryValuePtr) then Exit;
  T := 0;
  Bytes := 0;
  if RegQueryValuePtr(Key, PWideChar(Name), nil, @T, nil, @Bytes) <> ERROR_SUCCESS then Exit;
  if (T <> REG_SZ_LOCAL) and (T <> REG_EXPAND_SZ_LOCAL) then Exit;
  if (Bytes < SizeOf(WideChar)) or (Bytes > REG_VALUE_MAX_BYTES) then Exit;
  SetLength(B, Bytes + SizeOf(WideChar));
  FillChar(B[0], Length(B), 0);
  if RegQueryValuePtr(Key, PWideChar(Name), nil, @T, @B[0], @Bytes) <> ERROR_SUCCESS then Exit;
  P := PWideChar(@B[0]);
  N := 0;
  while (N < Bytes div SizeOf(WideChar)) and (P[N] <> #0) do Inc(N);
  SetString(Value, P, N);
  if (T = REG_EXPAND_SZ_LOCAL) and Assigned(ExpandEnvPtr) and (Value <> '') then
  begin
    SetLength(B, 32768 * SizeOf(WideChar));
    N := ExpandEnvPtr(PWideChar(Value), PWideChar(@B[0]), 32768);
    if (N > 0) and (N < 32768) then
      SetString(Value, PWideChar(@B[0]), N - 1);
  end;
  Result := True;
end;

function StripDriverArguments(const S: string): string;
var P: Integer; Q: string;
begin
  Q := Trim(S);
  if Q = '' then Exit('');
  if Q[1] = '"' then
  begin
    Delete(Q, 1, 1);
    P := Pos('"', Q);
    if P > 0 then Q := Copy(Q, 1, P - 1);
  end
  else
  begin
    P := Pos('.sys', LowerCase(Q));
    if P > 0 then Q := Copy(Q, 1, P + 3);
  end;
  Result := Trim(Q);
end;

function CanonicalServiceImage(const ServiceName, Raw: string): string;
var P, W: string;
begin
  P := StripDriverArguments(Raw);
  W := GetWindowsRoot;
  if P = '' then
  begin
    if W = '' then Exit('');
    P := W + '\System32\drivers\' + ServiceName + '.sys';
  end;
  if SameText(Copy(P, 1, 10), '\System32\') and (W <> '') then
    P := W + Copy(P, 10, MaxInt)
  else if SameText(Copy(P, 1, 9), 'System32\') and (W <> '') then
    P := W + '\' + P;
  if SameText(Copy(P, 1, 12), '\SystemRoot\') and (W <> '') then
    P := W + Copy(P, 12, MaxInt);
  if SameText(Copy(P, 1, 4), '\??\') then P := Copy(P, 5, MaxInt);
  Result := LowerCase(StringReplace(P, '/', '\', [rfReplaceAll]));
end;

procedure SortServices(var Services: TDriverServiceInfos);
var I, J: Integer; V: TDriverServiceInfo;
begin
  for I := 1 to High(Services) do
  begin
    V := Services[I];
    J := I;
    while (J > 0) and (CompareText(Services[J-1].Name, V.Name) > 0) do
    begin
      Services[J] := Services[J-1];
      Dec(J);
    end;
    Services[J] := V;
  end;
end;

function CaptureDriverServices(out Services: TDriverServiceInfos): Boolean;
var Root, Sub: HKEY; I, Count: Cardinal; NameLen: Cardinal;
  NameBuf: array[0..SERVICE_NAME_MAX - 1] of WideChar;
  Name, Image: string; T, Start: Cardinal; Item: TDriverServiceInfo;
begin
  Result := False;
  Services := nil;
  ResolvePlatformAPIs;
  if not PlatformResolved then Exit;
  Root := 0;
  if RegOpenKeyPtr(HKEY(HKEY_LOCAL_MACHINE_VALUE), PWideChar(SERVICES_PATH),
       0, KEY_READ_LOCAL, Root) <> ERROR_SUCCESS then Exit;
  try
    Count := 0;
    I := 0;
    while I < SERVICE_ENUM_MAX do
    begin
      FillChar(NameBuf, SizeOf(NameBuf), 0);
      NameLen := Length(NameBuf);
      case RegEnumKeyPtr(Root, I, @NameBuf[0], NameLen, nil, nil, nil, nil) of
        ERROR_SUCCESS: ;
        ERROR_NO_MORE_ITEMS: Break;
      else
        Exit(False);
      end;
      Inc(I);
      if (NameLen = 0) or (NameLen >= Cardinal(Length(NameBuf))) then Continue;
      SetString(Name, PWideChar(@NameBuf[0]), NameLen);
      Sub := 0;
      if RegOpenKeyPtr(Root, PWideChar(Name), 0, KEY_READ_LOCAL, Sub) <> ERROR_SUCCESS then Continue;
      try
        T := 0;
        if not QueryRegDword(Sub, 'Type', T) then Continue;
        if (T and (DRIVER_SERVICE_KERNEL or DRIVER_SERVICE_FILE_SYSTEM)) = 0 then Continue;
        Start := High(Cardinal);
        QueryRegDword(Sub, 'Start', Start);
        Image := '';
        QueryRegString(Sub, 'ImagePath', Image);
        Item := Default(TDriverServiceInfo);
        Item.Name := Name;
        Item.ImagePath := Image;
        Item.CanonicalPath := CanonicalServiceImage(Name, Image);
        Item.ServiceType := T;
        Item.StartType := Start;
        SetLength(Services, Count + 1);
        Services[Count] := Item;
        Inc(Count);
      finally
        RegCloseKeyPtr(Sub);
      end;
    end;
    SortServices(Services);
    Result := True;
  finally
    RegCloseKeyPtr(Root);
  end;
end;

function BaseNameLower(const P: string): string;
var I: Integer;
begin
  Result := LowerCase(P);
  for I := Length(Result) downto 1 do
    if Result[I] = '\' then Exit(Copy(Result, I + 1, MaxInt));
end;

function DriverServiceMatchesModule(const Service: TDriverServiceInfo;
  const Module: TKernelModuleInfo): Boolean;
var M: string;
begin
  M := LowerCase(Module.Path);
  Result := (Service.CanonicalPath <> '') and (M <> '') and
    (SameText(Service.CanonicalPath, M) or
     ((BaseNameLower(Service.CanonicalPath) <> '') and
      SameText(BaseNameLower(Service.CanonicalPath), BaseNameLower(M))));
end;

function FindDriverServiceForModule(const Services: TDriverServiceInfos;
  const Module: TKernelModuleInfo; out Service: TDriverServiceInfo): Boolean;
var I: Integer;
begin
  Service := Default(TDriverServiceInfo);
  for I := 0 to High(Services) do
    if DriverServiceMatchesModule(Services[I], Module) then
    begin
      Service := Services[I];
      Exit(True);
    end;
  Result := False;
end;

function DriverServiceKey(const Service: TDriverServiceInfo): string;
begin
  Result := LowerCase(Service.Name) + '|' + LowerCase(Service.CanonicalPath);
end;

function EmbeddedTrustOK(const Path: string): Boolean;
var F: TWinTrustFileInfo; D: TWinTrustData; S: LongInt;
begin
  Result := False;
  ResolvePlatformAPIs;
  if not Assigned(WinVerifyTrustPtr) then Exit;
  if (SizeOf(TWinTrustFileInfo) <> 32) or (SizeOf(TWinTrustData) <> 88) then Exit;
  F := Default(TWinTrustFileInfo);
  F.cbStruct := SizeOf(F);
  F.pcwszFilePath := PWideChar(Path);
  D := Default(TWinTrustData);
  D.cbStruct := SizeOf(D);
  D.dwUIChoice := WTD_UI_NONE;
  D.fdwRevocationChecks := WTD_REVOKE_NONE;
  D.dwUnionChoice := WTD_CHOICE_FILE;
  D.pInfo := @F;
  D.dwStateAction := WTD_STATEACTION_IGNORE;
  D.dwProvFlags := WTD_CACHE_ONLY_URL_RETRIEVAL;
  S := WinVerifyTrustPtr(HWND(-1), @WINTRUST_ACTION_GENERIC_VERIFY_V2, @D);
  Result := S = 0;
end;

function CatalogAssociationExists(const Path: string): Boolean;
var H, Admin, Cat: THandle; Hash: array[0..127] of Byte; HashBytes: Cardinal;
begin
  Result := False;
  ResolvePlatformAPIs;
  if not Assigned(CatAcquire2Ptr) or not Assigned(CatCalcHash2Ptr) or
     not Assigned(CatEnumPtr) or not Assigned(CatReleaseCatalogPtr) or
     not Assigned(CatReleasePtr) then Exit;
  H := WinCreateFile(PWideChar(Path), GENERIC_READ,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if H = INVALID_HANDLE_VALUE then Exit;
  Admin := 0;
  try
    if not CatAcquire2Ptr(Admin, @DRIVER_ACTION_VERIFY, nil, nil, 0) or (Admin = 0) then Exit;
    try
      FillChar(Hash, SizeOf(Hash), 0);
      HashBytes := SizeOf(Hash);
      if not CatCalcHash2Ptr(Admin, H, @HashBytes, @Hash[0], 0) then Exit;
      if (HashBytes = 0) or (HashBytes > SizeOf(Hash)) then Exit;
      Cat := CatEnumPtr(Admin, @Hash[0], HashBytes, 0, nil);
      if Cat <> 0 then
      begin
        Result := True;
        CatReleaseCatalogPtr(Admin, Cat, 0);
      end;
    finally
      CatReleasePtr(Admin, 0);
    end;
  finally
    WinCloseHandle(H);
  end;
end;

function QueryDriverTrustState(const Path: string; out TrustState: Byte): Boolean;
var Id: TDriverFileIdentity;
begin
  Result := False;
  TrustState := DRIVER_TRUST_UNKNOWN;
  if not QueryDriverFileIdentity(Path, Id) then Exit;
  if EmbeddedTrustOK(Path) then
    TrustState := DRIVER_TRUST_EMBEDDED
  else if CatalogAssociationExists(Path) then
    TrustState := DRIVER_TRUST_CATALOG
  else
    TrustState := DRIVER_TRUST_UNTRUSTED;
  Result := True;
end;

function VariantArrayHasInteger(const V: OleVariant; Wanted: Integer): Boolean;
var L, H, I: Integer;
begin
  Result := False;
  if not VarIsArray(V) then Exit;
  try
    L := VarArrayLowBound(V, 1);
    H := VarArrayHighBound(V, 1);
    for I := L to H do
      if Integer(V[I]) = Wanted then Exit(True);
  except
    Result := False;
  end;
end;

function CapturePlatformSecuritySnapshot(out Snapshot: TPlatformSecuritySnapshot): Boolean;
var Hr: HRESULT; NeedUninit: Boolean; Locator, Service, Items, Item: OleVariant;
  EnumUnk: IUnknown; EnumVar: IEnumVariant; Fetched: LongWord; V: OleVariant;
  CSService, CSItems, CSItem: OleVariant; CSEnumUnk: IUnknown; CSEnum: IEnumVariant;
  RegRoot: HKEY; RegValue: Cardinal; CancelEnabled: Boolean;
begin
  Snapshot := Default(TPlatformSecuritySnapshot);
  ResolvePlatformAPIs;
  if Assigned(IsProcessorFeaturePresentPtr) then
  begin
    Snapshot.VirtFirmwareValid := True;
    if IsProcessorFeaturePresentPtr(PF_VIRT_FIRMWARE_ENABLED_LOCAL) then
      Snapshot.VirtFirmwareEnabled := True;
  end;

  RegRoot := 0;
  if Assigned(RegOpenKeyPtr) and
     (RegOpenKeyPtr(HKEY(HKEY_LOCAL_MACHINE_VALUE), PWideChar(DEVICEGUARD_PATH),
        0, KEY_READ_LOCAL, RegRoot) = ERROR_SUCCESS) then
  begin
    try
      if QueryRegDword(RegRoot, 'RequirePlatformSecurityFeatures', RegValue) then
      begin
        Snapshot.RequirePlatformSecurityValid := True;
        Snapshot.RequirePlatformSecurityFeatures := RegValue;
      end;
    finally
      RegCloseKeyPtr(RegRoot);
    end;
  end;

  if NHWCancellationRequested then
    Exit(Snapshot.VirtFirmwareValid or Snapshot.RequirePlatformSecurityValid);
  NeedUninit := False;
  Hr := CoInitializeEx(nil, COINIT_MULTITHREADED);
  if (Hr = S_OK) or (Hr = S_FALSE) then NeedUninit := True
  else if Hr <> RPC_E_CHANGED_MODE then
    Exit(Snapshot.VirtFirmwareValid or Snapshot.RequirePlatformSecurityValid);
  CancelEnabled := NHWEnableComCancellation;
  try
    // An unavailable cancellation facility must not introduce a non-cancellable
    // provider call during shutdown. Retain the independent local observations
    // and leave the WMI views UNKNOWN for this sample.
    if not CancelEnabled then
      Exit(Snapshot.VirtFirmwareValid or Snapshot.RequirePlatformSecurityValid);
    if NHWCancellationRequested then
      Exit(Snapshot.VirtFirmwareValid or Snapshot.RequirePlatformSecurityValid);
    try
      Locator := CreateOleObject('WbemScripting.SWbemLocator');
      Service := Locator.ConnectServer('.', 'root\Microsoft\Windows\DeviceGuard',
        '', '', '', '', $80);
      Items := Service.ExecQuery('SELECT AvailableSecurityProperties,VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard', 'WQL', $30);
      EnumUnk := IUnknown(Items._NewEnum);
      EnumVar := EnumUnk as IEnumVariant;
      Item := Unassigned;
      Fetched := 0;
      if EnumVar.Next(1, Item, Fetched) = S_OK then
      begin
        Snapshot.DeviceGuardValid := True;
        Snapshot.VBSStatus := Cardinal(Integer(Item.VirtualizationBasedSecurityStatus));
        V := Item.AvailableSecurityProperties;
        Snapshot.DMAPropertyObserved := VarIsArray(V);
        if Snapshot.DMAPropertyObserved then
          Snapshot.DMAProtectionAvailable := VariantArrayHasInteger(V, 3);
      end;
    except
      Snapshot.DeviceGuardValid := False;
    end;

    if NHWCancellationRequested then
      Exit(Snapshot.DeviceGuardValid or Snapshot.VirtFirmwareValid or
        Snapshot.RequirePlatformSecurityValid);
    try
      Locator := CreateOleObject('WbemScripting.SWbemLocator');
      CSService := Locator.ConnectServer('.', 'root\cimv2', '', '', '', '', $80);
      CSItems := CSService.ExecQuery('SELECT HypervisorPresent FROM Win32_ComputerSystem', 'WQL', $30);
      CSEnumUnk := IUnknown(CSItems._NewEnum);
      CSEnum := CSEnumUnk as IEnumVariant;
      CSItem := Unassigned;
      Fetched := 0;
      if CSEnum.Next(1, CSItem, Fetched) = S_OK then
      begin
        if not VarIsNull(CSItem.HypervisorPresent) and
           not VarIsEmpty(CSItem.HypervisorPresent) then
        begin
          Snapshot.HypervisorViewValid := True;
          Snapshot.HypervisorPresent := Boolean(CSItem.HypervisorPresent);
        end;
      end;
    except
      Snapshot.HypervisorViewValid := False;
    end;
  finally
    // Release automation/COM references on the owning initialized thread.
    // CoCancelCall is cooperative, so the guard still waits for this unwind.
    CSEnum := nil;
    CSEnumUnk := nil;
    EnumVar := nil;
    EnumUnk := nil;
    VarClear(V);
    VarClear(CSItem);
    VarClear(CSItems);
    VarClear(CSService);
    VarClear(Item);
    VarClear(Items);
    VarClear(Service);
    VarClear(Locator);
    if CancelEnabled then NHWDisableComCancellation;
    if NeedUninit then CoUninitialize;
  end;
  Result := Snapshot.DeviceGuardValid or Snapshot.HypervisorViewValid or
    Snapshot.VirtFirmwareValid or Snapshot.RequirePlatformSecurityValid;
end;

end.
