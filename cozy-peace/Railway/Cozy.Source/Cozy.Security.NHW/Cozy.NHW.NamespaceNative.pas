unit Cozy.NHW.NamespaceNative;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Namespace.Decoders;

type
  TNamespaceEntry = Cozy.NHW.Namespace.Decoders.TNamespaceEntry;
  TNamespaceEntries = Cozy.NHW.Namespace.Decoders.TNamespaceEntries;

function NamespaceNativeAvailable: Boolean;
function EnumerateNamespace(const NativeDirectory: string;
  Entries: TNamespaceEntries): Boolean;
function QueryNamespaceDacl(const NativeDirectory: string;
  out Signature: UInt64): Boolean;

{$IFDEF NHW_NATIVE5_TESTS}
function TestNamespaceNativeHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses
  System.SyncObjs,
  Cozy.NHW.WinPointers,
  Cozy.NHW.Native;

const
  DIRECTORY_QUERY_RIGHT = $0001;
  NS_READ_CONTROL = $00020000;
  SYMLINK_QUERY_RIGHT = $0001;
  OBJ_CASE_INSENSITIVE = $00000040;
  DACL_SECURITY_INFORMATION_NS = $00000004;
  STATUS_NO_MORE_ENTRIES_NS = $8000001A;
  STATUS_MORE_ENTRIES_NS = $00000105;
  STATUS_BUFFER_TOO_SMALL_NS = $C0000023;
  STATUS_BUFFER_OVERFLOW_NS = $80000005;
  STATUS_LENGTH_MISMATCH_NS = $C0000004;
  NS_PAGE_BYTES = 65536;
  NS_MAX_PAGES = 128;
  NS_MAX_DACL_BYTES = 65536;
  NS_MAX_LINK_BYTES = 65534;
  NS_QUERY_ATTEMPTS = 4;

type
  TNtOpenDirectory = function(var Handle: THandle;
    DesiredAccess: Cardinal; ObjectAttributes: Pointer): LongInt; stdcall;
  TNtQueryDirectory = function(Handle: THandle; Buffer: Pointer;
    BufferLength: Cardinal; ReturnSingleEntry, RestartScan: Byte;
    Context, ReturnLength: PCardinal): LongInt; stdcall;
  TNtOpenSymbolicLink = function(var Handle: THandle;
    DesiredAccess: Cardinal; ObjectAttributes: Pointer): LongInt; stdcall;
  TNtQuerySymbolicLink = function(Handle: THandle;
    LinkTarget: Pointer; ReturnLength: PCardinal): LongInt; stdcall;
  TNtQueryObjectSecurity = function(Handle: THandle; SecurityInformation: Cardinal;
    Buffer: Pointer; BufferLength: Cardinal; Required: PCardinal): LongInt; stdcall;
  TNamespaceAPI = record
    OpenDirectory: TNtOpenDirectory;
    QueryDirectory: TNtQueryDirectory;
    OpenLink: TNtOpenSymbolicLink;
    QueryLink: TNtQuerySymbolicLink;
    QuerySecurity: TNtQueryObjectSecurity;
  end;

var
  NamespaceLock: TCriticalSection;
  APIs: TNamespaceAPI;

procedure NamespaceAPI(out A: TNamespaceAPI);
var
  Ntdll: HMODULE;
begin
  NamespaceLock.Acquire;
  try
    if not (Assigned(APIs.OpenDirectory) and Assigned(APIs.QueryDirectory) and
      Assigned(APIs.OpenLink) and Assigned(APIs.QueryLink) and
      Assigned(APIs.QuerySecurity)) then
    begin
      Ntdll := WinModule('ntdll.dll');
      if Ntdll <> 0 then
      begin
        APIs.OpenDirectory := TNtOpenDirectory(WinExport(Ntdll, 'NtOpenDirectoryObject'));
        APIs.QueryDirectory := TNtQueryDirectory(WinExport(Ntdll, 'NtQueryDirectoryObject'));
        APIs.OpenLink := TNtOpenSymbolicLink(WinExport(Ntdll, 'NtOpenSymbolicLinkObject'));
        APIs.QueryLink := TNtQuerySymbolicLink(WinExport(Ntdll, 'NtQuerySymbolicLinkObject'));
        APIs.QuerySecurity := TNtQueryObjectSecurity(WinExport(Ntdll, 'NtQuerySecurityObject'));
      end;
    end;
    A := APIs;
  finally
    NamespaceLock.Release;
  end;
end;

function NamespaceNativeAvailable: Boolean;
var A: TNamespaceAPI;
begin
  NamespaceAPI(A);
  Result := NamespaceLayoutsValid and Assigned(A.OpenDirectory) and
    Assigned(A.QueryDirectory);
end;

function NamespacePathValid(const Path: string): Boolean;
begin
  Result := False;
  if (Length(Path) = 0) or (Length(Path) >= 32760) then Exit;
  Result := (Path[1] = '\') and (Pos(#0, Path) = 0);
end;

procedure MakeAttributes(const Path: string;
  out Name: TNsUnicode; out Attr: TNsObjectAttributes);
begin
  Name := Default(TNsUnicode);
  Name.Length := Word(Length(Path) * SizeOf(WideChar));
  Name.MaximumLength := Name.Length;
  Name.Buffer := PWideChar(Path);
  Attr := Default(TNsObjectAttributes);
  Attr.Length := SizeOf(TNsObjectAttributes);
  Attr.ObjectName := @Name;
  Attr.Attributes := OBJ_CASE_INSENSITIVE;
end;

function OpenDirectory(const A: TNamespaceAPI; const Path: string;
  Rights: Cardinal; out Handle: THandle): Boolean;
var
  Name: TNsUnicode;
  Attr: TNsObjectAttributes;
begin
  Handle := 0;
  Result := False;
  if not NamespaceLayoutsValid or not NamespacePathValid(Path) or
     not Assigned(A.OpenDirectory) then Exit;
  MakeAttributes(Path, Name, Attr);
  Result := (A.OpenDirectory(Handle, Rights, @Attr) = 0) and (Handle <> 0);
  if not Result then CloseNativeProcess(Handle);
end;

function OpenLink(const A: TNamespaceAPI; const Path: string;
  out Handle: THandle): Boolean;
var
  Name: TNsUnicode;
  Attr: TNsObjectAttributes;
begin
  Handle := 0;
  Result := False;
  if not NamespaceLayoutsValid or not NamespacePathValid(Path) or
     not Assigned(A.OpenLink) then Exit;
  MakeAttributes(Path, Name, Attr);
  Result := (A.OpenLink(Handle, SYMLINK_QUERY_RIGHT, @Attr) = 0) and (Handle <> 0);
  if not Result then CloseNativeProcess(Handle);
end;

function NamespaceSizeStatus(Status: LongInt): Boolean;
begin
  Result := (Cardinal(Status) = STATUS_BUFFER_TOO_SMALL_NS) or
    (Cardinal(Status) = STATUS_BUFFER_OVERFLOW_NS) or
    (Cardinal(Status) = STATUS_LENGTH_MISMATCH_NS);
end;

function ReadLinkTarget(const A: TNamespaceAPI; const Path: string;
  out Target: string): Boolean;
var
  H: THandle;
  Data: TBytes;
  Name: TNsUnicode;
  Needed, Capacity: Cardinal;
  Status: LongInt;
  Attempt: Integer;
begin
  Target := '';
  Result := False;
  if not Assigned(A.QueryLink) then Exit;
  if not OpenLink(A, Path, H) then Exit;
  try
    Capacity := 16384;
    for Attempt := 1 to NS_QUERY_ATTEMPTS do
    begin
      SetLength(Data, Integer(Capacity));
      FillChar(Data[0], Length(Data), 0);
      Name := Default(TNsUnicode);
      Name.Buffer := PWideChar(@Data[0]);
      Name.MaximumLength := Word(Capacity);
      Needed := 0;
      Status := A.QueryLink(H, @Name, @Needed);
      if Status = 0 then
      begin
        if (Name.Buffer <> PWideChar(@Data[0])) or
           (Cardinal(Name.MaximumLength) > Capacity) or (Needed > Capacity) then Exit;
        Exit(ReadBoundedUnicode(Name, Data, Capacity, NS_MAX_LINK_BYTES, Target));
      end;
      if not NamespaceSizeStatus(Status) then Exit;
      if (Needed <= Capacity) or (Needed > NS_MAX_LINK_BYTES) or
         ((Needed and 1) <> 0) then Exit;
      Capacity := Needed;
    end;
  finally
    CloseNativeProcess(H);
  end;
end;

function EnumerateNamespace(const NativeDirectory: string;
  Entries: TNamespaceEntries): Boolean;
var
  A: TNamespaceAPI;
  H: THandle;
  Data: TBytes;
  Context, Returned, PrevContext: Cardinal;
  Status: LongInt;
  Page: Integer;
  LinkPath: string;
  Entry: TNamespaceEntry;
  Pair: TPair<string, TNamespaceEntry>;
  PageEntries: TNamespaceEntries;
  FirstPage: Boolean;
begin
  Result := False;
  if Entries = nil then Exit;
  Entries.Clear;
  NamespaceAPI(A);
  if not Assigned(A.QueryDirectory) then Exit;
  if not OpenDirectory(A, NativeDirectory, DIRECTORY_QUERY_RIGHT, H) then Exit;
  PageEntries := nil;
  try
    PageEntries := TNamespaceEntries.Create;
    SetLength(Data, NS_PAGE_BYTES);
    Context := 0;
    FirstPage := True;
    for Page := 0 to NS_MAX_PAGES - 1 do
    begin
      FillChar(Data[0], Length(Data), 0);
      Returned := 0;
      PrevContext := Context;
      Status := A.QueryDirectory(H, @Data[0], Cardinal(Length(Data)),
        0, Byte(Ord(FirstPage)), @Context, @Returned);
      FirstPage := False;
      if Cardinal(Status) = STATUS_NO_MORE_ENTRIES_NS then Exit(True);
      if (Status <> 0) and (Cardinal(Status) <> STATUS_MORE_ENTRIES_NS) then Exit;
      if not ParseNamespacePage(Data, Returned, PageEntries) then Exit;
      for Pair in PageEntries do
      begin
        if Entries.ContainsKey(Pair.Key) then Exit;
        Entry := Pair.Value;
        if SameText(Entry.TypeName, 'SymbolicLink') then
        begin
          LinkPath := NativeDirectory;
          if LinkPath[Length(LinkPath)] <> '\' then LinkPath := LinkPath + '\';
          LinkPath := LinkPath + Entry.Name;
          Entry.TargetKnown := ReadLinkTarget(A, LinkPath, Entry.Target);
        end;
        Entries.Add(Pair.Key, Entry);
        if Entries.Count > NS_MAX_ENTRIES then Exit;
      end;
      if Status = 0 then Exit(True); // success includes an empty final page
      if (PageEntries.Count = 0) or (Context = PrevContext) then Exit;
    end;
  finally
    PageEntries.Free;
    CloseNativeProcess(H);
    if not Result then Entries.Clear;
  end;
end;

function QueryNamespaceDacl(const NativeDirectory: string;
  out Signature: UInt64): Boolean;
var
  A: TNamespaceAPI;
  H: THandle;
  Data: TBytes;
  Needed, Capacity: Cardinal;
  Status: LongInt;
  Attempt: Integer;
begin
  Result := False;
  Signature := 0;
  NamespaceAPI(A);
  if not Assigned(A.QuerySecurity) then Exit;
  if not OpenDirectory(A, NativeDirectory, NS_READ_CONTROL, H) then Exit;
  try
    Needed := 0;
    Status := A.QuerySecurity(H, DACL_SECURITY_INFORMATION_NS, nil, 0, @Needed);
    if (Status <> 0) and not NamespaceSizeStatus(Status) then Exit;
    for Attempt := 1 to NS_QUERY_ATTEMPTS do
    begin
      if (Needed < 20) or (Needed > NS_MAX_DACL_BYTES) then Exit;
      Capacity := Needed;
      SetLength(Data, Integer(Capacity));
      FillChar(Data[0], Length(Data), 0);
      Status := A.QuerySecurity(H, DACL_SECURITY_INFORMATION_NS,
        @Data[0], Capacity, @Needed);
      if Status = 0 then Exit(ParseNamespaceDacl(Data, Needed, Signature));
      if not NamespaceSizeStatus(Status) or (Needed <= Capacity) then Exit;
    end;
  finally
    CloseNativeProcess(H);
  end;
end;

{$IFDEF NHW_NATIVE5_TESTS}
  {$I Cozy.NHW.Native5.Namespace.inc}
{$ENDIF}
initialization
  NamespaceLock := TCriticalSection.Create;
finalization
  NamespaceLock.Free;
end.
