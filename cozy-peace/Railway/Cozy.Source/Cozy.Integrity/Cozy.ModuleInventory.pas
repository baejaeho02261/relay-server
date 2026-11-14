unit Cozy.ModuleInventory;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}

{$B-}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity,

  System.JSON, Cozy.Measurement, Cozy.Integrity, Cozy.CodeIntegrity;

type
  TModuleInventoryCancelled = reference to function: Boolean;

{ Diagnostic inventory of modules in this process only. Hashes from the local
  disk are not trusted server baselines for OS DLLs. No directory paths, raw
  process memory, other processes, or registry data are sent. The caller owns
  the result and sends byte-bounded batches per authenticated report. }
{ Process-loader notifications detect load/unload during a scan, including an
  unload/reload at the same base address. They do not attest arbitrary memory
  writes, manual mappings, or a compromised kernel. }
function ModuleLoaderGenerationStatus(out Generation: Int64): string;

{ A local retry decision, never a successful integrity result. The caller must
  discard the entire interrupted inventory and collect all hashes again. }
function ModuleInventoryGenerationRetryable(Snapshot: TJSONObject): Boolean;

function CollectModuleInventoryJSON(
  const Cancelled: TModuleInventoryCancelled = nil;
  OwnImage: TImageIntegrity = nil; OwnCode: TCodeIntegrity = nil): TJSONObject;

implementation

uses Cozy.Clock,
  Winapi.Windows, System.SysUtils, System.SyncObjs, System.Generics.Collections,
  Cozy.WinApi, Cozy.Platform.ExportResolver, Cozy.Api.ROR13, Cozy.Api.Pointer, Cozy.ThreadInventory, Cozy.DeviceSignals;

{ Private API pointers: initialized before application code starts. }
var

  ApiSlot_CloseHandle: TEncodedApiPointer;
  ApiSlot_CreateFileW: TEncodedApiPointer;
  ApiSlot_GetFileInformationByHandle: TEncodedApiPointer;
  ApiSlot_LdrRegisterDllNotification, ApiSlot_LdrUnregisterDllNotification: TEncodedApiPointer;
  LoaderGeneration: Int64;
  LoaderTrackingState: Integer; { 0 unsupported, 1 active, 2 failed, 3 stopped }
  LoaderNotificationCookie: Pointer;


const
{$I Cozy.ModuleLimits.inc}
  MaximumModules = 1024;
  MaximumScanMilliseconds: UInt64 = 30000;
  OpenReparsePointFlag: DWORD = $00200000;

type
  TResolved_ReadProcessModules = function(Process: THandle; Modules: Pointer;
  Bytes: DWORD; out Needed: DWORD; Filter: DWORD): BOOL; stdcall;
var
  ApiSlot_ReadProcessModules: TEncodedApiPointer;
type
  TResolved_ReadModuleFileName = function(Process: THandle; Module: HMODULE;
  Buffer: PWideChar; Characters: DWORD): DWORD; stdcall;
var
  ApiSlot_ReadModuleFileName: TEncodedApiPointer;

type
  TDllNotification = procedure(Reason: Cardinal; Data, Context: Pointer); stdcall;
  TLdrRegisterDllNotification = function(Flags: Cardinal;
    Callback: TDllNotification; Context: Pointer; out Cookie: Pointer): LongInt; stdcall;
  TLdrUnregisterDllNotification = function(Cookie: Pointer): LongInt; stdcall;

procedure LoaderNotification(Reason: Cardinal; Data, Context: Pointer); stdcall;
begin
  { Runs under the loader lock. Only intrinsics operating on process-lifetime
    storage are permitted here: no API resolution, locks, heap, or callbacks. }
  if (Reason = 1) or (Reason = 2) then
    if TInterlocked.Increment(LoaderGeneration) <= 0 then
      TInterlocked.Exchange(LoaderTrackingState, 2);
end;

function ModuleLoaderGenerationStatus(out Generation: Int64): string;
var State: Integer;
begin
  State := TInterlocked.CompareExchange(LoaderTrackingState, 0, 0);
  Generation := TInterlocked.CompareExchange(LoaderGeneration, Int64(0), Int64(0));
  if State = 1 then Result := CozyText_ModuleInventory_TRACKED_552bbe54
  else if State = 0 then Result := CozyText_ModuleInventory_UNSUPPORTED_f2193519
  else Result := CozyText_ModuleInventory_TRACKING_FAILED_61956fd4;
end;

procedure StartLoaderGenerationTracking;
var RegisterTarget: TLdrRegisterDllNotification; Address: Pointer;
begin
  Address := OptionalSystemProcAddressHash64(CozyText_ModuleInventory_ntdll_dll_5106167c, HASH_LdrRegisterDllNotification);
  if Address <> nil then BindApiPointer(ApiSlot_LdrRegisterDllNotification, Address);
  Address := OptionalSystemProcAddressHash64(CozyText_ModuleInventory_ntdll_dll_5106167c, HASH_LdrUnregisterDllNotification);
  if Address <> nil then BindApiPointer(ApiSlot_LdrUnregisterDllNotification, Address);
  if not ApiSlot_LdrRegisterDllNotification.IsBound or
     not ApiSlot_LdrUnregisterDllNotification.IsBound then Exit;
  RegisterTarget := TLdrRegisterDllNotification(DecodeApiPointer(ApiSlot_LdrRegisterDllNotification));
  if (RegisterTarget(0, LoaderNotification, nil, LoaderNotificationCookie) <> 0) or
     (LoaderNotificationCookie = nil) then
    TInterlocked.Exchange(LoaderTrackingState, 2)
  else
    TInterlocked.CompareExchange(LoaderTrackingState, 1, 0);
end;

procedure StopLoaderGenerationTracking;
var UnregisterTarget: TLdrUnregisterDllNotification;
begin
  TInterlocked.Exchange(LoaderTrackingState, 3);
  if LoaderNotificationCookie = nil then Exit;
  { Static callback state outlives registration. No callback refers to a scan,
    caller object, JSON value, or freed heap allocation. }
  try
    UnregisterTarget := TLdrUnregisterDllNotification(DecodeApiPointer(ApiSlot_LdrUnregisterDllNotification));
    if UnregisterTarget(LoaderNotificationCookie) = 0 then LoaderNotificationCookie := nil;
  except
    { Finalization cannot safely replace the application's shutdown exception.
      The callback touches only static process-lifetime atomic counters. }
  end;
end;

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

function ReadProcessModules(Process: THandle; Modules: Pointer;
  Bytes: DWORD; out Needed: DWORD; Filter: DWORD): BOOL; stdcall;
var
  ApiTarget: TResolved_ReadProcessModules;
begin
  ApiTarget := TResolved_ReadProcessModules(DecodeApiPointer(ApiSlot_ReadProcessModules));
  Result := ApiTarget(Process, Modules, Bytes, Needed, Filter);
end;

function ReadModuleFileName(Process: THandle; Module: HMODULE;
  Buffer: PWideChar; Characters: DWORD): DWORD; stdcall;
var
  ApiTarget: TResolved_ReadModuleFileName;
begin
  ApiTarget := TResolved_ReadModuleFileName(DecodeApiPointer(ApiSlot_ReadModuleFileName));
  Result := ApiTarget(Process, Module, Buffer, Characters);
end;
{ POINTER WRAPPERS 1 END }

function ModuleRow(Module: HMODULE; var FileRemaining, CodeRemaining: Int64;
  out Measured: Boolean; const Budget: TMeasurementBudget;
  OwnImage: TImageIntegrity; OwnCode: TCodeIntegrity): TJSONObject;
var
  PathBuffer: array[0..32767] of WideChar;
  Path, Name, Status, CodeStatus, ExportStatus: string;
  Characters: DWORD;
  FailurePhase: Integer;
  Handle: THandle;
  Info: TByHandleFileInformation;
  Size: UInt64;
  FileDigest: TImageDigest;
  Code, Expected, ExportCode, ExpectedExport: TCodeIntegrityMeasurement;
  Plan: TCodeIntegrity;
  OwnPlan, RetainedOwn: Boolean;
  Coverage: TCodeExportCoverage;
begin
  Result := TJSONObject.Create;
  Measured := False;
  FailurePhase := 1;
  Handle := INVALID_HANDLE_VALUE;
  Plan := nil;
  OwnPlan := False;
  RetainedOwn := (Module = HMODULE(HInstance)) and (OwnImage <> nil);
  Status := CozyText_ModuleInventory_READ_ERROR_c862b4fb;
  CodeStatus := CozyText_ModuleInventory_READ_ERROR_c862b4fb;
  ExportStatus := CozyText_ModuleInventory_READ_ERROR_c862b4fb;
  FillChar(PathBuffer, SizeOf(PathBuffer), 0);
  FileDigest := Default(TImageDigest);
  Code := Default(TCodeIntegrityMeasurement);
  ExportCode := Default(TCodeIntegrityMeasurement);
  Coverage := Default(TCodeExportCoverage);
  Coverage.Status := CozyText_ModuleInventory_NOT_MEASURED_2b3a0ef4;
  try
    try
      Characters := ReadModuleFileName(GetCurrentProcess, Module,
        @PathBuffer[0], Length(PathBuffer));
      if (Characters = 0) or (Characters >= DWORD(Length(PathBuffer))) then
      begin
        Name := CozyText_ModuleInventory_unknown_5f6c4ba1;
        Exit;
      end;
      SetString(Path, PWideChar(@PathBuffer[0]), Integer(Characters));
      Name := ExtractFileName(Path);
      if Length(Name) > 64 then
      begin
        { A truncated basename can collide with a registered module. Keep the
          wire bound without associating any digest with a shortened identity. }
        Name := CozyText_ModuleInventory_unknown_5f6c4ba1;
        Status := CozyText_ModuleInventory_NAME_TOO_LONG_6852f079;
        CodeStatus := CozyText_ModuleInventory_NAME_TOO_LONG_6852f079;
        Exit;
      end;
      FailurePhase := 2;
      Budget.Check(0, 0);
      if RetainedOwn then
      begin
        { B/O remove their directory entry after authorized handoff. Re-read
          the retained own-image handle within THIS snapshot, never a cached
          digest or a replacement file at the old path. }
        FileDigest := OwnImage.VerifyNow(Budget);
        Size := FileDigest.Size;
      end
      else
      begin
        Handle := CreateFileW(PWideChar(Path), GENERIC_READ,
          FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil,
          OPEN_EXISTING, OpenReparsePointFlag or FILE_FLAG_SEQUENTIAL_SCAN, 0);
        if Handle = INVALID_HANDLE_VALUE then
        begin
          Status := CozyText_ModuleInventory_FILE_UNAVAILABLE_3c618d62;
          CodeStatus := CozyText_ModuleInventory_FILE_UNAVAILABLE_3c618d62;
          Exit;
        end;
        { Windows system files commonly have multiple hard links. That does not
          turn this diagnostic disk comparison into a verified upload baseline. }
        if not GetFileInformationByHandle(Handle, Info) or
          ((Info.dwFileAttributes and (FILE_ATTRIBUTE_DIRECTORY or
            FILE_ATTRIBUTE_REPARSE_POINT)) <> 0) then Exit;
        Size := (UInt64(Info.nFileSizeHigh) shl 32) or Info.nFileSizeLow;
      end;
      FailurePhase := 3;
      if (Size > InventoryPeFileLimit) or (FileRemaining < 0) or
        (Size > UInt64(FileRemaining)) then
      begin
        Status := CozyText_ModuleInventory_SKIPPED_LIMIT_0752544a;
        CodeStatus := CozyText_ModuleInventory_SKIPPED_LIMIT_0752544a;
        Exit;
      end;
      Dec(FileRemaining, Int64(Size));
      FailurePhase := 4;
      if not RetainedOwn then FileDigest := IntegrityHashHandle(Handle, Budget);
      Status := CozyText_ModuleInventory_UNVERIFIED_BASELINE_02af056c;
      if CodeRemaining <= 0 then
      begin
        CodeStatus := CozyText_ModuleInventory_SKIPPED_LIMIT_0752544a;
        Exit;
      end;
      FailurePhase := 5;
      if RetainedOwn then Plan := OwnCode
      else
      begin
        Plan := TCodeIntegrity.Create(Handle, Module, Budget);
        OwnPlan := True;
      end;
      Expected := Plan.FileMeasurement;
      ExpectedExport := Plan.FileExportMeasurement;
      Coverage := Plan.ExportCoverage;
      FailurePhase := 6;
      if (Expected.Size > UInt64(CodeRemaining)) or
        (ExpectedExport.Size > UInt64(CodeRemaining) - Expected.Size) then
      begin
        CodeStatus := CozyText_ModuleInventory_SKIPPED_LIMIT_0752544a;
        Exit;
      end;
      Dec(CodeRemaining, Int64(Expected.Size + ExpectedExport.Size));
      ExportStatus := Plan.ExportTableStatus;
      Budget.Check(0, 0);
      FailurePhase := 7;
      Code := Plan.MeasureNow(Budget);
      Budget.Check(0, 0);
      if (Code.SHA512 = Expected.SHA512) and (Code.CRC64 = Expected.CRC64) and
        (Code.XXH3_128 = Expected.XXH3_128) and (Code.Blake3 = Expected.Blake3) then
        CodeStatus := CozyText_ModuleInventory_MATCH_LOCAL_FILE_af64ed84
      else
      begin
        Status := CozyText_ModuleInventory_LOCAL_DIFFERENCE_2980b723;
        CodeStatus := CozyText_ModuleInventory_LOCAL_DIFFERENCE_2980b723;
      end;
      FailurePhase := 8;
      if ExportStatus = CozyText_ModuleInventory_MEASURED_1a49347e then
        try
          ExportCode := Plan.MeasureExportTableNow(Budget);
          if (ExportCode.SHA512 <> ExpectedExport.SHA512) or
            (ExportCode.CRC64 <> ExpectedExport.CRC64) or
            (ExportCode.XXH3_128 <> ExpectedExport.XXH3_128) or
            (ExportCode.Blake3 <> ExpectedExport.Blake3) then Status := CozyText_ModuleInventory_LOCAL_DIFFERENCE_2980b723;
        except
          on E: Exception do
          begin
            ExportStatus := CozyText_ModuleInventory_READ_ERROR_c862b4fb;
            CodeStatus := MeasurementStatusName(MeasurementFailureStatus(E));
            ExportCode := Default(TCodeIntegrityMeasurement);
            Exit;
          end;
        end;
      if ExportStatus = CozyText_ModuleInventory_UNSUPPORTED_EXPORT_LAYOUT_0cdf2d0a then
      begin
        CodeStatus := CozyText_ModuleInventory_COVERAGE_INSUFFICIENT_939f4901;
        Exit;
      end;
      FailurePhase := 9;
      Budget.Check(0, 0);
      Measured := True;
      FailurePhase := 0;
    except
      { A DLL can be unloaded during this snapshot or contain a PE layout not
        supported by this bounded normalizer. Keep its failed row visible;
        a plan requiring FULL coverage must not count it as measured. }
      on E: EMeasurement do
      begin
        CodeStatus := MeasurementStatusName(E.Status);
        if Status <> CozyText_ModuleInventory_UNVERIFIED_BASELINE_02af056c then Status := CodeStatus;
      end;
      on E: Exception do
      begin
        CodeStatus := CozyText_ModuleInventory_READ_ERROR_c862b4fb;
        if not Measured then Status := CozyText_ModuleInventory_READ_ERROR_c862b4fb;
      end;
    end;
  finally
    if OwnPlan then Plan.Free;
    if Handle <> INVALID_HANDLE_VALUE then CloseHandle(Handle);
    FillChar(PathBuffer, SizeOf(PathBuffer), 0);
    Path := '';
    if Name = '' then Name := CozyText_ModuleInventory_unknown_5f6c4ba1;
    Result.AddPair(CozyText_ModuleInventory_name_50ddbe41, Name);
    Result.AddPair(CozyText_ModuleInventory_status_d25097bf, Status);
    Result.AddPair(CozyText_ModuleInventory_fileSha512_6b5d2917, FileDigest.SHA512);
    Result.AddPair(CozyText_ModuleInventory_fileCrc64_9fb59b8f, FileDigest.CRC64);
    Result.AddPair(CozyText_ModuleInventory_fileXxh3_128_f971a6cc, FileDigest.XXH3_128);
    Result.AddPair(CozyText_ModuleInventory_fileBlake3_dd448d16, FileDigest.Blake3);
    Result.AddPair(CozyText_ModuleInventory_codeSha512_07ecb977, Code.SHA512);
    Result.AddPair(CozyText_ModuleInventory_codeCrc64_ba2b7de2, Code.CRC64);
    Result.AddPair(CozyText_ModuleInventory_codeXxh3_128_e3f1a848, Code.XXH3_128);
    Result.AddPair(CozyText_ModuleInventory_codeBlake3_bb3258b8, Code.Blake3);
    Result.AddPair(CozyText_ModuleInventory_codeStatus_98e6d2dd, CodeStatus);
    { Numeric operation phase only: no exception message, address or path. }
    Result.AddPair(CozyText_ModuleInventory_failurePhase_b6f9311f, TJSONNumber.Create(FailurePhase));
    if (Code.SHA512 = '') and (Coverage.Status <> CozyText_ModuleInventory_INVALID_EXPORT_TABLE_600c0162) then
      Coverage.Status := CozyText_ModuleInventory_NOT_MEASURED_2b3a0ef4;
    Result.AddPair(CozyText_ModuleInventory_executableSections_1a72c5b4, TJSONNumber.Create(Coverage.ExecutableSections));
    Result.AddPair(CozyText_ModuleInventory_exportCount_42328bd4, TJSONNumber.Create(Coverage.ExportCount));
    Result.AddPair(CozyText_ModuleInventory_codeExportCount_a4d1579c, TJSONNumber.Create(Coverage.CodeExportCount));
    Result.AddPair(CozyText_ModuleInventory_forwardedExportCount_952909ba, TJSONNumber.Create(Coverage.ForwardedExportCount));
    Result.AddPair(CozyText_ModuleInventory_exportCoverage_da93ce34, Coverage.Status);
    if (ExportStatus = CozyText_ModuleInventory_MEASURED_1a49347e) and (ExportCode.SHA512 = '') then
      ExportStatus := CozyText_ModuleInventory_READ_ERROR_c862b4fb;
    Result.AddPair(CozyText_ModuleInventory_exportTableSha512_90160130, ExportCode.SHA512);
    Result.AddPair(CozyText_ModuleInventory_exportTableCrc64_62099a5e, ExportCode.CRC64);
    Result.AddPair(CozyText_ModuleInventory_exportTableXxh3_128_794781ff, ExportCode.XXH3_128);
    Result.AddPair(CozyText_ModuleInventory_exportTableBlake3_bb1b5f3a, ExportCode.Blake3);
    Result.AddPair(CozyText_ModuleInventory_exportTableStatus_a2a69dc6, ExportStatus);
  end;
end;

function ModuleInventoryGenerationRetryable(Snapshot: TJSONObject): Boolean;
var Rows: TJSONArray; Threads, Signals, Row: TJSONObject; Value: TJSONValue;
  Total, Measured, Enumerated, Known, PhaseValue: Int64; I, TransientPaths: Integer;
  function TextIs(Obj: TJSONObject; const Name, Expected: string): Boolean;
  var Item: TJSONValue;
  begin
    Result := False;
    if Obj = nil then Exit;
    Item := Obj.GetValue(Name);
    Result := (Item is TJSONString) and (Item.Value = Expected);
  end;
  function BooleanIs(Obj: TJSONObject; const Name: string; Expected: Boolean): Boolean;
  var Item: TJSONValue;
  begin
    Result := False;
    if Obj = nil then Exit;
    Item := Obj.GetValue(Name);
    Result := (Item is TJSONBool) and (TJSONBool(Item).AsBoolean = Expected);
  end;
  function Number(Obj: TJSONObject; const Name: string; out NumberValue: Int64): Boolean;
  var Item: TJSONValue;
  begin
    Result := False; NumberValue := -1;
    if Obj = nil then Exit;
    Item := Obj.GetValue(Name);
    Result := (Item is TJSONNumber) and TryStrToInt64(Item.Value, NumberValue);
  end;
  function Zero(Obj: TJSONObject; const Name: string): Boolean;
  var NumberValue: Int64;
  begin Result := Number(Obj, Name, NumberValue) and (NumberValue = 0); end;
  function Digest(Obj: TJSONObject; const Name: string; Size: Integer): Boolean;
  var Item: TJSONValue; Text: string; At: Integer;
  begin
    Result := False; Item := Obj.GetValue(Name);
    if not (Item is TJSONString) then Exit;
    Text := Item.Value;
    if Length(Text) <> Size then Exit;
    for At := 1 to Length(Text) do
      if not CharInSet(Text[At], ['0'..'9','a'..'f','A'..'F']) then Exit;
    Result := True;
  end;
begin
  Result := False;
  if Snapshot = nil then Exit;
  if not TextIs(Snapshot, CozyText_ModuleInventory_measurementContract_3eab37ce, CozyText_ModuleInventory_GAME_MEASUREMENT_PLAN_V1_72801708) or
    not Number(Snapshot, CozyText_ModuleInventory_measurementPlanVersion_9085b6cf, Total) or (Total <> 1) or
    not TextIs(Snapshot, CozyText_ModuleInventory_moduleGenerationStatus_92ddf7ac, CozyText_ModuleInventory_TRACKED_CHANGED_6fbd302a) or
    not BooleanIs(Snapshot, CozyText_ModuleInventory_moduleGenerationStable_925125cf, False) or
    not BooleanIs(Snapshot, CozyText_ModuleInventory_complete_985dd049, False) or
    not BooleanIs(Snapshot, CozyText_ModuleInventory_truncated_7f23de4a, False) or
    not TextIs(Snapshot, CozyText_ModuleInventory_coverage_04f1cb48, CozyText_ModuleInventory_PARTIAL_0cd0d37b) or
    not TextIs(Snapshot, CozyText_ModuleInventory_scope_e5371a0e, CozyText_ModuleInventory_current_process_a83d0cb6) or
    not TextIs(Snapshot, CozyText_ModuleInventory_trust_5f9f8596, CozyText_ModuleInventory_client_reported_e36d453e) then Exit;
  Value := Snapshot.GetValue(CozyText_ModuleInventory_modules_c2359475);
  if not (Value is TJSONArray) then Exit;
  Rows := TJSONArray(Value);
  if not Number(Snapshot, CozyText_ModuleInventory_totalModules_9aee4fca, Total) or
    not Number(Snapshot, CozyText_ModuleInventory_measuredModules_82b9f090, Measured) or
    (Total < 1) or (Total > MaximumModules) or (Total <> Rows.Count) or
    (Measured < 0) or (Measured > Total) then Exit;
  TransientPaths := 0;
  Value := Snapshot.GetValue(CozyText_ModuleInventory_threadInventory_cdc87d69);
  if not (Value is TJSONObject) then Exit;
  Threads := TJSONObject(Value);
  if not TextIs(Threads, CozyText_ModuleInventory_status_d25097bf, CozyText_ModuleInventory_COMPLETE_cd2ce3ad) or
    not BooleanIs(Threads, CozyText_ModuleInventory_truncated_7f23de4a, False) or
    not Zero(Threads, CozyText_ModuleInventory_unknownStart_3d9100bf) or not Zero(Threads, CozyText_ModuleInventory_unreadable_ae1daed5) or
    not Number(Threads, CozyText_ModuleInventory_enumerated_cbddf6e0, Enumerated) or
    not Number(Threads, CozyText_ModuleInventory_knownImage_9a430ec8, Known) or
    (Enumerated < 1) or (Known <> Enumerated) then Exit;
  Value := Snapshot.GetValue(CozyText_ModuleInventory_deviceSignals_e28c93d0);
  if not (Value is TJSONObject) then Exit;
  Signals := TJSONObject(Value);
  { Requested device observations are one-shot; never discard that response.
    Other ancillary failures likewise remain visible to the server. }
  if not TextIs(Signals, CozyText_ModuleInventory_status_d25097bf, CozyText_ModuleInventory_NOT_REQUESTED_ca3404cf) or
    not BooleanIs(Signals, CozyText_ModuleInventory_truncated_7f23de4a, False) then Exit;
  for I := 0 to Rows.Count - 1 do
  begin
    if not (Rows.Items[I] is TJSONObject) then Exit;
    Row := TJSONObject(Rows.Items[I]);
    { A DLL unloaded while the loader generation changed may yield an
      unreadable MODULE_PATH row. This is not trusted or counted as measured.
      Permit only a full *discard and re-collect*, with the caller's bounded
      retry count; never accept failed file/code/export evidence. }
    if TextIs(Row, CozyText_ModuleInventory_name_50ddbe41, CozyText_ModuleInventory_unknown_5f6c4ba1) and
      TextIs(Row, CozyText_ModuleInventory_status_d25097bf, CozyText_ModuleInventory_READ_ERROR_c862b4fb) and
      TextIs(Row, CozyText_ModuleInventory_codeStatus_98e6d2dd, CozyText_ModuleInventory_READ_ERROR_c862b4fb) and
      TextIs(Row, CozyText_ModuleInventory_exportTableStatus_a2a69dc6, CozyText_ModuleInventory_READ_ERROR_c862b4fb) and
      Number(Row, CozyText_ModuleInventory_failurePhase_b6f9311f, PhaseValue) and (PhaseValue = 1) and
      TextIs(Row, CozyText_ModuleInventory_fileSha512_6b5d2917, '') and
      TextIs(Row, CozyText_ModuleInventory_codeSha512_07ecb977, '') and
      TextIs(Row, CozyText_ModuleInventory_exportTableSha512_90160130, '') then
    begin
      Inc(TransientPaths);
      Continue;
    end;
    { Measured=true alone includes LOCAL_DIFFERENCE. Those findings are never
      hidden by a fresh scan, nor are unreadable/unsupported module rows. }
    if not TextIs(Row, CozyText_ModuleInventory_status_d25097bf, CozyText_ModuleInventory_UNVERIFIED_BASELINE_02af056c) or
      not TextIs(Row, CozyText_ModuleInventory_codeStatus_98e6d2dd, CozyText_ModuleInventory_MATCH_LOCAL_FILE_af64ed84) or
      not Zero(Row, CozyText_ModuleInventory_failurePhase_b6f9311f) or
      not Digest(Row, CozyText_ModuleInventory_fileSha512_6b5d2917, 128) or not Digest(Row, CozyText_ModuleInventory_fileCrc64_9fb59b8f, 16) or
      not Digest(Row, CozyText_ModuleInventory_fileXxh3_128_f971a6cc, 32) or not Digest(Row, CozyText_ModuleInventory_fileBlake3_dd448d16, 64) or
      not Digest(Row, CozyText_ModuleInventory_codeSha512_07ecb977, 128) or not Digest(Row, CozyText_ModuleInventory_codeCrc64_ba2b7de2, 16) or
      not Digest(Row, CozyText_ModuleInventory_codeXxh3_128_e3f1a848, 32) or not Digest(Row, CozyText_ModuleInventory_codeBlake3_bb3258b8, 64) then Exit;
    if TextIs(Row, CozyText_ModuleInventory_exportTableStatus_a2a69dc6, CozyText_ModuleInventory_MEASURED_1a49347e) then
    begin
      if not TextIs(Row, CozyText_ModuleInventory_exportCoverage_da93ce34, CozyText_ModuleInventory_SECTION_HASHED_bf7117ca) or
        not Digest(Row, CozyText_ModuleInventory_exportTableSha512_90160130, 128) or
        not Digest(Row, CozyText_ModuleInventory_exportTableCrc64_62099a5e, 16) or
        not Digest(Row, CozyText_ModuleInventory_exportTableXxh3_128_794781ff, 32) or
        not Digest(Row, CozyText_ModuleInventory_exportTableBlake3_bb1b5f3a, 64) then Exit;
    end
    else if not TextIs(Row, CozyText_ModuleInventory_exportTableStatus_a2a69dc6, CozyText_ModuleInventory_NO_EXPORTS_0c749502) or
      not TextIs(Row, CozyText_ModuleInventory_exportCoverage_da93ce34, CozyText_ModuleInventory_NO_EXPORTS_0c749502) then Exit;
  end;
  { Every non-measured row must be exactly the transient path-only failure.
    File and code differences, untrusted exports, path budget errors and
    unsupported layouts all make this classifier FALSE. }
  Result := (TransientPaths = Total - Measured);
end;

function CollectModuleInventoryJSON(
  const Cancelled: TModuleInventoryCancelled;
  OwnImage: TImageIntegrity; OwnCode: TCodeIntegrity): TJSONObject;
var
  Modules: array[0..MaximumModules - 1] of HMODULE;
  Needed: DWORD;
  Started, Finished: UInt64;
  StartGeneration, EndGeneration: Int64;
  StartTracking, EndTracking, GenerationStatus: string;
  Total, Count, I, MeasuredCount: Integer;
  Complete, Measured, Truncated: Boolean;
  FileRemaining, CodeRemaining: Int64;
  Rows: TJSONArray;
  Row: TJSONObject;
  Budget: TMeasurementBudget;
  EndModules: array[0..MaximumModules - 1] of HMODULE;
  EndNeeded: DWORD;
  GenerationStable: Boolean;
begin
  if (OwnImage <> nil) and ((OwnCode = nil) or not OwnCode.IsOwnImage) then
    raise EArgumentException.Create(CozyText_ModuleInventory_A_retained_own_image_requires_its_own_code_plan_2d780d77);
  Result := TJSONObject.Create;
  Rows := TJSONArray.Create;
  try
    Result.AddPair(CozyText_ModuleInventory_version_79567f17, TJSONNumber.Create(1));
    Result.AddPair(CozyText_ModuleInventory_scope_e5371a0e, CozyText_ModuleInventory_current_process_a83d0cb6);
    Result.AddPair(CozyText_ModuleInventory_trust_5f9f8596, CozyText_ModuleInventory_client_reported_e36d453e);
    Result.AddPair(CozyText_ModuleInventory_modules_c2359475, Rows);
    Rows := Result.GetValue<TJSONArray>(CozyText_ModuleInventory_modules_c2359475);
    FillChar(Modules, SizeOf(Modules), 0);
    Needed := 0;
    Started := CozyTick;
    Budget := TMeasurementBudget.Start(InventoryPeFileLimit, Cardinal(MaximumScanMilliseconds),
      function: Boolean begin Result := Assigned(Cancelled) and Cancelled(); end);
    Result.AddPair(CozyText_ModuleInventory_threadInventory_cdc87d69, CollectThreadInventoryJSON(Budget));
    Result.AddPair(CozyText_ModuleInventory_deviceSignals_e28c93d0, CollectDeviceSignalsJSON(Budget));
    StartTracking := ModuleLoaderGenerationStatus(StartGeneration);
    Complete := ReadProcessModules(GetCurrentProcess, @Modules[0],
      SizeOf(Modules), Needed, 3);
    Complete := Complete and (Needed > 0) and ((Needed mod SizeOf(HMODULE)) = 0);
    Total := Integer(Needed div SizeOf(HMODULE));
    if Total > 65535 then Total := 65535;
    Count := Total;
    if Count > MaximumModules then Count := MaximumModules;
    if not Complete then Count := 0;
    Truncated := Count < Total;
    MeasuredCount := 0;
    FileRemaining := InventoryFileBudget;
    CodeRemaining := InventoryCodeBudget;
    for I := 0 to Count - 1 do
    begin
      { The same absolute budget reaches each overlapped file read and PE plan.
        Cancellation retains only pending I/O resources, never a caller buffer. }
      if ((Assigned(Cancelled)) and Cancelled()) or
        (CozyTick - Started >= MaximumScanMilliseconds) then
      begin
        Truncated := True;
        Break;
      end;
      Row := ModuleRow(Modules[I], FileRemaining, CodeRemaining,
        Measured, Budget, OwnImage, OwnCode);
      Rows.AddElement(Row);
      if Measured then Inc(MeasuredCount);
    end;
    { Completeness describes enumeration; coverage also requires every file/code
      row to be measured. The optional retained own-image pair keeps authorized
      unlinking from forcing a false FILE_UNAVAILABLE row. Actual read errors
      remain visible, never counted as success, and keep coverage PARTIAL. }
    Truncated := Truncated or (Rows.Count < Total);
    FillChar(EndModules, SizeOf(EndModules), 0); EndNeeded := 0;
    GenerationStable := ReadProcessModules(GetCurrentProcess, @EndModules[0],
      SizeOf(EndModules), EndNeeded, 3) and (EndNeeded = Needed) and
      (EndNeeded <= SizeOf(EndModules)) and (EndNeeded > 0) and
      ((EndNeeded mod SizeOf(HMODULE)) = 0);
    if GenerationStable then
      for I := 0 to Count - 1 do
        if Modules[I] <> EndModules[I] then GenerationStable := False;
    EndTracking := ModuleLoaderGenerationStatus(EndGeneration);
    if (StartTracking <> CozyText_ModuleInventory_TRACKED_552bbe54) or (EndTracking <> CozyText_ModuleInventory_TRACKED_552bbe54) then
    begin
      GenerationStable := False;
      if (StartTracking = CozyText_ModuleInventory_UNSUPPORTED_f2193519) and (EndTracking = CozyText_ModuleInventory_UNSUPPORTED_f2193519) then
        GenerationStatus := CozyText_ModuleInventory_UNSUPPORTED_f2193519
      else GenerationStatus := CozyText_ModuleInventory_TRACKING_FAILED_61956fd4;
    end
    else
    begin
      GenerationStable := GenerationStable and (StartGeneration = EndGeneration);
      if GenerationStable then GenerationStatus := CozyText_ModuleInventory_TRACKED_STABLE_fc1e4b31
      else GenerationStatus := CozyText_ModuleInventory_TRACKED_CHANGED_6fbd302a;
    end;
    Finished := CozyTick;
    if (Finished - Started >= MaximumScanMilliseconds) or
       (Assigned(Cancelled) and Cancelled()) then Truncated := True;
    Complete := Complete and not Truncated and GenerationStable;
    { Full coverage requires both matching enumerations and an unchanged loader
      generation across the scan. Unsupported notifications are explicit PARTIAL.
      This is a loader-observed snapshot, not an atomic memory/OS attestation. }
    Result.AddPair(CozyText_ModuleInventory_measurementContract_3eab37ce, CozyText_ModuleInventory_GAME_MEASUREMENT_PLAN_V1_72801708);
    Result.AddPair(CozyText_ModuleInventory_measurementPlanVersion_9085b6cf, TJSONNumber.Create(1));
    Result.AddPair(CozyText_ModuleInventory_measurementStartedTick_b816a1e9, TJSONNumber.Create(Int64(Started)));
    Result.AddPair(CozyText_ModuleInventory_measurementFinishedTick_56bfd885, TJSONNumber.Create(Int64(Finished)));
    Result.AddPair(CozyText_ModuleInventory_moduleGenerationStable_925125cf, TJSONBool.Create(GenerationStable));
    Result.AddPair(CozyText_ModuleInventory_moduleGenerationStatus_92ddf7ac, GenerationStatus);
    if Complete and (MeasuredCount = Total) then Result.AddPair(CozyText_ModuleInventory_coverage_04f1cb48, CozyText_ModuleInventory_FULL_5d779297)
    else Result.AddPair(CozyText_ModuleInventory_coverage_04f1cb48, CozyText_ModuleInventory_PARTIAL_0cd0d37b);
    Result.AddPair(CozyText_ModuleInventory_complete_985dd049, TJSONBool.Create(Complete));
    Result.AddPair(CozyText_ModuleInventory_truncated_7f23de4a, TJSONBool.Create(Truncated));
    Result.AddPair(CozyText_ModuleInventory_totalModules_9aee4fca, TJSONNumber.Create(Total));
    Result.AddPair(CozyText_ModuleInventory_measuredModules_82b9f090, TJSONNumber.Create(MeasuredCount));
  except
    Result.Free;
    raise;
  end;
end;

initialization
  { API binding only; original startup actions follow unchanged. }

  BindApiPointer(ApiSlot_CloseHandle, RequireProcAddressHash64(CozyText_ModuleInventory_kernel32_dll_06e0bdbd, HASH_CloseHandle));
  BindApiPointer(ApiSlot_CreateFileW, RequireProcAddressHash64(CozyText_ModuleInventory_kernel32_dll_06e0bdbd, HASH_CreateFileW));
  BindApiPointer(ApiSlot_GetFileInformationByHandle, RequireProcAddressHash64(CozyText_ModuleInventory_kernel32_dll_06e0bdbd, HASH_GetFileInformationByHandle));
  BindApiPointer(ApiSlot_ReadProcessModules, RequireProcAddressHash64(CozyText_ModuleInventory_psapi_dll_76600a08, HASH_EnumProcessModulesEx));
  BindApiPointer(ApiSlot_ReadModuleFileName, RequireProcAddressHash64(CozyText_ModuleInventory_psapi_dll_76600a08, HASH_GetModuleFileNameExW));
  StartLoaderGenerationTracking;
finalization
  StopLoaderGenerationTracking;
end.
