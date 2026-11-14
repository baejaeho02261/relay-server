program Cozy_MeasurementCompletionProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
{$IFNDEF GAME_OWN_MEASUREMENT_TESTS}
  {$MESSAGE FATAL 'Build this isolated probe with GAME_OWN_MEASUREMENT_TESTS.'}
{$ENDIF}
{ TEST ONLY: reads its own EXE; never patches code, contacts the server or
  disposes an application image. PASS here is not an A/B/O lifecycle PASS. }
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsIntegrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIntegrity.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 System.SysUtils, System.Classes, System.JSON, Cozy.Measurement,
  Cozy.Integrity, Cozy.CodeIntegrity, Cozy.OwnMeasurement, Cozy.Api.Pointer,
  Cozy.OwnedRuntime, Cozy.ModuleInventory;
const LayerNames: array[0..8] of string = (CozyText_MeasurementCompletionProbe_ecma182_3e9aa325,CozyText_MeasurementCompletionProbe_nvme_7542e0d8,CozyText_MeasurementCompletionProbe_jones_0c441514,CozyText_MeasurementCompletionProbe_xz_ce8d22b7,
  CozyText_MeasurementCompletionProbe_we_2c4af241,CozyText_MeasurementCompletionProbe_iso_ea7511e3,CozyText_MeasurementCompletionProbe_crc32c_553f81fd,CozyText_MeasurementCompletionProbe_crc16_arc_dd1683c8,CozyText_MeasurementCompletionProbe_crc8_smbus_db1f5c02);
var Checks: Integer;
procedure Require(Value: Boolean; const Name: string);
begin
  if not Value then raise Exception.Create(Name);
  Inc(Checks);
end;
procedure Replace(Obj: TJSONObject; const Name: string; Value: TJSONValue);
var Pair: TJSONPair;
begin
  Pair := Obj.RemovePair(Name);
  Pair.Free;
  Obj.AddPair(Name, Value);
end;
procedure TestModuleGenerationRetry;
var Snapshot, Changed, Row, Threads, Signals: TJSONObject; Rows: TJSONArray;
  Before: string;
  procedure RejectRoot(const Name: string; Value: TJSONValue);
  begin
    Changed := TJSONObject(Snapshot.Clone);
    try
      Replace(Changed, Name, Value);
      Require(not ModuleInventoryGenerationRetryable(Changed), CozyText_MeasurementCompletionProbe_GENERATION_ROOT_455c2b12 + Name);
    finally FreeAndNil(Changed); end;
  end;
  procedure RejectRow(const Name: string; Value: TJSONValue);
  var ChangedRows: TJSONArray;
  begin
    Changed := TJSONObject(Snapshot.Clone);
    try
      ChangedRows := TJSONArray(Changed.GetValue(CozyText_MeasurementCompletionProbe_modules_e743ea33));
      Replace(TJSONObject(ChangedRows.Items[0]), Name, Value);
      Require(not ModuleInventoryGenerationRetryable(Changed), CozyText_MeasurementCompletionProbe_GENERATION_ROW_979ad14f + Name);
    finally FreeAndNil(Changed); end;
  end;
  procedure RejectAncillary(const Name, Field: string; Value: TJSONValue);
  begin
    Changed := TJSONObject(Snapshot.Clone);
    try
      Replace(TJSONObject(Changed.GetValue(Name)), Field, Value);
      Require(not ModuleInventoryGenerationRetryable(Changed), CozyText_MeasurementCompletionProbe_GENERATION_ANCILLARY_9c04971b + Name + '_' + Field);
    finally FreeAndNil(Changed); end;
  end;
begin
  Snapshot := TJSONObject.Create; Changed := nil;
  try
    Snapshot.AddPair(CozyText_MeasurementCompletionProbe_measurementContract_5dcdfab0, CozyText_MeasurementCompletionProbe_GAME_MEASUREMENT_PLAN_V1_c392da68);
    Snapshot.AddPair(CozyText_MeasurementCompletionProbe_measurementPlanVersion_22265676, TJSONNumber.Create(1));
    Snapshot.AddPair(CozyText_MeasurementCompletionProbe_scope_fa27400f, CozyText_MeasurementCompletionProbe_current_process_5aebe82d); Snapshot.AddPair(CozyText_MeasurementCompletionProbe_trust_79dbb2a2, CozyText_MeasurementCompletionProbe_client_reported_f1a1c3af);
    Snapshot.AddPair(CozyText_MeasurementCompletionProbe_moduleGenerationStatus_fb238a0b, CozyText_MeasurementCompletionProbe_TRACKED_CHANGED_400a2304);
    Snapshot.AddPair(CozyText_MeasurementCompletionProbe_moduleGenerationStable_e72f6525, TJSONBool.Create(False));
    Snapshot.AddPair(CozyText_MeasurementCompletionProbe_complete_c9d18e24, TJSONBool.Create(False));
    Snapshot.AddPair(CozyText_MeasurementCompletionProbe_truncated_4a459c88, TJSONBool.Create(False)); Snapshot.AddPair(CozyText_MeasurementCompletionProbe_coverage_f74393c7, CozyText_MeasurementCompletionProbe_PARTIAL_092b2957);
    Snapshot.AddPair(CozyText_MeasurementCompletionProbe_totalModules_7039501d, TJSONNumber.Create(1));
    Snapshot.AddPair(CozyText_MeasurementCompletionProbe_measuredModules_d2b31b39, TJSONNumber.Create(1));
    Rows := TJSONArray.Create; Snapshot.AddPair(CozyText_MeasurementCompletionProbe_modules_e743ea33, Rows);
    Row := TJSONObject.Create; Rows.AddElement(Row);
    Row.AddPair(CozyText_MeasurementCompletionProbe_status_c84422e6, CozyText_MeasurementCompletionProbe_UNVERIFIED_BASELINE_6e3d8d4d); Row.AddPair(CozyText_MeasurementCompletionProbe_codeStatus_67da2b77, CozyText_MeasurementCompletionProbe_MATCH_LOCAL_FILE_8f27ce07);
    Row.AddPair(CozyText_MeasurementCompletionProbe_failurePhase_c471908a, TJSONNumber.Create(0));
    Row.AddPair(CozyText_MeasurementCompletionProbe_fileSha512_a27ea87d, StringOfChar('a', 128)); Row.AddPair(CozyText_MeasurementCompletionProbe_fileCrc64_95601b7e, StringOfChar('a', 16));
    Row.AddPair(CozyText_MeasurementCompletionProbe_fileXxh3_128_1865d51f, StringOfChar('a', 32)); Row.AddPair(CozyText_MeasurementCompletionProbe_fileBlake3_e0c9d84c, StringOfChar('a', 64));
    Row.AddPair(CozyText_MeasurementCompletionProbe_codeSha512_ebab52d0, StringOfChar('b', 128)); Row.AddPair(CozyText_MeasurementCompletionProbe_codeCrc64_833a8153, StringOfChar('b', 16));
    Row.AddPair(CozyText_MeasurementCompletionProbe_codeXxh3_128_9339fc31, StringOfChar('b', 32)); Row.AddPair(CozyText_MeasurementCompletionProbe_codeBlake3_4ddf881e, StringOfChar('b', 64));
    Row.AddPair(CozyText_MeasurementCompletionProbe_exportTableStatus_5594bde2, CozyText_MeasurementCompletionProbe_NO_EXPORTS_99aa5c43); Row.AddPair(CozyText_MeasurementCompletionProbe_exportCoverage_8c9803c0, CozyText_MeasurementCompletionProbe_NO_EXPORTS_99aa5c43);
    Threads := TJSONObject.Create; Snapshot.AddPair(CozyText_MeasurementCompletionProbe_threadInventory_76bf54e6, Threads);
    Threads.AddPair(CozyText_MeasurementCompletionProbe_status_c84422e6, CozyText_MeasurementCompletionProbe_COMPLETE_a74f9c8d); Threads.AddPair(CozyText_MeasurementCompletionProbe_truncated_4a459c88, TJSONBool.Create(False));
    Threads.AddPair(CozyText_MeasurementCompletionProbe_enumerated_6caa430b, TJSONNumber.Create(2)); Threads.AddPair(CozyText_MeasurementCompletionProbe_knownImage_8c8aa9db, TJSONNumber.Create(2));
    Threads.AddPair(CozyText_MeasurementCompletionProbe_unknownStart_3a9795f3, TJSONNumber.Create(0)); Threads.AddPair(CozyText_MeasurementCompletionProbe_unreadable_becf6c04, TJSONNumber.Create(0));
    Signals := TJSONObject.Create; Snapshot.AddPair(CozyText_MeasurementCompletionProbe_deviceSignals_03ef92ad, Signals);
    Signals.AddPair(CozyText_MeasurementCompletionProbe_status_c84422e6, CozyText_MeasurementCompletionProbe_NOT_REQUESTED_3978d65d); Signals.AddPair(CozyText_MeasurementCompletionProbe_truncated_4a459c88, TJSONBool.Create(False));
    Require(not ModuleInventoryGenerationRetryable(nil), CozyText_MeasurementCompletionProbe_GENERATION_NIL_RETRY_713f8fac);
    Before := Snapshot.ToJSON;
    Require(ModuleInventoryGenerationRetryable(Snapshot), CozyText_MeasurementCompletionProbe_GENERATION_ONLY_NOT_RETRYABLE_6ed65718);
    Require(Snapshot.ToJSON = Before, CozyText_MeasurementCompletionProbe_GENERATION_RETRY_CHANGED_EVIDENCE_043d6131);
    RejectRoot(CozyText_MeasurementCompletionProbe_moduleGenerationStatus_fb238a0b, TJSONString.Create(CozyText_MeasurementCompletionProbe_TRACKED_STABLE_c289060d));
    RejectRoot(CozyText_MeasurementCompletionProbe_moduleGenerationStatus_fb238a0b, TJSONString.Create(CozyText_MeasurementCompletionProbe_TRACKING_FAILED_725d0bee));
    RejectRoot(CozyText_MeasurementCompletionProbe_moduleGenerationStable_e72f6525, TJSONBool.Create(True));
    RejectRoot(CozyText_MeasurementCompletionProbe_complete_c9d18e24, TJSONBool.Create(True)); RejectRoot(CozyText_MeasurementCompletionProbe_truncated_4a459c88, TJSONBool.Create(True));
    RejectRoot(CozyText_MeasurementCompletionProbe_measuredModules_d2b31b39, TJSONNumber.Create(0)); RejectRoot(CozyText_MeasurementCompletionProbe_totalModules_7039501d, TJSONNumber.Create(2));
    RejectRoot(CozyText_MeasurementCompletionProbe_measurementPlanVersion_22265676, TJSONString.Create('1'));
    RejectRow(CozyText_MeasurementCompletionProbe_status_c84422e6, TJSONString.Create(CozyText_MeasurementCompletionProbe_LOCAL_DIFFERENCE_69cfff3d));
    RejectRow(CozyText_MeasurementCompletionProbe_codeStatus_67da2b77, TJSONString.Create(CozyText_MeasurementCompletionProbe_LOCAL_DIFFERENCE_69cfff3d));
    RejectRow(CozyText_MeasurementCompletionProbe_codeStatus_67da2b77, TJSONString.Create(CozyText_MeasurementCompletionProbe_READ_ERROR_dadfed25));
    RejectRow(CozyText_MeasurementCompletionProbe_failurePhase_c471908a, TJSONNumber.Create(7));
    RejectRow(CozyText_MeasurementCompletionProbe_fileSha512_a27ea87d, TJSONString.Create(''));
    RejectRow(CozyText_MeasurementCompletionProbe_codeBlake3_4ddf881e, TJSONString.Create(StringOfChar('x', 64)));
    RejectRow(CozyText_MeasurementCompletionProbe_exportTableStatus_5594bde2, TJSONString.Create(CozyText_MeasurementCompletionProbe_UNSUPPORTED_EXPORT_LAYOUT_b9abc04b));
    RejectAncillary(CozyText_MeasurementCompletionProbe_threadInventory_76bf54e6, CozyText_MeasurementCompletionProbe_status_c84422e6, TJSONString.Create(CozyText_MeasurementCompletionProbe_PARTIAL_092b2957));
    RejectAncillary(CozyText_MeasurementCompletionProbe_threadInventory_76bf54e6, CozyText_MeasurementCompletionProbe_unknownStart_3a9795f3, TJSONNumber.Create(1));
    RejectAncillary(CozyText_MeasurementCompletionProbe_threadInventory_76bf54e6, CozyText_MeasurementCompletionProbe_unreadable_becf6c04, TJSONNumber.Create(1));
    RejectAncillary(CozyText_MeasurementCompletionProbe_threadInventory_76bf54e6, CozyText_MeasurementCompletionProbe_knownImage_8c8aa9db, TJSONNumber.Create(1));
    RejectAncillary(CozyText_MeasurementCompletionProbe_deviceSignals_03ef92ad, CozyText_MeasurementCompletionProbe_status_c84422e6, TJSONString.Create(CozyText_MeasurementCompletionProbe_MEASURED_f30b1b8e));
    RejectAncillary(CozyText_MeasurementCompletionProbe_deviceSignals_03ef92ad, CozyText_MeasurementCompletionProbe_status_c84422e6, TJSONString.Create(CozyText_MeasurementCompletionProbe_READ_ERROR_dadfed25));
    Replace(Row, CozyText_MeasurementCompletionProbe_exportTableStatus_5594bde2, TJSONString.Create(CozyText_MeasurementCompletionProbe_MEASURED_f30b1b8e));
    Replace(Row, CozyText_MeasurementCompletionProbe_exportCoverage_8c9803c0, TJSONString.Create(CozyText_MeasurementCompletionProbe_SECTION_HASHED_a5ee7041));
    Require(not ModuleInventoryGenerationRetryable(Snapshot), CozyText_MeasurementCompletionProbe_GENERATION_EXPORT_DIGESTS_REQUIRED_514975b9);
    Row.AddPair(CozyText_MeasurementCompletionProbe_exportTableSha512_e422d3a5, StringOfChar('c', 128)); Row.AddPair(CozyText_MeasurementCompletionProbe_exportTableCrc64_b02d8eb5, StringOfChar('c', 16));
    Row.AddPair(CozyText_MeasurementCompletionProbe_exportTableXxh3_128_805e32ff, StringOfChar('c', 32)); Row.AddPair(CozyText_MeasurementCompletionProbe_exportTableBlake3_e99f0994, StringOfChar('c', 64));
    Require(ModuleInventoryGenerationRetryable(Snapshot), CozyText_MeasurementCompletionProbe_GENERATION_MEASURED_EXPORT_RETRY_ae9475fc);
    RejectRow(CozyText_MeasurementCompletionProbe_exportTableSha512_e422d3a5, TJSONString.Create(''));
  finally Changed.Free; Snapshot.Free; end;
end;
procedure TestUnavailablePlan;
var Image: TImageDigest; Code: TCodeIntegrityMeasurement;
  Bundle, Layers: TJSONObject; Status: TMeasurementStatus;
begin
  Bundle := nil; Layers := nil;
  try
    Status := Default(TMeasurementStatus);
    Require(Status = msNotMeasured, CozyText_MeasurementCompletionProbe_DEFAULT_MUST_BE_NOT_MEASURED_6633b5a1);
    Image := Default(TImageDigest); Code := Default(TCodeIntegrityMeasurement);
    Require(not OwnMeasurementComplete(nil, Image, Code, nil, msMeasured), CozyText_MeasurementCompletionProbe_NIL_CANNOT_PASS_7d711ff8);
    Image.SHA512 := StringOfChar('a', 128); Image.Size := 123;
    Code.SHA512 := StringOfChar('b', 128); Code.Size := 123; Code.Sections := 1;
    Status := msMeasured;
    Bundle := CollectOwnMeasurement(nil, nil, TMeasurementBudget.Start(1024, 1000),
      Image, Code, Layers, Status);
    Require(Status <> msMeasured, CozyText_MeasurementCompletionProbe_UNAVAILABLE_PLAN_CANNOT_PASS_ccdc0ddd);
    Require((Image.Size = 0) and (Image.SHA512 = '') and (Code.Size = 0) and
      (Code.SHA512 = ''), CozyText_MeasurementCompletionProbe_FAILED_PLAN_MUST_CLEAR_PREVIOUS_DIGESTS_e9e28786);
    Require(not OwnMeasurementComplete(Bundle, Image, Code, Layers, Status),
      CozyText_MeasurementCompletionProbe_FAILED_BUNDLE_CANNOT_PASS_21a58651);
  finally Bundle.Free; Layers.Free; end;
end;
procedure TestLiveBundle;
var Input: TFileStream; ImagePlan: TImageIntegrity; CodePlan: TCodeIntegrity;
  Expected, Image: TImageDigest; Code: TCodeIntegrityMeasurement;
  Bundle, Layers, Changed, Role: TJSONObject; Value: TJSONValue;
  Status: TMeasurementStatus; I, J: Integer; StateName: string;
  Root, Gate, Transport, Security: TObject;
  RuntimeGraph: TCozyOwnedRuntimeGraph; Runtime: ICozyRuntimeMeasurement;
  Fault: TOwnMeasurementFault; FailedBundle, FailedLayers: TJSONObject;
  FailedImage: TImageDigest; FailedCode: TCodeIntegrityMeasurement;
  FailedStatus: TMeasurementStatus; FailedBudget: TMeasurementBudget;
  procedure RequireClearedFailure;
  var ApiGraph, OwnedGraph: TJSONObject;
  begin
    Require(FailedStatus<>msMeasured,CozyText_MeasurementCompletionProbe_SINGLE_STAGE_FAILURE_STATUS_4f7b674b);
    Require((FailedImage.Size=0) and (FailedImage.SHA512='') and (FailedImage.CRC64='') and
      (FailedImage.XXH3_128='') and (FailedImage.Blake3='') and (FailedCode.Size=0) and
      (FailedCode.SHA512='') and (FailedCode.CRC64='') and (FailedCode.XXH3_128='') and
      (FailedCode.Blake3=''),CozyText_MeasurementCompletionProbe_SINGLE_STAGE_FAILURE_CLEARS_ALL_DIGESTS_9e93eecf);
    Require(FailedLayers=nil,CozyText_MeasurementCompletionProbe_SINGLE_STAGE_FAILURE_CLEARS_CRC_LAYERS_241f84bb);
    Require(FailedBundle.GetValue(CozyText_MeasurementCompletionProbe_coverage_f74393c7).Value=CozyText_MeasurementCompletionProbe_PARTIAL_092b2957,CozyText_MeasurementCompletionProbe_SINGLE_STAGE_FAILURE_PARTIAL_7ee62257);
    ApiGraph:=TJSONObject(FailedBundle.GetValue(CozyText_MeasurementCompletionProbe_pointerGraph_9615e6f5));
    OwnedGraph:=TJSONObject(FailedBundle.GetValue(CozyText_MeasurementCompletionProbe_ownedGraph_e9d12742));
    Require((ApiGraph.GetValue(CozyText_MeasurementCompletionProbe_sha512_57d5fa13).Value='') and (ApiGraph.GetValue(CozyText_MeasurementCompletionProbe_crc64_e9b860a3).Value='') and
      (OwnedGraph.GetValue(CozyText_MeasurementCompletionProbe_sha512_57d5fa13).Value='') and (OwnedGraph.GetValue(CozyText_MeasurementCompletionProbe_crc64_e9b860a3).Value=''),
      CozyText_MeasurementCompletionProbe_SINGLE_STAGE_FAILURE_CLEARS_GRAPH_DIGESTS_e2e2fae9);
    Require((OwnedGraph.GetValue(CozyText_MeasurementCompletionProbe_before_2451f593) is TJSONNull) and
      (OwnedGraph.GetValue(CozyText_MeasurementCompletionProbe_after_daa53811) is TJSONNull),CozyText_MeasurementCompletionProbe_SINGLE_STAGE_FAILURE_CLEARS_SNAPSHOTS_4cebe1d3);
    Require(not OwnMeasurementComplete(FailedBundle,FailedImage,FailedCode,FailedLayers,FailedStatus),
      CozyText_MeasurementCompletionProbe_SINGLE_STAGE_FAILURE_NEVER_COMPLETE_8a9bef1e);
  end;
  procedure RejectVersion(NewValue: TJSONValue; const Name: string);
  var CopyLayers: TJSONObject;
  begin
    CopyLayers := TJSONObject(Layers.Clone);
    try
      Replace(CopyLayers, CozyText_MeasurementCompletionProbe_version_1c771620, NewValue);
      Require(not OwnMeasurementComplete(Bundle, Image, Code, CopyLayers, msMeasured), Name);
    finally CopyLayers.Free; end;
  end;
begin
  Input := nil; ImagePlan := nil; CodePlan := nil; Bundle := nil; Layers := nil;
  Root:=nil;Gate:=nil;Transport:=nil;Security:=nil;RuntimeGraph:=nil;Runtime:=nil;
  FailedBundle:=nil;FailedLayers:=nil;
  try
    Input := TFileStream.Create(ParamStr(0), fmOpenRead or fmShareDenyNone);
    Expected := IntegrityHashHandle(Input.Handle);
    ImagePlan := TImageIntegrity.Create(Input.Handle, Expected.SHA512, Expected.CRC64);
    CodePlan := TCodeIntegrity.Create(Input.Handle);
    Root:=TObject.Create;Gate:=TObject.Create;Transport:=TObject.Create;Security:=TObject.Create;
    RuntimeGraph:=TCozyOwnedRuntimeGraph.Create(rpLicenseApi,Root,Gate,Transport);
    RuntimeGraph.BindDependencies(Security,ImagePlan,CodePlan);
    Runtime:=RuntimeGraph.Measurement(function:TCozyRuntimeBindings
      begin Result:=CozyRuntimeBindings(Root,Gate,Transport,Security,ImagePlan,CodePlan);end);
    Status := msNotMeasured;
    Bundle := CollectOwnMeasurement(ImagePlan, CodePlan,
      TMeasurementBudget.Start(128 * 1024 * 1024, 30000), Image, Code, Layers, Status, Runtime);
    if (Status <> msMeasured) or not OwnMeasurementComplete(Bundle, Image, Code, Layers, Status) then
    begin
      Writeln(CozyText_MeasurementCompletionProbe_Live_measurement_status_b9c4d395, MeasurementStatusName(Status));
      if Bundle <> nil then Writeln(CozyText_MeasurementCompletionProbe_Own_metadata_268bb1b0, Bundle.ToJSON);
      if Layers <> nil then Writeln(CozyText_MeasurementCompletionProbe_CRC_roles_ef64e756, Layers.ToJSON);
    end;
    Require(Status = msMeasured, CozyText_MeasurementCompletionProbe_LIVE_COLLECTION_MUST_BE_MEASURED_cdc3a3be);
    Require(OwnMeasurementComplete(Bundle, Image, Code, Layers, Status),
      CozyText_MeasurementCompletionProbe_LIVE_OWN_BUNDLE_MUST_COMPLETE_63764c54);
    Value := Layers.GetValue(CozyText_MeasurementCompletionProbe_version_1c771620);
    Require((Value is TJSONString) and (Value.Value = CozyText_MeasurementCompletionProbe_CRC_LAYERS_V1_a5226458),
      CozyText_MeasurementCompletionProbe_LIVE_CRC_PRODUCER_VERSION_67e5b635);
    Value := Bundle.GetValue(CozyText_MeasurementCompletionProbe_version_1c771620);
    Require((Value is TJSONNumber) and (Value.Value = '3'), CozyText_MeasurementCompletionProbe_OUTER_VERSION_IS_NUMERIC_09ced219);
    RejectVersion(TJSONNumber.Create(1), CozyText_MeasurementCompletionProbe_CRC_NUMERIC_VERSION_MUST_FAIL_df203f2b);
    RejectVersion(TJSONString.Create('1'), CozyText_MeasurementCompletionProbe_CRC_STRING_ONE_MUST_FAIL_602bc807);
    RejectVersion(TJSONString.Create(CozyText_MeasurementCompletionProbe_CRC_LAYERS_V2_c832b479), CozyText_MeasurementCompletionProbe_CRC_UNKNOWN_VERSION_MUST_FAIL_b6803a7e);
    Require(not OwnMeasurementComplete(Bundle, Image, Code, Layers, msNotMeasured),
      CozyText_MeasurementCompletionProbe_UNEXECUTED_CHECK_MUST_NOT_REUSE_PREVIOUS_DIGEST_36e32b6e);
    for I := Low(LayerNames) to High(LayerNames) do
    begin
      for J := 0 to 2 do
      begin
        case J of
          0: StateName := CozyText_MeasurementCompletionProbe_failed_9093388a;
          1: StateName := CozyText_MeasurementCompletionProbe_partial_e06ddbdf;
        else StateName := CozyText_MeasurementCompletionProbe_unavailable_acbd1eae;
        end;
        Changed := TJSONObject(Layers.Clone);
        try
          Role := TJSONObject(Changed.GetValue(LayerNames[I]));
          Replace(Role, CozyText_MeasurementCompletionProbe_status_c84422e6, TJSONString.Create(StateName));
          Require(not OwnMeasurementComplete(Bundle, Image, Code, Changed, msMeasured),
            CozyText_MeasurementCompletionProbe_ALL_NINE_ROLE_FAILURES_MUST_FAIL_9cec2cb2 + LayerNames[I] + ':' + StateName);
        finally Changed.Free; end;
      end;
      Changed := TJSONObject(Layers.Clone);
      try
        Changed.RemovePair(LayerNames[I]).Free;
        Require(not OwnMeasurementComplete(Bundle, Image, Code, Changed, msMeasured),
          CozyText_MeasurementCompletionProbe_MISSING_ROLE_MUST_FAIL_6adfee5e + LayerNames[I]);
      finally Changed.Free; end;
    end;
    Changed := TJSONObject(Bundle.Clone);
    try
      Replace(Changed, CozyText_MeasurementCompletionProbe_version_1c771620, TJSONString.Create('1'));
      Require(not OwnMeasurementComplete(Changed, Image, Code, Layers, msMeasured),
        CozyText_MeasurementCompletionProbe_OUTER_STRING_VERSION_MUST_FAIL_664fb20d);
    finally Changed.Free; end;
    Changed := TJSONObject(Bundle.Clone);
    try
      Replace(Changed, CozyText_MeasurementCompletionProbe_coverage_f74393c7, TJSONString.Create(CozyText_MeasurementCompletionProbe_PARTIAL_092b2957));
      Require(not OwnMeasurementComplete(Changed, Image, Code, Layers, msMeasured),
        CozyText_MeasurementCompletionProbe_PARTIAL_BUNDLE_MUST_FAIL_cfd4baf9);
    finally Changed.Free; end;
    Changed := TJSONObject(Bundle.Clone);
    try
      Replace(Changed, CozyText_MeasurementCompletionProbe_imageStable_fd463291, TJSONBool.Create(False));
      Require(not OwnMeasurementComplete(Changed, Image, Code, Layers, msMeasured),
        CozyText_MeasurementCompletionProbe_UNSTABLE_BUNDLE_MUST_FAIL_a8f76511);
    finally Changed.Free; end;
    { Each real collection begins with fresh outputs and then injects exactly
      one failed stage, cancellation or deadline after successful preceding
      work. No partial CRC/API/runtime digest may remain consumable. }
    for Fault:=omfFile to omfDeadline do
    begin
      SetOwnMeasurementFault(Fault);FailedImage:=Image;FailedCode:=Code;
      try
        FailedBundle:=CollectOwnMeasurement(ImagePlan,CodePlan,
          TMeasurementBudget.Start(128*1024*1024,30000),FailedImage,FailedCode,
          FailedLayers,FailedStatus,Runtime);
        RequireClearedFailure;
      finally
        FreeAndNil(FailedBundle);FreeAndNil(FailedLayers);SetOwnMeasurementFault(omfNone);
      end;
    end;
    FailedImage:=Image;FailedCode:=Code;
    try
      FailedBundle:=CollectOwnMeasurement(ImagePlan,CodePlan,
        TMeasurementBudget.Start(128*1024*1024,30000,function:Boolean begin Result:=True;end),
        FailedImage,FailedCode,FailedLayers,FailedStatus,Runtime);
      Require(FailedStatus=msCancelled,CozyText_MeasurementCompletionProbe_REAL_PRE_CANCELLED_BUDGET_3bb7a272);RequireClearedFailure;
    finally FreeAndNil(FailedBundle);FreeAndNil(FailedLayers);end;
    FailedBudget:=TMeasurementBudget.Start(128*1024*1024,30000);
    FailedBudget.DeadlineTick:=MeasurementTick;
    FailedImage:=Image;FailedCode:=Code;
    try
      FailedBundle:=CollectOwnMeasurement(ImagePlan,CodePlan,FailedBudget,
        FailedImage,FailedCode,FailedLayers,FailedStatus,Runtime);
      Require(FailedStatus=msDeadlineExceeded,CozyText_MeasurementCompletionProbe_REAL_EXPIRED_BUDGET_811c2116);RequireClearedFailure;
    finally FreeAndNil(FailedBundle);FreeAndNil(FailedLayers);end;
    Code.SHA512 := '';
    Require(not OwnMeasurementComplete(Bundle, Image, Code, Layers, msMeasured),
      CozyText_MeasurementCompletionProbe_MISSING_DIGEST_MUST_FAIL_2ebba1ca);
  finally
    SetOwnMeasurementFault(omfNone);
    FailedBundle.Free;FailedLayers.Free;
    Runtime:=nil;
    if RuntimeGraph<>nil then RuntimeGraph.Close;
    RuntimeGraph.Free;Security.Free;Transport.Free;Gate.Free;Root.Free;
    Bundle.Free; Layers.Free; CodePlan.Free; ImagePlan.Free; Input.Free;
  end;
end;
begin
  Checks := 0;
  try
    TestUnavailablePlan;
    TestModuleGenerationRetry;
    SealApiPointerStorage;
    TestLiveBundle;
    Writeln(CozyText_MeasurementCompletionProbe_MEASUREMENT_COMPLETION_NATIVE_PROBE_PASS_14da5ba6, Checks, CozyText_MeasurementCompletionProbe_checks_8f5ae3d3);
    Writeln(CozyText_MeasurementCompletionProbe_Scope_this_probe_EXE_and_completion_predicate_no_43dbb39a);
  except
    on E: Exception do
    begin Writeln(CozyText_MeasurementCompletionProbe_MEASUREMENT_COMPLETION_NATIVE_PROBE_FAIL_2ca83647, E.Message); ExitCode := 1; end;
  end;
end.
