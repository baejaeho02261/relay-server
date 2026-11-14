unit Cozy.OwnMeasurement;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity,
 System.SysUtils, System.JSON, Cozy.Measurement, Cozy.Integrity, Cozy.CodeIntegrity, Cozy.OwnedRuntime;
const OwnMeasurementContract = CozyText_OwnMeasurement_GAME_OWN_MEASUREMENT_BUNDLE_V3_6bcba2dc;
function CollectOwnMeasurement(Image: TImageIntegrity; Code: TCodeIntegrity;
  const Budget: TMeasurementBudget; out ImageDigest: TImageDigest;
  out CodeDigest: TCodeIntegrityMeasurement; out CrcLayers: TJSONObject;
  out Status: TMeasurementStatus; const Runtime: ICozyRuntimeMeasurement = nil): TJSONObject;
{ Completion is checked again at each caller before hashes become evidence.
  No persistent client state or reusable success cache is created. }
function OwnMeasurementComplete(Bundle: TJSONObject; const ImageDigest: TImageDigest;
  const CodeDigest: TCodeIntegrityMeasurement; CrcLayers: TJSONObject;
  Status: TMeasurementStatus): Boolean;
{$IFDEF GAME_OWN_MEASUREMENT_TESTS}
type TOwnMeasurementFault = (omfNone, omfFile, omfCode, omfCrc, omfApiGraph,
  omfRuntimeGraph, omfCancelled, omfDeadline);
procedure SetOwnMeasurementFault(Value: TOwnMeasurementFault);
{$ENDIF}
implementation
uses Cozy.Api.Pointer, Cozy.PointerGraph, Cozy.Hashes, Cozy.CrcLayers;
{$IFDEF GAME_OWN_MEASUREMENT_TESTS}
var OwnMeasurementFault: TOwnMeasurementFault;
procedure SetOwnMeasurementFault(Value: TOwnMeasurementFault);
begin OwnMeasurementFault := Value; end;
procedure InjectFault(Value: TOwnMeasurementFault);
begin
  if OwnMeasurementFault <> Value then Exit;
  case Value of
    omfCancelled: raise EMeasurement.Create(msCancelled,CozyText_OwnMeasurement_PROBE_CANCELLED_09660605);
    omfDeadline: raise EMeasurement.Create(msDeadlineExceeded,CozyText_OwnMeasurement_PROBE_DEADLINE_5eda51ed);
  else raise EMeasurement.Create(msReadError,CozyText_OwnMeasurement_PROBE_SINGLE_STAGE_FAILURE_af78c43d);end;
end;
{$ENDIF}
function HexDigest(const Value: string; Expected: Integer): Boolean;
var I: Integer;
begin
  Result := False;
  if Length(Value) <> Expected then Exit;
  for I := 1 to Length(Value) do
    if not CharInSet(Value[I], ['0'..'9', 'a'..'f', 'A'..'F']) then Exit;
  Result := True;
end;
function PointerGraphComplete(Value: TJSONValue): Boolean;
var Graph: TJSONObject; Slots, Nodes, Edges, Depth: UInt64; Item: TJSONValue;
  function Number(const Name: string; out N: UInt64): Boolean;
  var V: TJSONValue;
  begin V:=Graph.GetValue(Name);Result:=(V is TJSONNumber) and TryStrToUInt64(V.Value,N);end;
  function Text(const Name, Expected: string): Boolean;
  var V: TJSONValue;
  begin V:=Graph.GetValue(Name);Result:=(V is TJSONString) and (V.Value=Expected);end;
begin
  Result:=False;if not (Value is TJSONObject) then Exit;Graph:=TJSONObject(Value);
  if Graph.Count<>9 then Exit;
  Item:=Graph.GetValue(CozyText_OwnMeasurement_version_b04eb4ac);if not (Item is TJSONNumber) or (Item.Value<>'1') then Exit;
  if not Text(CozyText_OwnMeasurement_scope_718bb03a,CozyText_OwnMeasurement_SEALED_API_ARENA_62c2dab0) or not Text(CozyText_OwnMeasurement_status_64397a20,CozyText_OwnMeasurement_MEASURED_498762dc) then Exit;
  if not Number(CozyText_OwnMeasurement_slots_26025179,Slots) or (Slots<1) or (Slots>1024) or
    not Number(CozyText_OwnMeasurement_nodes_0715a5cc,Nodes) or (Nodes<>1+3*Slots) or
    not Number(CozyText_OwnMeasurement_edges_5b917cde,Edges) or (Edges<>3*Slots) or
    not Number(CozyText_OwnMeasurement_depth_e07a027f,Depth) or (Depth<>3) then Exit;
  Item:=Graph.GetValue(CozyText_OwnMeasurement_sha512_ae79a37a);if not (Item is TJSONString) or not HexDigest(Item.Value,128) then Exit;
  Item:=Graph.GetValue(CozyText_OwnMeasurement_crc64_622fa901);if not (Item is TJSONString) or not HexDigest(Item.Value,16) then Exit;
  Result:=True;
end;
function DigestsComplete(const Image: TImageDigest;
  const Code: TCodeIntegrityMeasurement): Boolean;
begin
  Result := (Image.Size > 0) and (Code.Size > 0) and (Code.Sections > 0) and
    HexDigest(Image.SHA512, 128) and HexDigest(Image.CRC64, 16) and
    HexDigest(Image.XXH3_128, 32) and HexDigest(Image.Blake3, 64) and
    HexDigest(Code.SHA512, 128) and HexDigest(Code.CRC64, 16) and
    HexDigest(Code.XXH3_128, 32) and HexDigest(Code.Blake3, 64);
end;
function AllRolesMeasured(Layers: TJSONObject): Boolean;
const Roles: array[0..8] of string = (CozyText_OwnMeasurement_ecma182_d7f23211, CozyText_OwnMeasurement_nvme_4d80cc7d, CozyText_OwnMeasurement_jones_a8b04243, CozyText_OwnMeasurement_xz_ee026359,
  CozyText_OwnMeasurement_we_9040cded, CozyText_OwnMeasurement_iso_5ea13593, CozyText_OwnMeasurement_crc32c_504d1764, CozyText_OwnMeasurement_crc16_arc_8f15b90c, CozyText_OwnMeasurement_crc8_smbus_3b494097);
var I: Integer; Role, Value: TJSONValue;
begin
  Result := False;
  if (Layers = nil) or (Layers.Count <> 10) then Exit;
  Value := Layers.GetValue(CozyText_OwnMeasurement_version_b04eb4ac);
  { CRC-LAYERS-V1 is a string wire contract emitted by MeasureCrcLayersCore.
    The outer own-measurement bundle has a separate numeric version (1). }
  if not (Value is TJSONString) or (Value.Value <> CozyText_OwnMeasurement_CRC_LAYERS_V1_9529f83c) then Exit;
  for I := Low(Roles) to High(Roles) do
  begin
    Role := Layers.GetValue(Roles[I]);
    if not (Role is TJSONObject) then Exit;
    Value := TJSONObject(Role).GetValue(CozyText_OwnMeasurement_status_64397a20);
    if not (Value is TJSONString) or (Value.Value <> CozyText_OwnMeasurement_measured_854d8100) then Exit;
  end;
  Result := True;
end;
function OwnMeasurementComplete(Bundle: TJSONObject; const ImageDigest: TImageDigest;
  const CodeDigest: TCodeIntegrityMeasurement; CrcLayers: TJSONObject;
  Status: TMeasurementStatus): Boolean;
var Value: TJSONValue; Started, Finished: UInt64;
  function IsText(const Name, Expected: string): Boolean;
  var Item: TJSONValue;
  begin
    Item := Bundle.GetValue(Name);
    Result := (Item is TJSONString) and (Item.Value = Expected);
  end;
begin
  Result := False;
  if (Status <> msMeasured) or (Bundle = nil) then Exit;
  if (Bundle.Count <> 11) or not DigestsComplete(ImageDigest, CodeDigest) or
    not AllRolesMeasured(CrcLayers) then Exit;
  if not IsText(CozyText_OwnMeasurement_contract_d06c9067, OwnMeasurementContract) or not IsText(CozyText_OwnMeasurement_coverage_59fbaaf0, CozyText_OwnMeasurement_FULL_3998f2bd) or
    not IsText(CozyText_OwnMeasurement_fileStatus_135b5cb8, CozyText_OwnMeasurement_MEASURED_498762dc) or not IsText(CozyText_OwnMeasurement_codeStatus_28e08f2b, CozyText_OwnMeasurement_MEASURED_498762dc) or
    not IsText(CozyText_OwnMeasurement_crcStatus_e1381e51, CozyText_OwnMeasurement_MEASURED_498762dc) then Exit;
  Value := Bundle.GetValue(CozyText_OwnMeasurement_version_b04eb4ac);
  if not (Value is TJSONNumber) or (Value.Value <> '3') then Exit;
  if not PointerGraphComplete(Bundle.GetValue(CozyText_OwnMeasurement_pointerGraph_6a10a954)) or
    not OwnedRuntimeComplete(Bundle.GetValue(CozyText_OwnMeasurement_ownedGraph_450e3856)) then Exit;
  Value := Bundle.GetValue(CozyText_OwnMeasurement_imageStable_923d6097);
  if not (Value is TJSONBool) or (Value.Value <> CozyText_OwnMeasurement_true_087005a7) then Exit;
  Value := Bundle.GetValue(CozyText_OwnMeasurement_startedTick_1ed15b2e);
  if not (Value is TJSONNumber) then Exit;
  if not TryStrToUInt64(Value.Value, Started) then Exit;
  Value := Bundle.GetValue(CozyText_OwnMeasurement_finishedTick_22d741e0);
  if not (Value is TJSONNumber) then Exit;
  if not TryStrToUInt64(Value.Value, Finished) then Exit;
  if Finished < Started then Exit;
  if Finished - Started > 60000 then Exit;
  Result := True;
end;
function CollectOwnMeasurement(Image: TImageIntegrity; Code: TCodeIntegrity;
  const Budget: TMeasurementBudget; out ImageDigest: TImageDigest;
  out CodeDigest: TCodeIntegrityMeasurement; out CrcLayers: TJSONObject;
  out Status: TMeasurementStatus; const Runtime: ICozyRuntimeMeasurement): TJSONObject;
var Started: UInt64; AfterImage: TImageDigest;
  FileStatus, CodeStatus, CrcStatus, Coverage, RuntimeReason, RuntimeProfile: string;
  Stable: Boolean; Scope: Integer;
  GraphBefore, GraphAfter: TBytes; Graph, RuntimeGraph: TJSONObject;
  SlotsBefore, SlotsAfter, DepthBefore, DepthAfter: Cardinal;
  GraphMeasured: Boolean; RuntimeBefore, RuntimeAfter: TCozyPointerSnapshot;
begin
  Status := msNotMeasured;
  ImageDigest := Default(TImageDigest); CodeDigest := Default(TCodeIntegrityMeasurement);
  CrcLayers := nil; AfterImage := Default(TImageDigest);
  Started := MeasurementTick; Stable := False; GraphMeasured := False;
  GraphBefore := nil; GraphAfter := nil; SlotsBefore := 0; DepthBefore := 0;
  RuntimeGraph := nil; RuntimeReason := CozyText_OwnMeasurement_MEASUREMENT_FAILED_a72ffdd2; RuntimeProfile := CozyText_OwnMeasurement_UNAVAILABLE_766d9476;
  RuntimeBefore := Default(TCozyPointerSnapshot); RuntimeAfter := Default(TCozyPointerSnapshot);
  FileStatus := CozyText_OwnMeasurement_NOT_MEASURED_aa20b28c; CodeStatus := CozyText_OwnMeasurement_NOT_MEASURED_aa20b28c; CrcStatus := CozyText_OwnMeasurement_NOT_MEASURED_aa20b28c;
  Scope := 0;
  try
    try
    try
      Budget.Check(0, 0);
      if (Image = nil) or (Code = nil) or not Code.IsOwnImage then
        raise EMeasurement.Create(msReadError, CozyText_OwnMeasurement_OWN_MEASUREMENT_PLAN_REQUIRED_b76d308f);
      if Runtime = nil then raise ECozyRuntimeGraph.Create(CozyText_OwnMeasurement_RUNTIME_GRAPH_REQUIRED_585593ac);
      RuntimeProfile := Runtime.Profile;
      RuntimeBefore := Runtime.Capture;
      GraphBefore := CaptureApiPointerGraph(SlotsBefore, DepthBefore);
      Budget.Check(0, 0);
      ImageDigest := Image.VerifyNow(Budget); FileStatus := CozyText_OwnMeasurement_MEASURED_498762dc;
      {$IFDEF GAME_OWN_MEASUREMENT_TESTS}InjectFault(omfFile);{$ENDIF}
      Scope := 1;
      Code.MeasureBundle(CodeDigest, CrcLayers, Budget);
      {$IFDEF GAME_OWN_MEASUREMENT_TESTS}InjectFault(omfCode);{$ENDIF}
      if not DigestsComplete(ImageDigest, CodeDigest) then
        raise EMeasurement.Create(msCoverageInsufficient, CozyText_OwnMeasurement_OWN_MEASUREMENT_DIGEST_INCOMPLETE_7e282f88);
      CodeStatus := CozyText_OwnMeasurement_MEASURED_498762dc; Scope := 2;
      if AllRolesMeasured(CrcLayers) then CrcStatus := CozyText_OwnMeasurement_MEASURED_498762dc
      else raise EMeasurement.Create(msCoverageInsufficient, CozyText_OwnMeasurement_OWN_CRC_LAYERS_INCOMPLETE_d5ae6553);
      {$IFDEF GAME_OWN_MEASUREMENT_TESTS}InjectFault(omfCrc);{$ENDIF}
      Scope := 3; AfterImage := Image.VerifyNow(Budget);
      if (ImageDigest.SHA512 <> AfterImage.SHA512) or (ImageDigest.Size <> AfterImage.Size) then
        raise EMeasurement.Create(msChanged, CozyText_OwnMeasurement_OWN_FILE_GENERATION_CHANGED_3f9c840d);
      Scope := 4;
      GraphAfter := CaptureApiPointerGraph(SlotsAfter, DepthAfter);
      if (SlotsBefore <> SlotsAfter) or (DepthBefore <> DepthAfter) or
        (Length(GraphBefore) <> Length(GraphAfter)) or (Length(GraphBefore) = 0) or
        not CompareMem(@GraphBefore[0], @GraphAfter[0], Length(GraphBefore)) then
        raise EMeasurement.Create(msChanged, CozyText_OwnMeasurement_OWN_POINTER_GRAPH_CHANGED_e533f9f1);
      GraphMeasured := True;
      {$IFDEF GAME_OWN_MEASUREMENT_TESTS}InjectFault(omfApiGraph);{$ENDIF}
      Scope := 5;
      RuntimeAfter := Runtime.Capture;
      RuntimeGraph := OwnedRuntimeObservation(RuntimeProfile, RuntimeBefore, RuntimeAfter);
      if not OwnedRuntimeComplete(RuntimeGraph) then
        raise ECozyRuntimeGraph.Create(CozyText_OwnMeasurement_RUNTIME_BINDING_INVALID_1cc7839d);
      {$IFDEF GAME_OWN_MEASUREMENT_TESTS}
      InjectFault(omfRuntimeGraph);InjectFault(omfCancelled);InjectFault(omfDeadline);
      {$ENDIF}
      Budget.Check(0, 0); Stable := True; Status := msMeasured;
    except
      on E: Exception do
      begin
        Status := MeasurementFailureStatus(E);
        if E is ECozyRuntimeGraph then
        begin
          RuntimeReason := ECozyRuntimeGraph(E).Reason;
          if (RuntimeReason=CozyText_OwnMeasurement_RUNTIME_GRAPH_CHANGED_80502eb1) or (RuntimeReason=CozyText_OwnMeasurement_RUNTIME_OBJECT_RETIRED_8bb9ca51) then
            Status := msChanged else Status := msCoverageInsufficient;
        end
        else if Status=msCancelled then RuntimeReason:=CozyText_OwnMeasurement_CANCELLED_d10f1fdf
        else if Status=msDeadlineExceeded then RuntimeReason:=CozyText_OwnMeasurement_DEADLINE_EXCEEDED_2e60c1ef;
        case Scope of
          0,3: FileStatus := MeasurementStatusName(Status);
          1: CodeStatus := MeasurementStatusName(Status);
          2: CrcStatus := MeasurementStatusName(Status);
        end;
      end;
    end;
    if Status = msMeasured then Coverage := CozyText_OwnMeasurement_FULL_3998f2bd
    else
    begin
      Coverage := CozyText_OwnMeasurement_PARTIAL_39c0d98d; Stable := False; GraphMeasured := False;
      { Any single failure clears ALL usable measurements, including CRC and
        previously complete API/runtime graphs. There is no V2 fallback. }
      ImageDigest := Default(TImageDigest); CodeDigest := Default(TCodeIntegrityMeasurement);
      FreeAndNil(CrcLayers); FreeAndNil(RuntimeGraph);
      RuntimeGraph := OwnedRuntimeFailure(RuntimeProfile, RuntimeReason);
    end;
    Result := TJSONObject.Create;
    try
      Result.AddPair(CozyText_OwnMeasurement_contract_d06c9067, OwnMeasurementContract);
      Result.AddPair(CozyText_OwnMeasurement_version_b04eb4ac, TJSONNumber.Create(3));
      Result.AddPair(CozyText_OwnMeasurement_startedTick_1ed15b2e, TJSONNumber.Create(Int64(Started)));
      Result.AddPair(CozyText_OwnMeasurement_finishedTick_22d741e0, TJSONNumber.Create(Int64(MeasurementTick)));
      Result.AddPair(CozyText_OwnMeasurement_coverage_59fbaaf0, Coverage);
      Result.AddPair(CozyText_OwnMeasurement_fileStatus_135b5cb8, FileStatus); Result.AddPair(CozyText_OwnMeasurement_codeStatus_28e08f2b, CodeStatus);
      Result.AddPair(CozyText_OwnMeasurement_crcStatus_e1381e51, CrcStatus); Result.AddPair(CozyText_OwnMeasurement_imageStable_923d6097, TJSONBool.Create(Stable));
      Graph := TJSONObject.Create;
      Result.AddPair(CozyText_OwnMeasurement_pointerGraph_6a10a954, Graph);
      Graph.AddPair(CozyText_OwnMeasurement_version_b04eb4ac, TJSONNumber.Create(1));
      Graph.AddPair(CozyText_OwnMeasurement_scope_718bb03a, CozyText_OwnMeasurement_SEALED_API_ARENA_62c2dab0);
      if GraphMeasured then begin
        Graph.AddPair(CozyText_OwnMeasurement_status_64397a20, CozyText_OwnMeasurement_MEASURED_498762dc);
        Graph.AddPair(CozyText_OwnMeasurement_slots_26025179, TJSONNumber.Create(Int64(SlotsBefore)));
        Graph.AddPair(CozyText_OwnMeasurement_nodes_0715a5cc, TJSONNumber.Create(Int64(1+3*SlotsBefore)));
        Graph.AddPair(CozyText_OwnMeasurement_edges_5b917cde, TJSONNumber.Create(Int64(3*SlotsBefore)));
        Graph.AddPair(CozyText_OwnMeasurement_depth_e07a027f, TJSONNumber.Create(Int64(DepthBefore)));
        Graph.AddPair(CozyText_OwnMeasurement_sha512_ae79a37a, SHA512Bytes(GraphBefore));
        Graph.AddPair(CozyText_OwnMeasurement_crc64_622fa901, CrcBytes(ckEcma182,GraphBefore));
      end else begin
        Graph.AddPair(CozyText_OwnMeasurement_status_64397a20, CozyText_OwnMeasurement_FAILED_29f6f4fc);
        Graph.AddPair(CozyText_OwnMeasurement_slots_26025179, TJSONNumber.Create(0)); Graph.AddPair(CozyText_OwnMeasurement_nodes_0715a5cc, TJSONNumber.Create(0));
        Graph.AddPair(CozyText_OwnMeasurement_edges_5b917cde, TJSONNumber.Create(0)); Graph.AddPair(CozyText_OwnMeasurement_depth_e07a027f, TJSONNumber.Create(0));
        Graph.AddPair(CozyText_OwnMeasurement_sha512_ae79a37a, ''); Graph.AddPair(CozyText_OwnMeasurement_crc64_622fa901, '');
      end;
      Result.AddPair(CozyText_OwnMeasurement_ownedGraph_450e3856, RuntimeGraph); RuntimeGraph := nil;
    except Result.Free;raise;end;
    except
      { Allocation/serialization failure must not leave successful out values
        behind when no complete envelope can be returned. }
      Status:=msReadError;ImageDigest:=Default(TImageDigest);
      CodeDigest:=Default(TCodeIntegrityMeasurement);FreeAndNil(CrcLayers);
      raise;
    end;
  finally
    RuntimeGraph.Free;
    if Length(GraphBefore)>0 then FillChar(GraphBefore[0],Length(GraphBefore),0);
    if Length(GraphAfter)>0 then FillChar(GraphAfter[0],Length(GraphAfter),0);
  end;
end;
end.
