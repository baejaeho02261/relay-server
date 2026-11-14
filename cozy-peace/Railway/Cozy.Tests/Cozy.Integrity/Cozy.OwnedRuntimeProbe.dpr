program Cozy_OwnedRuntimeProbe;
{$APPTYPE CONSOLE}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
{ Native explicit-object registration/retirement checks. It does not inspect
  arbitrary memory, contact a server or claim Windows A/B/O runtime PASS. }
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.TestsIntegrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIntegrity.pas',
 System.SysUtils, System.JSON, Cozy.PointerGraph, Cozy.OwnedRuntime;
var Checks:Integer;
procedure Require(Value:Boolean;const Name:string);
begin if not Value then raise Exception.Create(Name);Inc(Checks);end;
procedure Replace(O:TJSONObject;const Name:string;V:TJSONValue);
var Pair:TJSONPair;
begin Pair:=O.RemovePair(Name);Pair.Free;O.AddPair(Name,V);end;
procedure RunProfile(Profile:TCozyRuntimeProfile);
var Objects:array[1..6]of TObject;Replacement:TObject;Graph:TCozyOwnedRuntimeGraph;
  Runtime:ICozyRuntimeMeasurement;Actual:TCozyRuntimeBindings;
  Before,After:TCozyPointerSnapshot;Wire,Bad:TJSONObject;Edge:TJSONObject;
  I:Integer;Rejected:Boolean;
begin
  FillChar(Objects,SizeOf(Objects),0);Replacement:=nil;Graph:=nil;Wire:=nil;Runtime:=nil;
  try
    for I:=1 to 6 do Objects[I]:=TObject.Create;
    Replacement:=TObject.Create;
    Actual:=CozyRuntimeBindings(Objects[1],Objects[2],Objects[3],Objects[4],Objects[5],Objects[6]);
    Graph:=TCozyOwnedRuntimeGraph.Create(Profile,Objects[1],Objects[2],Objects[3]);
    Runtime:=Graph.Measurement(function:TCozyRuntimeBindings begin Result:=Actual;end);
    Rejected:=False;
    try Runtime.Capture;except on E:ECozyRuntimeGraph do Rejected:=E.Reason=CozyText_OwnedRuntimeProbe_RUNTIME_GRAPH_REQUIRED_a6d8b6ec;end;
    Require(Rejected,CozyText_OwnedRuntimeProbe_UNREGISTERED_DEPENDENCIES_REJECTED_92aa5195);
    Graph.BindDependencies(Objects[4],Objects[5],Objects[6]);
    Before:=Runtime.Capture;After:=Runtime.Capture;
    Require((Before.Revision=2) and (Length(Before.Nodes)=6) and (Length(Before.Edges)=5),CozyText_OwnedRuntimeProbe_ACTUAL_REGISTRATION_SHAPE_4e1bb2cc);
    Wire:=OwnedRuntimeObservation(Runtime.Profile,Before,After);
    Require(OwnedRuntimeComplete(Wire),CozyText_OwnedRuntimeProbe_REGISTERED_RUNTIME_COMPLETES_9a01e648);
    Require(Wire.GetValue(CozyText_OwnedRuntimeProbe_sha512_a541ad8c).Value=
      CozyText_OwnedRuntimeProbe_Digest_8fd1f804,
      CozyText_OwnedRuntimeProbe_INDEPENDENT_REVISION_TWO_SHA512_GOLDEN_8fd5ccb3);
    Require(Wire.GetValue(CozyText_OwnedRuntimeProbe_crc64_ae68eeb1).Value=CozyText_OwnedRuntimeProbe_5164BB6162E7F72A_08eddc7c,CozyText_OwnedRuntimeProbe_INDEPENDENT_REVISION_TWO_CRC64_GOLDEN_aaaabff2);
    Require(Pos(CozyText_OwnedRuntimeProbe_pointer_d77d7283,LowerCase(Wire.ToJSON))=0,CozyText_OwnedRuntimeProbe_NO_POINTER_ADDRESS_FIELDS_b6bf5dee);
    Wire.Free;Wire:=nil;
    Actual.Gate:=Replacement;Rejected:=False;
    try Runtime.Capture;except on E:ECozyRuntimeGraph do Rejected:=E.Reason=CozyText_OwnedRuntimeProbe_RUNTIME_BINDING_INVALID_06b2fe33;end;
    Require(Rejected,CozyText_OwnedRuntimeProbe_ACTUAL_FIELD_REPLACEMENT_REJECTED_418baa92);Actual.Gate:=Objects[2];
    Rejected:=False;
    try Graph.BindDependencies(Objects[4],Replacement,Objects[6]);
    except on E:ECozyRuntimeGraph do Rejected:=E.Reason=CozyText_OwnedRuntimeProbe_RUNTIME_BINDING_INVALID_06b2fe33;end;
    Require(Rejected,CozyText_OwnedRuntimeProbe_LIVE_BINDING_CANNOT_AUTOREGISTER_REPLACEMENT_86136904);
    After:=Runtime.Capture;Require(After.Revision=Before.Revision,CozyText_OwnedRuntimeProbe_FAILED_BIND_LEAVES_HISTORY_UNCHANGED_f67366ec);
    Graph.RetireDependency(5);Rejected:=False;
    try Runtime.Capture;except on E:ECozyRuntimeGraph do Rejected:=E.Reason=CozyText_OwnedRuntimeProbe_RUNTIME_OBJECT_RETIRED_d605b328;end;
    Require(Rejected,CozyText_OwnedRuntimeProbe_RETIRED_OBJECT_DISTINGUISHED_4a52d316);
    Graph.BindDependencies(Objects[4],Replacement,Objects[6]);Actual.Image:=Replacement;
    After:=Runtime.Capture;
    Require((After.Revision=4) and (After.Nodes[4].Generation=2),CozyText_OwnedRuntimeProbe_EXPLICIT_REREGISTRATION_ADVANCES_GENERATION_72e5e81f);
    Rejected:=False;
    try Wire:=OwnedRuntimeObservation(Runtime.Profile,Before,After);
    except on E:ECozyRuntimeGraph do Rejected:=E.Reason=CozyText_OwnedRuntimeProbe_RUNTIME_GRAPH_CHANGED_56cb5537;end;
    Require(Rejected,CozyText_OwnedRuntimeProbe_MID_MEASUREMENT_GENERATION_CHANGE_REJECTED_b327d43f);
    Wire:=OwnedRuntimeObservation(Runtime.Profile,After,After);
    Require(OwnedRuntimeComplete(Wire),CozyText_OwnedRuntimeProbe_NORMAL_GENERATION_STABLE_NEXT_MEASUREMENT_ALLOWE_3b075dfb);
    Bad:=TJSONObject(Wire.Clone);
    try
      Edge:=TJSONObject(TJSONArray(TJSONObject(Bad.GetValue(CozyText_OwnedRuntimeProbe_after_1a85ead0)).GetValue(CozyText_OwnedRuntimeProbe_edges_d6694165)).Items[0]);
      Replace(Edge,CozyText_OwnedRuntimeProbe_targetGeneration_3ecb3417,TJSONNumber.Create(99));
      Require(not OwnedRuntimeComplete(Bad),CozyText_OwnedRuntimeProbe_WRONG_RELATION_GENERATION_REJECTED_13e18727);
    finally Bad.Free;end;
    Bad:=TJSONObject(Wire.Clone);
    try
      TJSONObject(Bad.GetValue(CozyText_OwnedRuntimeProbe_before_e7f868a2)).AddPair(CozyText_OwnedRuntimeProbe_address_b60a03fd,CozyText_OwnedRuntimeProbe_not_allowed_dcc7bf4f);
      Require(not OwnedRuntimeComplete(Bad),CozyText_OwnedRuntimeProbe_EXTRA_ADDRESS_FIELD_REJECTED_96547617);
    finally Bad.Free;end;
    Graph.Close;Rejected:=False;
    try Runtime.Capture;except on E:ECozyRuntimeGraph do Rejected:=E.Reason=CozyText_OwnedRuntimeProbe_RUNTIME_OBJECT_RETIRED_d605b328;end;
    Require(Rejected,CozyText_OwnedRuntimeProbe_CLOSED_OWNER_CANNOT_MEASURE_3eb24ac2);
  finally
    Runtime:=nil;Wire.Free;Graph.Free;Replacement.Free;
    for I:=6 downto 1 do Objects[I].Free;
  end;
end;
begin
  Checks:=0;
  try
    RunProfile(rpBootstrapClient);RunProfile(rpLicenseApi);RunProfile(rpOverlayClient);
    Writeln(CozyText_OwnedRuntimeProbe_OWNED_RUNTIME_NATIVE_PROBE_PASS_9673330b,Checks,CozyText_OwnedRuntimeProbe_checks_378598b3);
    Writeln(CozyText_OwnedRuntimeProbe_Scope_explicit_owned_client_bindings_not_hardwar_bd57d099);
  except on E:Exception do
    begin Writeln(CozyText_OwnedRuntimeProbe_OWNED_RUNTIME_NATIVE_PROBE_FAIL_5ce16a7a,E.Message);ExitCode:=1;end;
  end;
end.
