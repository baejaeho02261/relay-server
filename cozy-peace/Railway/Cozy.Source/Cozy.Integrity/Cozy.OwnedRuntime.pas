unit Cozy.OwnedRuntime;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity,
 System.SysUtils, System.JSON, System.SyncObjs, Cozy.PointerGraph;
type
  TCozyRuntimeProfile = (rpBootstrapClient, rpLicenseApi, rpOverlayClient);
  TCozyRuntimeBindings = record
    Owner, Gate, Transport, Security, Image, Code: TObject;
  end;
  TCozyRuntimeCapture = reference to function: TCozyRuntimeBindings;
  ECozyRuntimeGraph = class(Exception)
  private FReason: string;
  public
    constructor Create(const Reason: string);
    property Reason: string read FReason;
  end;
  ICozyRuntimeMeasurement = interface
    ['{66AD7C60-165C-4F9E-A1BB-05120A0B8630}']
    function Capture: TCozyPointerSnapshot;
    function Profile: string;
  end;
  { Explicit application registrations only. Object references are compared for
    identity under this registry's lock; never dereferenced or put on the wire.
    The client lifetime gate must outlive all measurement handles. This class
    does not own/free client objects or substitute for their lifetime locks.
    Nodes 4..6 represent registered dependency BINDINGS: borrowed by A/O,
    resources owned by B. Owner links describe these cells, not memory scans. }
  TCozyOwnedRuntimeGraph = class
  private
    FLock: TCriticalSection;
    FHistory: TCozyPointerGraphHistory;
    FBindings: array[1..6] of TObject;
    FProfile: TCozyRuntimeProfile;
    FClosed: Boolean;
    procedure ChangeDependencies(Security, Image, Code: TObject);
    function CaptureChecked(const Actual: TCozyRuntimeBindings): TCozyPointerSnapshot;
    function ProfileName: string;
  public
    constructor Create(Profile: TCozyRuntimeProfile; Owner, Gate, Transport: TObject);
    destructor Destroy; override;
    { Explicit first registration, or generation+1 after explicit retirement.
      A changed live reference is rejected rather than silently re-registered. }
    procedure BindDependencies(Security, Image, Code: TObject);
    procedure RetireDependency(Id: Cardinal);
    { Call after the owning gate has drained and BEFORE referenced objects free. }
    procedure Close;
    function Measurement(const Capture: TCozyRuntimeCapture): ICozyRuntimeMeasurement;
  end;
function CozyRuntimeBindings(Owner, Gate, Transport, Security, Image,
  Code: TObject): TCozyRuntimeBindings;
function OwnedRuntimeObservation(const Profile: string;
  const Before, After: TCozyPointerSnapshot): TJSONObject;
function OwnedRuntimeFailure(const Profile, Reason: string): TJSONObject;
function OwnedRuntimeComplete(Value: TJSONValue): Boolean;
implementation
uses System.Generics.Collections, Cozy.Hashes, Cozy.CrcLayers;
type
  TCozyRuntimeMeasurement = class(TInterfacedObject, ICozyRuntimeMeasurement)
  private
    FGraph: TCozyOwnedRuntimeGraph;
    FCapture: TCozyRuntimeCapture;
  public
    constructor Create(Graph: TCozyOwnedRuntimeGraph; const Capture: TCozyRuntimeCapture);
    function Capture: TCozyPointerSnapshot;
    function Profile: string;
  end;
constructor ECozyRuntimeGraph.Create(const Reason: string);
begin FReason := Reason; inherited Create(Reason); end;
procedure Require(Value: Boolean; const Reason: string = CozyText_OwnedRuntime_RUNTIME_BINDING_INVALID_ef99bc3d);
begin if not Value then raise ECozyRuntimeGraph.Create(Reason); end;
function CozyRuntimeBindings(Owner, Gate, Transport, Security, Image,
  Code: TObject): TCozyRuntimeBindings;
begin
  Result.Owner:=Owner; Result.Gate:=Gate; Result.Transport:=Transport;
  Result.Security:=Security; Result.Image:=Image; Result.Code:=Code;
end;
function ProfileValid(const Value: string): Boolean;
begin
  Result := (Value=CozyText_OwnedRuntime_BOOTSTRAP_CLIENT_V1_1d16e1ca) or (Value=CozyText_OwnedRuntime_LICENSE_API_V1_d3d72ec7) or
    (Value=CozyText_OwnedRuntime_OVERLAY_CLIENT_V1_91475572);
end;
function TCozyOwnedRuntimeGraph.ProfileName: string;
begin
  case FProfile of
    rpBootstrapClient: Result := CozyText_OwnedRuntime_BOOTSTRAP_CLIENT_V1_1d16e1ca;
    rpLicenseApi: Result := CozyText_OwnedRuntime_LICENSE_API_V1_d3d72ec7;
    rpOverlayClient: Result := CozyText_OwnedRuntime_OVERLAY_CLIENT_V1_91475572;
  else raise ECozyRuntimeGraph.Create(CozyText_OwnedRuntime_RUNTIME_BINDING_INVALID_ef99bc3d); end;
end;
procedure RebuildEdges(var S: TCozyPointerSnapshot);
var I,N: Integer;
begin
  SetLength(S.Edges,Length(S.Nodes)-1); N:=0;
  for I:=1 to High(S.Nodes) do
    if S.Nodes[I].Alive then
    begin
      S.Edges[N].SourceId:=1; S.Edges[N].SourceGeneration:=1;
      S.Edges[N].TargetId:=S.Nodes[I].Id;
      S.Edges[N].TargetGeneration:=S.Nodes[I].Generation;
      S.Edges[N].Offset:=(S.Nodes[I].Id-2)*8; S.Edges[N].Width:=8;
      Inc(N);
    end;
  SetLength(S.Edges,N);
end;
procedure AddChange(var Changes: TCozyPointerChanges; Id: Cardinal;
  Kind: TCozyPointerChangeKind);
var N: Integer;
begin N:=Length(Changes);SetLength(Changes,N+1);Changes[N].NodeId:=Id;Changes[N].Kind:=Kind;end;
constructor TCozyOwnedRuntimeGraph.Create(Profile: TCozyRuntimeProfile;
  Owner, Gate, Transport: TObject);
var S: TCozyPointerSnapshot; Changes: TCozyPointerChanges; I: Integer; Bytes:TBytes;
begin
  inherited Create;
  Require((Owner<>nil) and (Gate<>nil) and (Transport<>nil),CozyText_OwnedRuntime_RUNTIME_GRAPH_REQUIRED_ac523d97);
  Require((Owner<>Gate) and (Owner<>Transport) and (Gate<>Transport));
  FLock:=TCriticalSection.Create; FHistory:=TCozyPointerGraphHistory.Create;
  FProfile:=Profile; Require(ProfileValid(ProfileName));
  FBindings[1]:=Owner; FBindings[2]:=Gate; FBindings[3]:=Transport;
  S:=Default(TCozyPointerSnapshot); S.Revision:=1; S.RootId:=1; S.RootGeneration:=1;
  SetLength(S.Nodes,3); Changes:=nil;
  for I:=0 to 2 do
  begin
    S.Nodes[I].Id:=I+1;S.Nodes[I].Kind:=I+1;S.Nodes[I].Generation:=1;
    S.Nodes[I].Alive:=True;S.Nodes[I].Span:=8;
    if I=0 then S.Nodes[I].Span:=40
    else begin S.Nodes[I].OwnerId:=1;S.Nodes[I].OwnerGeneration:=1;end;
    AddChange(Changes,I+1,pcRegister);
  end;
  RebuildEdges(S); Bytes:=FHistory.Accept(S,Changes);
  if Length(Bytes)>0 then FillChar(Bytes[0],Length(Bytes),0);
end;
destructor TCozyOwnedRuntimeGraph.Destroy;
begin
  { Owner must already have drained its call gate. No application object is
    freed here; keeping an arbitrary raw pointer alive is not this contract. }
  FClosed:=True; FillChar(FBindings,SizeOf(FBindings),0);
  FHistory.Free; FLock.Free; inherited;
end;
procedure TCozyOwnedRuntimeGraph.ChangeDependencies(Security, Image, Code: TObject);
var S:TCozyPointerSnapshot; Changes:TCozyPointerChanges; Items:array[4..6]of TObject;
  Id,I,J:Integer; Bytes:TBytes;
begin
  Require(not FClosed,CozyText_OwnedRuntime_RUNTIME_OBJECT_RETIRED_79be3016);
  Items[4]:=Security;Items[5]:=Image;Items[6]:=Code;
  for Id:=4 to 6 do
  begin
    Require(Items[Id]<>nil,CozyText_OwnedRuntime_RUNTIME_GRAPH_REQUIRED_ac523d97);
    for J:=1 to 3 do Require(Items[Id]<>FBindings[J]);
    for J:=4 to Id-1 do Require(Items[Id]<>Items[J]);
    Require((FBindings[Id]=nil) or (FBindings[Id]=Items[Id]));
  end;
  if (FBindings[4]<>nil) and (FBindings[5]<>nil) and (FBindings[6]<>nil) then Exit;
  S:=FHistory.Capture; Require(S.Revision<High(UInt64));Inc(S.Revision);
  Changes:=nil; AddChange(Changes,1,pcRebind);
  for Id:=4 to 6 do
    if FBindings[Id]=nil then
    begin
      I:=Id-1;
      if I>=Length(S.Nodes) then
      begin
        SetLength(S.Nodes,I+1);S.Nodes[I].Id:=Id;S.Nodes[I].Kind:=Id;
        S.Nodes[I].Span:=8;S.Nodes[I].Generation:=1;
        S.Nodes[I].OwnerId:=1;S.Nodes[I].OwnerGeneration:=1;
        AddChange(Changes,Id,pcRegister);
      end else
      begin
        Require(not S.Nodes[I].Alive and (S.Nodes[I].Generation<High(Cardinal)));
        Inc(S.Nodes[I].Generation); AddChange(Changes,Id,pcReregister);
      end;
      S.Nodes[I].Alive:=True;
    end;
  RebuildEdges(S); Bytes:=FHistory.Accept(S,Changes);
  for Id:=4 to 6 do FBindings[Id]:=Items[Id];
  if Length(Bytes)>0 then FillChar(Bytes[0],Length(Bytes),0);
end;
procedure TCozyOwnedRuntimeGraph.BindDependencies(Security, Image, Code:TObject);
begin
  FLock.Acquire;
  try ChangeDependencies(Security,Image,Code);
  finally FLock.Release;end;
end;
procedure TCozyOwnedRuntimeGraph.RetireDependency(Id:Cardinal);
var S:TCozyPointerSnapshot;Changes:TCozyPointerChanges;Bytes:TBytes;
begin
  Require((Id>=4) and (Id<=6));
  FLock.Acquire;
  try
    Require(not FClosed,CozyText_OwnedRuntime_RUNTIME_OBJECT_RETIRED_79be3016);
    if FBindings[Id]=nil then Exit;
    S:=FHistory.Capture;Require(S.Revision<High(UInt64));Inc(S.Revision);
    S.Nodes[Id-1].Alive:=False;Changes:=nil;
    AddChange(Changes,Id,pcRetire);AddChange(Changes,1,pcRebind);RebuildEdges(S);
    Bytes:=FHistory.Accept(S,Changes);FBindings[Id]:=nil;
    if Length(Bytes)>0 then FillChar(Bytes[0],Length(Bytes),0);
  finally FLock.Release;end;
end;
procedure TCozyOwnedRuntimeGraph.Close;
var S:TCozyPointerSnapshot;Changes:TCozyPointerChanges;I:Integer;Bytes:TBytes;
begin
  if FLock=nil then Exit;
  FLock.Acquire;
  try
    if FClosed then Exit;
    if FHistory<>nil then
    begin
      S:=FHistory.Capture;
      if S.Revision>0 then
      begin
        Require(S.Revision<High(UInt64));Inc(S.Revision);Changes:=nil;
        for I:=1 to High(S.Nodes) do
          if S.Nodes[I].Alive then
          begin S.Nodes[I].Alive:=False;AddChange(Changes,S.Nodes[I].Id,pcRetire);end;
        if Length(Changes)>0 then AddChange(Changes,1,pcRebind);
        RebuildEdges(S);Bytes:=FHistory.Accept(S,Changes);
        if Length(Bytes)>0 then FillChar(Bytes[0],Length(Bytes),0);
      end;
    end;
    FillChar(FBindings,SizeOf(FBindings),0);FClosed:=True;
  finally FLock.Release;end;
end;
function TCozyOwnedRuntimeGraph.CaptureChecked(const Actual:TCozyRuntimeBindings):TCozyPointerSnapshot;
var Items:array[1..6]of TObject;I:Integer;Bytes:TBytes;Live,Depth:Cardinal;
begin
  Items[1]:=Actual.Owner;Items[2]:=Actual.Gate;Items[3]:=Actual.Transport;
  Items[4]:=Actual.Security;Items[5]:=Actual.Image;Items[6]:=Actual.Code;
  FLock.Acquire;
  try
    Require(not FClosed,CozyText_OwnedRuntime_RUNTIME_OBJECT_RETIRED_79be3016);
    Result:=FHistory.Capture;
    Require(Length(Result.Nodes)=6,CozyText_OwnedRuntime_RUNTIME_GRAPH_REQUIRED_ac523d97);
    for I:=1 to 6 do
    begin
      Require(Result.Nodes[I-1].Alive,CozyText_OwnedRuntime_RUNTIME_OBJECT_RETIRED_79be3016);
      Require((Items[I]<>nil) and (FBindings[I]=Items[I]));
    end;
    Bytes:=CozyOwnedPointerGraphBytes(Result,Live,Depth);
    Require((Live=6) and (Depth=1));
    if Length(Bytes)>0 then FillChar(Bytes[0],Length(Bytes),0);
  finally FLock.Release;end;
end;
function TCozyOwnedRuntimeGraph.Measurement(const Capture:TCozyRuntimeCapture):ICozyRuntimeMeasurement;
begin
  Require(Assigned(Capture),CozyText_OwnedRuntime_RUNTIME_GRAPH_REQUIRED_ac523d97);
  Result:=TCozyRuntimeMeasurement.Create(Self,Capture);
end;
constructor TCozyRuntimeMeasurement.Create(Graph:TCozyOwnedRuntimeGraph;const Capture:TCozyRuntimeCapture);
begin inherited Create;FGraph:=Graph;FCapture:=Capture;end;
function TCozyRuntimeMeasurement.Capture:TCozyPointerSnapshot;
var Actual:TCozyRuntimeBindings;
begin Actual:=FCapture();Result:=FGraph.CaptureChecked(Actual);end;
function TCozyRuntimeMeasurement.Profile:string;
begin Result:=FGraph.ProfileName;end;
function SnapshotJSON(const S:TCozyPointerSnapshot):TJSONObject;
var Nodes,Edges:TJSONArray;N:TJSONObject;I:Integer;
begin
  Result:=TJSONObject.Create;
  try
    Result.AddPair(CozyText_OwnedRuntime_revision_941a9012,UIntToStr(S.Revision));
    Result.AddPair(CozyText_OwnedRuntime_rootId_ee2e7edc,TJSONNumber.Create(Int64(S.RootId)));
    Result.AddPair(CozyText_OwnedRuntime_rootGeneration_8fc8cd0b,TJSONNumber.Create(Int64(S.RootGeneration)));
    Nodes:=TJSONArray.Create;Result.AddPair(CozyText_OwnedRuntime_nodes_d079c654,Nodes);
    for I:=0 to High(S.Nodes) do
    begin
      N:=TJSONObject.Create;Nodes.AddElement(N);
      N.AddPair(CozyText_OwnedRuntime_id_a1b0dd63,TJSONNumber.Create(Int64(S.Nodes[I].Id)));
      N.AddPair(CozyText_OwnedRuntime_kind_711f8205,TJSONNumber.Create(Int64(S.Nodes[I].Kind)));
      N.AddPair(CozyText_OwnedRuntime_span_0d5c34de,TJSONNumber.Create(Int64(S.Nodes[I].Span)));
      N.AddPair(CozyText_OwnedRuntime_generation_efc9f034,TJSONNumber.Create(Int64(S.Nodes[I].Generation)));
      N.AddPair(CozyText_OwnedRuntime_ownerId_ac33175a,TJSONNumber.Create(Int64(S.Nodes[I].OwnerId)));
      N.AddPair(CozyText_OwnedRuntime_ownerGeneration_1541bdcf,TJSONNumber.Create(Int64(S.Nodes[I].OwnerGeneration)));
      N.AddPair(CozyText_OwnedRuntime_alive_70120845,TJSONBool.Create(S.Nodes[I].Alive));
    end;
    Edges:=TJSONArray.Create;Result.AddPair(CozyText_OwnedRuntime_edges_932f6bf8,Edges);
    for I:=0 to High(S.Edges) do
    begin
      N:=TJSONObject.Create;Edges.AddElement(N);
      N.AddPair(CozyText_OwnedRuntime_sourceId_f4c8313d,TJSONNumber.Create(Int64(S.Edges[I].SourceId)));
      N.AddPair(CozyText_OwnedRuntime_sourceGeneration_b666c249,TJSONNumber.Create(Int64(S.Edges[I].SourceGeneration)));
      N.AddPair(CozyText_OwnedRuntime_targetId_c9502f37,TJSONNumber.Create(Int64(S.Edges[I].TargetId)));
      N.AddPair(CozyText_OwnedRuntime_targetGeneration_b0f27b41,TJSONNumber.Create(Int64(S.Edges[I].TargetGeneration)));
      N.AddPair(CozyText_OwnedRuntime_offset_69d3e254,TJSONNumber.Create(Int64(S.Edges[I].Offset)));
      N.AddPair(CozyText_OwnedRuntime_width_bbe43ff7,TJSONNumber.Create(Int64(S.Edges[I].Width)));
    end;
  except Result.Free;raise;end;
end;
function OwnedRuntimeFailure(const Profile,Reason:string):TJSONObject;
begin
  Result:=TJSONObject.Create;
  try
  Result.AddPair(CozyText_OwnedRuntime_version_69d33ebb,TJSONNumber.Create(1));Result.AddPair(CozyText_OwnedRuntime_scope_d98b0bfc,CozyText_OwnedRuntime_REGISTERED_APP_OBJECTS_22e259e4);
  Result.AddPair(CozyText_OwnedRuntime_profile_a8e06e10,Profile);Result.AddPair(CozyText_OwnedRuntime_status_97d1d749,CozyText_OwnedRuntime_FAILED_9bb8493c);Result.AddPair(CozyText_OwnedRuntime_reason_3fce503d,Reason);
  Result.AddPair(CozyText_OwnedRuntime_stable_c967afce,TJSONBool.Create(False));Result.AddPair(CozyText_OwnedRuntime_before_a41b3543,TJSONNull.Create);
  Result.AddPair(CozyText_OwnedRuntime_after_c8acc289,TJSONNull.Create);Result.AddPair(CozyText_OwnedRuntime_changes_8ebbe18c,TJSONArray.Create);
  Result.AddPair(CozyText_OwnedRuntime_sha512_707e15b5,'');Result.AddPair(CozyText_OwnedRuntime_crc64_697d97d6,'');
  except Result.Free;raise;end;
end;
function OwnedRuntimeObservation(const Profile:string;const Before,After:TCozyPointerSnapshot):TJSONObject;
var A,B:TBytes;Live,Depth:Cardinal;
begin
  Require(ProfileValid(Profile));
  A:=CozyOwnedPointerGraphBytes(Before,Live,Depth);
  try
    Require((Live=6) and (Depth=1));
    B:=CozyOwnedPointerGraphBytes(After,Live,Depth);
    try
      Require((Length(A)=Length(B)) and (Length(A)>0) and
        CompareMem(@A[0],@B[0],Length(A)),CozyText_OwnedRuntime_RUNTIME_GRAPH_CHANGED_b7cd3f5b);
      Result:=TJSONObject.Create;
      try
        Result.AddPair(CozyText_OwnedRuntime_version_69d33ebb,TJSONNumber.Create(1));Result.AddPair(CozyText_OwnedRuntime_scope_d98b0bfc,CozyText_OwnedRuntime_REGISTERED_APP_OBJECTS_22e259e4);
        Result.AddPair(CozyText_OwnedRuntime_profile_a8e06e10,Profile);Result.AddPair(CozyText_OwnedRuntime_status_97d1d749,CozyText_OwnedRuntime_MEASURED_149cac1b);Result.AddPair(CozyText_OwnedRuntime_reason_3fce503d,CozyText_OwnedRuntime_STABLE_4eb626fb);
        Result.AddPair(CozyText_OwnedRuntime_stable_c967afce,TJSONBool.Create(True));Result.AddPair(CozyText_OwnedRuntime_before_a41b3543,SnapshotJSON(Before));
        Result.AddPair(CozyText_OwnedRuntime_after_c8acc289,SnapshotJSON(After));Result.AddPair(CozyText_OwnedRuntime_changes_8ebbe18c,TJSONArray.Create);
        Result.AddPair(CozyText_OwnedRuntime_sha512_707e15b5,SHA512Bytes(A));Result.AddPair(CozyText_OwnedRuntime_crc64_697d97d6,CrcBytes(ckEcma182,A));
      except Result.Free;raise;end;
    finally if Length(B)>0 then FillChar(B[0],Length(B),0);end;
  finally if Length(A)>0 then FillChar(A[0],Length(A),0);end;
end;
function SnapshotFromJSON(Value:TJSONValue):TCozyPointerSnapshot;
var O,N:TJSONObject;Nodes,Edges:TJSONArray;V:TJSONValue;I:Integer;Revision:UInt64;
  function Number(Obj:TJSONObject;const Name:string):Cardinal;
  var Item:TJSONValue;U:UInt64;
  begin
    U:=0;Item:=Obj.GetValue(Name);Require((Item is TJSONNumber) and
      TryStrToUInt64(Item.Value,U) and (U<=High(Cardinal)));Result:=Cardinal(U);
  end;
begin
  Revision:=0;Result:=Default(TCozyPointerSnapshot);Require(Value is TJSONObject);O:=TJSONObject(Value);
  Require(O.Count=5);V:=O.GetValue(CozyText_OwnedRuntime_revision_941a9012);Require((V is TJSONString) and
    TryStrToUInt64(V.Value,Revision) and (UIntToStr(Revision)=V.Value) and (Revision>0));
  Result.Revision:=Revision;Result.RootId:=Number(O,CozyText_OwnedRuntime_rootId_ee2e7edc);Result.RootGeneration:=Number(O,CozyText_OwnedRuntime_rootGeneration_8fc8cd0b);
  Require((Result.RootId=1) and (Result.RootGeneration=1));
  V:=O.GetValue(CozyText_OwnedRuntime_nodes_d079c654);Require(V is TJSONArray);Nodes:=TJSONArray(V);Require(Nodes.Count=6);
  V:=O.GetValue(CozyText_OwnedRuntime_edges_932f6bf8);Require(V is TJSONArray);Edges:=TJSONArray(V);Require(Edges.Count=5);
  SetLength(Result.Nodes,6);SetLength(Result.Edges,5);
  for I:=0 to 5 do
  begin
    Require(Nodes.Items[I] is TJSONObject);N:=TJSONObject(Nodes.Items[I]);Require(N.Count=7);
    Result.Nodes[I].Id:=Number(N,CozyText_OwnedRuntime_id_a1b0dd63);Result.Nodes[I].Kind:=Number(N,CozyText_OwnedRuntime_kind_711f8205);
    Result.Nodes[I].Span:=Number(N,CozyText_OwnedRuntime_span_0d5c34de);Result.Nodes[I].Generation:=Number(N,CozyText_OwnedRuntime_generation_efc9f034);
    Result.Nodes[I].OwnerId:=Number(N,CozyText_OwnedRuntime_ownerId_ac33175a);Result.Nodes[I].OwnerGeneration:=Number(N,CozyText_OwnedRuntime_ownerGeneration_1541bdcf);
    V:=N.GetValue(CozyText_OwnedRuntime_alive_70120845);Require((V is TJSONBool) and (V.Value=CozyText_OwnedRuntime_true_12fe9b6f));Result.Nodes[I].Alive:=True;
    Require((Result.Nodes[I].Id=Cardinal(I+1)) and (Result.Nodes[I].Kind=Cardinal(I+1)) and
      (Result.Nodes[I].Generation>0));
    if I=0 then Require((Result.Nodes[I].Span=40) and (Result.Nodes[I].Generation=1) and
      (Result.Nodes[I].OwnerId=0) and (Result.Nodes[I].OwnerGeneration=0))
    else Require((Result.Nodes[I].Span=8) and (Result.Nodes[I].OwnerId=1) and
      (Result.Nodes[I].OwnerGeneration=1));
  end;
  for I:=0 to 4 do
  begin
    Require(Edges.Items[I] is TJSONObject);N:=TJSONObject(Edges.Items[I]);Require(N.Count=6);
    Result.Edges[I].SourceId:=Number(N,CozyText_OwnedRuntime_sourceId_f4c8313d);Result.Edges[I].SourceGeneration:=Number(N,CozyText_OwnedRuntime_sourceGeneration_b666c249);
    Result.Edges[I].TargetId:=Number(N,CozyText_OwnedRuntime_targetId_c9502f37);Result.Edges[I].TargetGeneration:=Number(N,CozyText_OwnedRuntime_targetGeneration_b0f27b41);
    Result.Edges[I].Offset:=Number(N,CozyText_OwnedRuntime_offset_69d3e254);Result.Edges[I].Width:=Number(N,CozyText_OwnedRuntime_width_bbe43ff7);
    Require((Result.Edges[I].SourceId=1) and (Result.Edges[I].SourceGeneration=1) and
      (Result.Edges[I].TargetId=Cardinal(I+2)) and (Result.Edges[I].Offset=Cardinal(I*8)) and
      (Result.Edges[I].Width=8));
  end;
end;
function OwnedRuntimeComplete(Value:TJSONValue):Boolean;
var O:TJSONObject;V:TJSONValue;A,B:TCozyPointerSnapshot;BytesA,BytesB:TBytes;Live,Depth:Cardinal;
  function Text(const Name,Expected:string):Boolean;
  var Item:TJSONValue;
  begin Item:=O.GetValue(Name);Result:=(Item is TJSONString) and (Item.Value=Expected);end;
begin
  Result:=False;BytesA:=nil;BytesB:=nil;
  try
    try
      if not (Value is TJSONObject) then Exit;O:=TJSONObject(Value);if O.Count<>11 then Exit;
      V:=O.GetValue(CozyText_OwnedRuntime_version_69d33ebb);if not (V is TJSONNumber) or (V.Value<>'1') then Exit;
      if not Text(CozyText_OwnedRuntime_scope_d98b0bfc,CozyText_OwnedRuntime_REGISTERED_APP_OBJECTS_22e259e4) or not Text(CozyText_OwnedRuntime_status_97d1d749,CozyText_OwnedRuntime_MEASURED_149cac1b) or
        not Text(CozyText_OwnedRuntime_reason_3fce503d,CozyText_OwnedRuntime_STABLE_4eb626fb) then Exit;
      V:=O.GetValue(CozyText_OwnedRuntime_profile_a8e06e10);if not (V is TJSONString) or not ProfileValid(V.Value) then Exit;
      V:=O.GetValue(CozyText_OwnedRuntime_stable_c967afce);if not (V is TJSONBool) or (V.Value<>CozyText_OwnedRuntime_true_12fe9b6f) then Exit;
      V:=O.GetValue(CozyText_OwnedRuntime_changes_8ebbe18c);if not (V is TJSONArray) or (TJSONArray(V).Count<>0) then Exit;
      A:=SnapshotFromJSON(O.GetValue(CozyText_OwnedRuntime_before_a41b3543));B:=SnapshotFromJSON(O.GetValue(CozyText_OwnedRuntime_after_c8acc289));
      BytesA:=CozyOwnedPointerGraphBytes(A,Live,Depth);BytesB:=CozyOwnedPointerGraphBytes(B,Live,Depth);
      if (Length(BytesA)=0) or (Length(BytesA)<>Length(BytesB)) or
        not CompareMem(@BytesA[0],@BytesB[0],Length(BytesA)) then Exit;
      if not Text(CozyText_OwnedRuntime_sha512_707e15b5,SHA512Bytes(BytesA)) or not Text(CozyText_OwnedRuntime_crc64_697d97d6,CrcBytes(ckEcma182,BytesA)) then Exit;
      Result:=True;
    except Result:=False;end;
  finally
    if Length(BytesA)>0 then FillChar(BytesA[0],Length(BytesA),0);
    if Length(BytesB)>0 then FillChar(BytesB[0],Length(BytesB),0);
  end;
end;
end.
