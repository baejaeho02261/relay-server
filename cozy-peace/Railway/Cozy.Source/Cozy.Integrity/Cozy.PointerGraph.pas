unit Cozy.PointerGraph;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$B-}{$Q+}{$R+}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity,
 {$IFDEF FPC}SysUtils{$ELSE}System.SysUtils{$ENDIF};
const CozyPointerGraphContract = CozyText_PointerGraph_COZY_POINTER_GRAPH_V1_e7479c2a;
  CozyOwnedPointerGraphContract = CozyText_PointerGraph_COZY_OWNED_POINTER_GRAPH_V2_de145bfc;
  CozyPointerGraphMaxNodes = 4096;
  CozyPointerGraphMaxEdges = 4096;
  CozyPointerGraphMaxDepth = 16;
type
  { Caller-owned snapshot only. Hold the owning structure's lifetime/read lock
    while capturing. Register explicit stable IDs and semantic offsets, never
    process addresses. The validator never dereferences an edge or a pointer. }
  TCozyPointerNode = record
    Id, Kind, Span, Generation: Cardinal;
    Alive: Boolean;
  end;
  TCozyPointerEdge = record
    SourceId, TargetId, Offset, Width: Cardinal;
  end;
  TCozyPointerNodes = array of TCozyPointerNode;
  TCozyPointerEdges = array of TCozyPointerEdge;
  { V2 is opt-in. Stable IDs are caller-assigned logical identifiers, never
    addresses. Retired nodes remain as bounded tombstones for this history. }
  TCozyOwnedPointerNode = record
    Id, Kind, Span, Generation, OwnerId, OwnerGeneration: Cardinal;
    Alive: Boolean;
  end;
  TCozyOwnedPointerEdge = record
    SourceId, SourceGeneration, TargetId, TargetGeneration, Offset, Width: Cardinal;
  end;
  TCozyOwnedPointerNodes = array of TCozyOwnedPointerNode;
  TCozyOwnedPointerEdges = array of TCozyOwnedPointerEdge;
  TCozyPointerSnapshot = record
    Revision: UInt64;
    RootId, RootGeneration: Cardinal;
    Nodes: TCozyOwnedPointerNodes;
    Edges: TCozyOwnedPointerEdges;
  end;
  TCozyPointerChangeKind = (pcRegister, pcRetire, pcReregister, pcRebind);
  TCozyPointerChange = record
    NodeId: Cardinal;
    Kind: TCozyPointerChangeKind;
  end;
  TCozyPointerChanges = array of TCozyPointerChange;
  { Caller serializes Accept/Capture under the same owning lifetime lock.
    Failed transitions leave the history unchanged. No disk state is created. }
  TCozyPointerGraphHistory = class
  private
    FSnapshot: TCozyPointerSnapshot;
  public
    function Accept(const Next: TCozyPointerSnapshot;
      const Changes: TCozyPointerChanges): TBytes;
    function Capture: TCozyPointerSnapshot;
  end;
function CozyOwnedPointerGraphBytes(const Snapshot: TCozyPointerSnapshot;
  out LiveNodes, OwnerDepth: Cardinal): TBytes;
procedure CozyPointerGraphTransition(const Previous, Next: TCozyPointerSnapshot;
  const Changes: TCozyPointerChanges);
function CozyPointerGraphBytes(const Nodes: TCozyPointerNodes;
  const Edges: TCozyPointerEdges; out Depth: Cardinal): TBytes;
procedure CozyApiGraphShape(Slots: Cardinal; out Nodes: TCozyPointerNodes;
  out Edges: TCozyPointerEdges);
implementation
procedure Require(Value: Boolean);
begin
  if not Value then raise EArgumentException.Create(CozyText_PointerGraph_OWN_POINTER_GRAPH_INVALID_27aedbdd);
end;
function CozyPointerGraphBytes(const Nodes: TCozyPointerNodes;
  const Edges: TCozyPointerEdges; out Depth: Cardinal): TBytes;
const Prefix: AnsiString = CozyText_PointerGraph_COZY_POINTER_GRAPH_V1_f4b17a52;
var Color: array of Byte; Heights: array of Cardinal; FirstEdge: array of Integer;
  I, J, At, Visited: Integer;
  procedure Put(Value: Cardinal);
  var K: Integer;
  begin
    for K := 0 to 3 do begin Result[At] := Byte((Value shr (8*K)) and $FF); Inc(At); end;
  end;
  function Visit(Index: Integer; Level: Cardinal): Cardinal;
  var E: Integer; Child: Cardinal;
  begin
    Require(Level <= CozyPointerGraphMaxDepth);
    Require(Color[Index] <> 1);
    if Color[Index] = 2 then begin
      Require(Level + Heights[Index] <= CozyPointerGraphMaxDepth);
      Exit(Heights[Index]);
    end;
    Color[Index] := 1; Inc(Visited); Result := 0;
    for E := FirstEdge[Index] to FirstEdge[Index+1]-1 do begin
      Child := 1 + Visit(Integer(Edges[E].TargetId)-1, Level+1);
      if Child > Result then Result := Child;
    end;
    Color[Index] := 2; Heights[Index] := Result;
  end;
begin
  Result := nil; Depth := 0;
  Require((Length(Nodes) > 0) and (Length(Nodes) <= CozyPointerGraphMaxNodes));
  Require(Length(Edges) <= CozyPointerGraphMaxEdges);
  for I := 0 to High(Nodes) do begin
    Require(Nodes[I].Id = Cardinal(I+1));
    Require(Nodes[I].Alive and (Nodes[I].Generation > 0));
    Require((Nodes[I].Kind >= 1) and (Nodes[I].Kind <= 16));
    Require((Nodes[I].Span >= 1) and (Nodes[I].Span <= 1048576));
  end;
  SetLength(FirstEdge,Length(Nodes)+1);
  for I := 0 to High(Edges) do begin
    Require((Edges[I].SourceId >= 1) and (Edges[I].SourceId <= Cardinal(Length(Nodes))) and
      (Edges[I].TargetId >= 1) and (Edges[I].TargetId <= Cardinal(Length(Nodes))));
    Inc(FirstEdge[Edges[I].SourceId]);
    Require((Edges[I].Width = 4) or (Edges[I].Width = 8));
    Require(UInt64(Edges[I].Offset) + Edges[I].Width <= Nodes[Edges[I].SourceId-1].Span);
    Require(Nodes[Edges[I].SourceId-1].Generation = Nodes[Edges[I].TargetId-1].Generation);
    if I > 0 then Require((Edges[I-1].SourceId < Edges[I].SourceId) or
      ((Edges[I-1].SourceId = Edges[I].SourceId) and
       (UInt64(Edges[I-1].Offset)+Edges[I-1].Width <= Edges[I].Offset)));
  end;
  for I := 1 to Length(Nodes) do Inc(FirstEdge[I],FirstEdge[I-1]);
  SetLength(Color, Length(Nodes)); SetLength(Heights, Length(Nodes)); Visited := 0;
  Depth := Visit(0,0); Require(Visited = Length(Nodes));
  SetLength(Result, Length(Prefix)+12+Length(Nodes)*20+Length(Edges)*16);
  Move(Prefix[1],Result[0],Length(Prefix)); At := Length(Prefix);
  Put(Cardinal(Length(Nodes))); Put(Cardinal(Length(Edges))); Put(Depth);
  for I := 0 to High(Nodes) do begin
    Put(Nodes[I].Id); Put(Nodes[I].Kind); Put(Nodes[I].Span);
    Put(Nodes[I].Generation); Put(Ord(Nodes[I].Alive));
  end;
  for J := 0 to High(Edges) do begin
    Put(Edges[J].SourceId); Put(Edges[J].TargetId); Put(Edges[J].Offset); Put(Edges[J].Width);
  end;
end;
procedure CozyApiGraphShape(Slots: Cardinal; out Nodes: TCozyPointerNodes;
  out Edges: TCozyPointerEdges);
var I, At: Cardinal;
  procedure Node(Id, Kind, Span: Cardinal);
  begin Nodes[Id-1].Id:=Id; Nodes[Id-1].Kind:=Kind; Nodes[Id-1].Span:=Span;
    Nodes[Id-1].Generation:=1; Nodes[Id-1].Alive:=True; end;
  procedure Edge(SourceId, TargetId, Offset: Cardinal);
  begin Edges[At].SourceId:=SourceId; Edges[At].TargetId:=TargetId;
    Edges[At].Offset:=Offset; Edges[At].Width:=8; Inc(At); end;
begin
  Require((Slots >= 1) and (Slots <= 1024));
  SetLength(Nodes,1+3*Slots); SetLength(Edges,3*Slots); At:=0;
  Node(1,1,Slots*8);
  for I:=0 to Slots-1 do begin Node(2+3*I,2,16);Node(3+3*I,3,8);Node(4+3*I,4,1);Edge(1,2+3*I,I*8);end;
  for I:=0 to Slots-1 do begin Edge(2+3*I,3+3*I,0);Edge(3+3*I,4+3*I,0);end;
end;
{ V1 above is deliberately unchanged: its strict DAG and golden bytes remain. }
procedure TransitionRequire(Value: Boolean);
begin
  if not Value then raise EArgumentException.Create(CozyText_PointerGraph_OWN_POINTER_GRAPH_TRANSITION_INVALID_8bc8b2c4);
end;
function CloneSnapshot(const Value: TCozyPointerSnapshot): TCozyPointerSnapshot;
begin
  Result := Value;
  Result.Nodes := Copy(Value.Nodes, 0, Length(Value.Nodes));
  Result.Edges := Copy(Value.Edges, 0, Length(Value.Edges));
end;
function NodeCompare(const A, B: TCozyOwnedPointerNode): Integer;
begin
  if A.Id < B.Id then Result := -1 else if A.Id > B.Id then Result := 1 else Result := 0;
end;
function EdgeCompare(const A, B: TCozyOwnedPointerEdge): Integer;
begin
  if A.SourceId < B.SourceId then Exit(-1);
  if A.SourceId > B.SourceId then Exit(1);
  if A.Offset < B.Offset then Exit(-1);
  if A.Offset > B.Offset then Exit(1);
  Result := 0;
end;
procedure SortSnapshot(var Value: TCozyPointerSnapshot);
var I, J: Integer; Node: TCozyOwnedPointerNode; Edge: TCozyOwnedPointerEdge;
begin
  { Bounded insertion sort: <= 4096 records; no recursion or pointer walking. }
  for I := 1 to High(Value.Nodes) do begin
    Node := Value.Nodes[I]; J := I-1;
    while (J >= 0) and (NodeCompare(Value.Nodes[J], Node) > 0) do begin
      Value.Nodes[J+1] := Value.Nodes[J]; Dec(J);
    end;
    Value.Nodes[J+1] := Node;
  end;
  for I := 1 to High(Value.Edges) do begin
    Edge := Value.Edges[I]; J := I-1;
    while (J >= 0) and (EdgeCompare(Value.Edges[J], Edge) > 0) do begin
      Value.Edges[J+1] := Value.Edges[J]; Dec(J);
    end;
    Value.Edges[J+1] := Edge;
  end;
end;
function FindOwnedNode(const Nodes: TCozyOwnedPointerNodes; Id: Cardinal): Integer;
var L, H, M: Integer;
begin
  L:=0; H:=High(Nodes);
  while L<=H do begin
    M:=L+(H-L) div 2;
    if Nodes[M].Id=Id then Exit(M);
    if Nodes[M].Id<Id then L:=M+1 else H:=M-1;
  end;
  Result:=-1;
end;
function CozyOwnedPointerGraphBytes(const Snapshot: TCozyPointerSnapshot;
  out LiveNodes, OwnerDepth: Cardinal): TBytes;
const Prefix: AnsiString = CozyText_PointerGraph_COZY_OWNED_POINTER_GRAPH_V2_8260ba3b;
var S: TCozyPointerSnapshot; I, J, Root, Source, Target, At, Head, Tail: Integer;
  Seen: array of Boolean; Queue, FirstEdge: array of Integer; Depth: Cardinal;
  procedure Put(Value: Cardinal);
  var K: Integer;
  begin
    for K:=0 to 3 do begin Result[At]:=Byte((Value shr (8*K)) and $FF);Inc(At);end;
  end;
begin
  Result:=nil; LiveNodes:=0; OwnerDepth:=0;
  Require((Snapshot.Revision>0) and (Length(Snapshot.Nodes)>0) and
    (Length(Snapshot.Nodes)<=CozyPointerGraphMaxNodes) and
    (Length(Snapshot.Edges)<=CozyPointerGraphMaxEdges));
  S:=CloneSnapshot(Snapshot); SortSnapshot(S);
  Root:=FindOwnedNode(S.Nodes,S.RootId); Require(Root>=0);
  Require(S.Nodes[Root].Alive and (S.RootGeneration=S.Nodes[Root].Generation));
  for I:=0 to High(S.Nodes) do begin
    Require((S.Nodes[I].Id>0) and (S.Nodes[I].Generation>0) and
      (S.Nodes[I].Kind>=1) and (S.Nodes[I].Kind<=16) and
      (S.Nodes[I].Span>=1) and (S.Nodes[I].Span<=1048576));
    if I>0 then Require(S.Nodes[I-1].Id<>S.Nodes[I].Id);
    if S.Nodes[I].OwnerId=0 then Require(S.Nodes[I].OwnerGeneration=0)
    else Require((S.Nodes[I].OwnerGeneration>0) and
      (FindOwnedNode(S.Nodes,S.Nodes[I].OwnerId)>=0));
    if not S.Nodes[I].Alive then Continue;
    Inc(LiveNodes); J:=I; Depth:=0;
    while S.Nodes[J].OwnerId<>0 do begin
      Target:=FindOwnedNode(S.Nodes,S.Nodes[J].OwnerId); Require(Target>=0);
      Require(S.Nodes[Target].Alive and
        (S.Nodes[Target].Generation=S.Nodes[J].OwnerGeneration));
      Inc(Depth); Require(Depth<=CozyPointerGraphMaxDepth); J:=Target;
    end;
    Require(J=Root);
    if Depth>OwnerDepth then OwnerDepth:=Depth;
  end;
  SetLength(FirstEdge,Length(S.Nodes)+1);
  for I:=0 to High(S.Edges) do begin
    Source:=FindOwnedNode(S.Nodes,S.Edges[I].SourceId);
    Target:=FindOwnedNode(S.Nodes,S.Edges[I].TargetId);
    Require((Source>=0) and (Target>=0));
    Require(S.Nodes[Source].Alive and S.Nodes[Target].Alive and
      (S.Nodes[Source].Generation=S.Edges[I].SourceGeneration) and
      (S.Nodes[Target].Generation=S.Edges[I].TargetGeneration));
    Require((S.Edges[I].Width=4) or (S.Edges[I].Width=8));
    Require(UInt64(S.Edges[I].Offset)+S.Edges[I].Width<=S.Nodes[Source].Span);
    if (I>0) and (S.Edges[I-1].SourceId=S.Edges[I].SourceId) then
      Require(UInt64(S.Edges[I-1].Offset)+S.Edges[I-1].Width<=S.Edges[I].Offset);
    Inc(FirstEdge[Source+1]);
  end;
  for I:=1 to Length(S.Nodes) do Inc(FirstEdge[I],FirstEdge[I-1]);
  { Cyclic references use a bounded queue. Owner links remain acyclic. }
  SetLength(Seen,Length(S.Nodes)); SetLength(Queue,Length(S.Nodes));
  Queue[0]:=Root; Seen[Root]:=True; Head:=0; Tail:=1;
  while Head<Tail do begin
    Source:=Queue[Head]; Inc(Head);
    for I:=FirstEdge[Source] to FirstEdge[Source+1]-1 do begin
      Target:=FindOwnedNode(S.Nodes,S.Edges[I].TargetId);
      if not Seen[Target] then begin
        Seen[Target]:=True; Queue[Tail]:=Target; Inc(Tail);
      end;
    end;
  end;
  Require(Cardinal(Tail)=LiveNodes);
  SetLength(Result,Length(Prefix)+28+Length(S.Nodes)*28+Length(S.Edges)*24);
  Move(Prefix[1],Result[0],Length(Prefix)); At:=Length(Prefix);
  Put(Cardinal(S.Revision and $FFFFFFFF)); Put(Cardinal(S.Revision shr 32));
  Put(S.RootId); Put(S.RootGeneration); Put(Cardinal(Length(S.Nodes)));
  Put(Cardinal(Length(S.Edges))); Put(OwnerDepth);
  for I:=0 to High(S.Nodes) do begin
    Put(S.Nodes[I].Id);Put(S.Nodes[I].Kind);Put(S.Nodes[I].Span);
    Put(S.Nodes[I].Generation);Put(S.Nodes[I].OwnerId);
    Put(S.Nodes[I].OwnerGeneration);Put(Ord(S.Nodes[I].Alive));
  end;
  for I:=0 to High(S.Edges) do begin
    Put(S.Edges[I].SourceId);Put(S.Edges[I].SourceGeneration);
    Put(S.Edges[I].TargetId);Put(S.Edges[I].TargetGeneration);
    Put(S.Edges[I].Offset);Put(S.Edges[I].Width);
  end;
end;
function SameNodeShape(const A,B:TCozyOwnedPointerNode):Boolean;
begin
  Result:=(A.Id=B.Id) and (A.Kind=B.Kind) and (A.Span=B.Span) and
    (A.OwnerId=B.OwnerId) and (A.OwnerGeneration=B.OwnerGeneration);
end;
function SameOutgoing(const A,B:TCozyOwnedPointerEdges;Id:Cardinal):Boolean;
var I,J:Integer;
begin
  I:=0;J:=0;
  while (I<Length(A)) and (A[I].SourceId<Id) do Inc(I);
  while (J<Length(B)) and (B[J].SourceId<Id) do Inc(J);
  while (I<Length(A)) and (A[I].SourceId=Id) do begin
    if (J>=Length(B)) or (B[J].SourceId<>Id) then Exit(False);
    if (A[I].SourceGeneration<>B[J].SourceGeneration) or
      (A[I].TargetId<>B[J].TargetId) or (A[I].TargetGeneration<>B[J].TargetGeneration) or
      (A[I].Offset<>B[J].Offset) or (A[I].Width<>B[J].Width) then Exit(False);
    Inc(I);Inc(J);
  end;
  Result:=(J>=Length(B)) or (B[J].SourceId<>Id);
end;
procedure CozyPointerGraphTransition(const Previous,Next:TCozyPointerSnapshot;
  const Changes:TCozyPointerChanges);
var P,N:TCozyPointerSnapshot; I,J,ChangeIndex:Integer; Live,Depth:Cardinal;
  Bytes:TBytes; Used:array of Boolean;
  procedure Change(Kind:TCozyPointerChangeKind;Id:Cardinal);
  var C,K:Integer;
  begin
    C:=-1;
    for K:=0 to High(Changes) do if Changes[K].NodeId=Id then C:=K;
    TransitionRequire((C>=0) and (Changes[C].Kind=Kind)); Used[C]:=True;
  end;
begin
  TransitionRequire(Length(Changes)<=CozyPointerGraphMaxNodes);
  Bytes:=CozyOwnedPointerGraphBytes(Next,Live,Depth); Require(Length(Bytes)>0); Bytes:=nil;
  if Previous.Revision=0 then
    TransitionRequire((Length(Previous.Nodes)=0) and (Length(Previous.Edges)=0) and
      (Previous.RootId=0) and (Previous.RootGeneration=0))
  else begin
    Bytes:=CozyOwnedPointerGraphBytes(Previous,Live,Depth);
    Require(Length(Bytes)>0);Bytes:=nil;
    TransitionRequire(Previous.RootId=Next.RootId);
  end;
  P:=CloneSnapshot(Previous);N:=CloneSnapshot(Next);SortSnapshot(P);SortSnapshot(N);
  TransitionRequire((P.Revision<High(UInt64)) and (N.Revision=P.Revision+1));
  SetLength(Used,Length(Changes));
  for I:=0 to High(Changes) do begin
    TransitionRequire((Ord(Changes[I].Kind)>=Ord(Low(TCozyPointerChangeKind))) and
      (Ord(Changes[I].Kind)<=Ord(High(TCozyPointerChangeKind))));
    TransitionRequire(FindOwnedNode(N.Nodes,Changes[I].NodeId)>=0);
    for J:=0 to I-1 do TransitionRequire(Changes[J].NodeId<>Changes[I].NodeId);
  end;
  for I:=0 to High(P.Nodes) do TransitionRequire(FindOwnedNode(N.Nodes,P.Nodes[I].Id)>=0);
  for I:=0 to High(N.Nodes) do begin
    J:=FindOwnedNode(P.Nodes,N.Nodes[I].Id);
    if J<0 then begin
      TransitionRequire(N.Nodes[I].Alive and (N.Nodes[I].Generation=1));
      Change(pcRegister,N.Nodes[I].Id);
    end else if not P.Nodes[J].Alive then begin
      if N.Nodes[I].Alive then begin
        TransitionRequire((P.Nodes[J].Generation<High(Cardinal)) and
          (N.Nodes[I].Generation=P.Nodes[J].Generation+1));
        Change(pcReregister,N.Nodes[I].Id);
      end else TransitionRequire(SameNodeShape(P.Nodes[J],N.Nodes[I]) and
        (P.Nodes[J].Generation=N.Nodes[I].Generation));
    end else begin
      TransitionRequire(SameNodeShape(P.Nodes[J],N.Nodes[I]) and
        (P.Nodes[J].Generation=N.Nodes[I].Generation));
      if not N.Nodes[I].Alive then Change(pcRetire,N.Nodes[I].Id)
      else if not SameOutgoing(P.Edges,N.Edges,N.Nodes[I].Id) then
        Change(pcRebind,N.Nodes[I].Id);
    end;
  end;
  for ChangeIndex:=0 to High(Used) do TransitionRequire(Used[ChangeIndex]);
end;
function TCozyPointerGraphHistory.Accept(const Next:TCozyPointerSnapshot;
  const Changes:TCozyPointerChanges):TBytes;
var Live,Depth:Cardinal; Candidate:TCozyPointerSnapshot;
begin
  { Capture before validation so callers cannot mutate our retained arrays. }
  Require((Length(Next.Nodes)>0) and (Length(Next.Nodes)<=CozyPointerGraphMaxNodes) and
    (Length(Next.Edges)<=CozyPointerGraphMaxEdges));
  Candidate:=CloneSnapshot(Next);
  CozyPointerGraphTransition(FSnapshot,Candidate,Changes);
  Result:=CozyOwnedPointerGraphBytes(Candidate,Live,Depth);
  FSnapshot:=Candidate;
end;
function TCozyPointerGraphHistory.Capture:TCozyPointerSnapshot;
begin
  Result:=CloneSnapshot(FSnapshot);
end;
end.
