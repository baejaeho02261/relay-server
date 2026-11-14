{ Opt-in V2 lifecycle/cyclic contracts. Run by Cozy.PointerGraphProbe on Windows. }
function OwnedGraphSample: TCozyPointerSnapshot;
var I: Integer;
begin
  Result:=Default(TCozyPointerSnapshot);Result.Revision:=1;
  Result.RootId:=10;Result.RootGeneration:=1;SetLength(Result.Nodes,3);SetLength(Result.Edges,3);
  for I:=0 to 2 do begin
    Result.Nodes[I].Id:=Cardinal((I+1)*10);Result.Nodes[I].Kind:=Cardinal(I+1);
    Result.Nodes[I].Span:=16;Result.Nodes[I].Generation:=1;Result.Nodes[I].Alive:=True;
    if I>0 then begin Result.Nodes[I].OwnerId:=Cardinal(I*10);Result.Nodes[I].OwnerGeneration:=1;end;
    Result.Edges[I].SourceId:=Result.Nodes[I].Id;Result.Edges[I].SourceGeneration:=1;
    Result.Edges[I].TargetId:=Cardinal(((I+1) mod 3+1)*10);Result.Edges[I].TargetGeneration:=1;
    Result.Edges[I].Width:=8;
  end;
  Result.Nodes[2].Span:=8;
end;
function OwnedGraphChanges(Kind:TCozyPointerChangeKind;
  const Ids:array of Cardinal):TCozyPointerChanges;
var I:Integer;
begin
  SetLength(Result,Length(Ids));
  for I:=0 to High(Ids) do begin Result[I].NodeId:=Ids[I];Result[I].Kind:=Kind;end;
end;
function OwnedGraphClone(const S:TCozyPointerSnapshot):TCozyPointerSnapshot;
begin Result:=S;Result.Nodes:=Copy(S.Nodes,0,Length(S.Nodes));Result.Edges:=Copy(S.Edges,0,Length(S.Edges));end;
function OwnedGraphRejected(const S:TCozyPointerSnapshot):Boolean;
var B:TBytes;Live,Depth:Cardinal;
begin
  Result:=False;
  try B:=CozyOwnedPointerGraphBytes(S,Live,Depth);Check(Length(B)>0);
  except on E:EArgumentException do Result:=True;end;
end;
procedure OwnedGraphTransitionRejected(History:TCozyPointerGraphHistory;
  const S:TCozyPointerSnapshot;const Changes:TCozyPointerChanges);
var B,BeforeBytes,AfterBytes:TBytes;Before,After:TCozyPointerSnapshot;
  Live,Depth:Cardinal;Failed:Boolean;
begin
  Before:=History.Capture;
  if Before.Revision>0 then BeforeBytes:=CozyOwnedPointerGraphBytes(Before,Live,Depth);
  Failed:=False;
  try B:=History.Accept(S,Changes);Check(Length(B)>0);
  except on E:EArgumentException do Failed:=True;end;
  Check(Failed);After:=History.Capture;Check(Before.Revision=After.Revision);
  if Before.Revision>0 then begin
    AfterBytes:=CozyOwnedPointerGraphBytes(After,Live,Depth);
    Check((Length(BeforeBytes)=Length(AfterBytes)) and
      CompareMem(@BeforeBytes[0],@AfterBytes[0],Length(BeforeBytes)));
  end;
end;
procedure RunPointerLifecycleContracts;
var S,N,Saved:TCozyPointerSnapshot;H:TCozyPointerGraphHistory;B,Golden:TBytes;
  C:TCozyPointerChanges;Node:TCozyOwnedPointerNode;Edge:TCozyOwnedPointerEdge;
  Live,Depth:Cardinal;I:Integer;
begin
  S:=OwnedGraphSample;Golden:=CozyOwnedPointerGraphBytes(S,Live,Depth);
  Check((Live=3) and (Depth=2) and (Length(Golden)=212));
  Check(SHA512Bytes(Golden)=CozyText_PointerGraphLifecycleContracts_Digest_bad5dbb5);
  Node:=S.Nodes[0];S.Nodes[0]:=S.Nodes[2];S.Nodes[2]:=Node;
  Edge:=S.Edges[0];S.Edges[0]:=S.Edges[2];S.Edges[2]:=Edge;
  B:=CozyOwnedPointerGraphBytes(S,Live,Depth);
  Check((Length(B)=Length(Golden)) and CompareMem(@B[0],@Golden[0],Length(B)));
  for I:=1 to 13 do begin
    N:=OwnedGraphSample;
    case I of
      1:N.Nodes[1].Id:=10;
      2:N.Edges[0].TargetId:=99;
      3:N.Edges[0].TargetGeneration:=2;
      4:N.Edges[0].SourceGeneration:=2;
      5:N.Nodes[1].Alive:=False;
      6:N.Nodes[2].OwnerGeneration:=2;
      7:begin N.Nodes[0].OwnerId:=30;N.Nodes[0].OwnerGeneration:=1;end;
      8:begin N.Edges[1]:=N.Edges[2];SetLength(N.Edges,2);end;
      9:begin SetLength(N.Edges,4);N.Edges[3]:=N.Edges[0];N.Edges[3].Offset:=4;end;
      10:N.Edges[0].Offset:=High(Cardinal);
      11:N.Edges[0].Width:=16;
      12:N.Revision:=0;
      13:N.RootId:=0;
    end;
    Check(OwnedGraphRejected(N));
  end;
  H:=TCozyPointerGraphHistory.Create;
  try
    S:=OwnedGraphSample;OwnedGraphTransitionRejected(H,S,nil);
    B:=H.Accept(S,OwnedGraphChanges(pcRegister,[10,20,30]));Check(Length(B)=212);
    { Neither caller input nor Capture aliases the retained arrays. }
    S.Nodes[0].Generation:=50;Saved:=H.Capture;Saved.Nodes[0].Alive:=False;
    Saved:=H.Capture;Check(Saved.Nodes[0].Alive and (Saved.Nodes[0].Generation=1));
    N:=OwnedGraphSample;N.Revision:=2;N.Nodes[1].Alive:=False;N.Nodes[2].Alive:=False;N.Edges:=nil;
    OwnedGraphTransitionRejected(H,N,OwnedGraphChanges(pcRetire,[20,30]));
    C:=OwnedGraphChanges(pcRetire,[20,30,10]);C[2].Kind:=pcRebind;
    B:=H.Accept(N,C);Check(Length(B)>0);
    { Tombstones persist over idle snapshots and cannot disappear. }
    N:=H.Capture;N.Revision:=3;B:=H.Accept(N,nil);Check(Length(B)>0);
    N:=H.Capture;N.Revision:=4;SetLength(N.Nodes,1);OwnedGraphTransitionRejected(H,N,nil);
    N:=OwnedGraphSample;N.Revision:=4;C:=OwnedGraphChanges(pcReregister,[20,30,10]);C[2].Kind:=pcRebind;
    OwnedGraphTransitionRejected(H,N,C);
    N.Nodes[1].Generation:=2;N.Nodes[2].Generation:=2;N.Nodes[2].OwnerGeneration:=2;
    for I:=0 to High(N.Edges) do begin
      if N.Edges[I].SourceId<>10 then N.Edges[I].SourceGeneration:=2;
      if N.Edges[I].TargetId<>10 then N.Edges[I].TargetGeneration:=2;
    end;
    B:=H.Accept(N,C);Check(Length(B)>0);
    N:=H.Capture;N.Revision:=5;
    OwnedGraphTransitionRejected(H,N,OwnedGraphChanges(pcRebind,[10]));
    B:=H.Accept(N,nil);Check(Length(B)>0);
    N:=H.Capture;N.Revision:=7;OwnedGraphTransitionRejected(H,N,nil);
  finally H.Free;end;
  { Maximum permitted references may form a ring; no recursive cycle walk. }
  S:=Default(TCozyPointerSnapshot);S.Revision:=1;S.RootId:=1;S.RootGeneration:=1;
  SetLength(S.Nodes,4096);SetLength(S.Edges,4096);
  for I:=0 to 4095 do begin
    S.Nodes[I].Id:=Cardinal(I+1);S.Nodes[I].Kind:=1;S.Nodes[I].Span:=8;
    S.Nodes[I].Generation:=1;S.Nodes[I].Alive:=True;
    if I>0 then begin S.Nodes[I].OwnerId:=1;S.Nodes[I].OwnerGeneration:=1;end;
    S.Edges[I].SourceId:=Cardinal(I+1);S.Edges[I].SourceGeneration:=1;
    S.Edges[I].TargetId:=Cardinal((I+1) mod 4096+1);S.Edges[I].TargetGeneration:=1;S.Edges[I].Width:=8;
  end;
  B:=CozyOwnedPointerGraphBytes(S,Live,Depth);Check((Live=4096) and (Depth=1) and (Length(B)=213048));
  SetLength(S.Nodes,4097);Check(OwnedGraphRejected(S));
  { Ownership itself must stay a bounded acyclic tree rooted in RootId. }
  S:=Default(TCozyPointerSnapshot);S.Revision:=1;S.RootId:=1;S.RootGeneration:=1;
  SetLength(S.Nodes,18);SetLength(S.Edges,17);
  for I:=0 to 17 do begin
    S.Nodes[I].Id:=Cardinal(I+1);S.Nodes[I].Kind:=1;S.Nodes[I].Span:=8;
    S.Nodes[I].Generation:=1;S.Nodes[I].Alive:=True;
    if I>0 then begin S.Nodes[I].OwnerId:=Cardinal(I);S.Nodes[I].OwnerGeneration:=1;end;
    if I<17 then begin
      S.Edges[I].SourceId:=Cardinal(I+1);S.Edges[I].SourceGeneration:=1;
      S.Edges[I].TargetId:=Cardinal(I+2);S.Edges[I].TargetGeneration:=1;S.Edges[I].Width:=8;
    end;
  end;
  Check(OwnedGraphRejected(S));SetLength(S.Nodes,17);SetLength(S.Edges,16);
  B:=CozyOwnedPointerGraphBytes(S,Live,Depth);Check((Depth=16) and (Length(B)>0));
end;
