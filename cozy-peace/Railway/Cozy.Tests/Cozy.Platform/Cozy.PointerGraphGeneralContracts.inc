{ Native V1 registered-DAG checks. No address scanning or dereferencing.
  Golden bytes were serialized independently with little-endian uint32 fields;
  SHA-512 and bitwise CRC-64/ECMA are checked by the server-side companion test.
  V1 rejects reference cycles; the separate V2 lifecycle suite permits them. }
procedure GeneralGraphSample(out N: TCozyPointerNodes; out E: TCozyPointerEdges);
var K: Integer;
  procedure EdgeAt(Index: Integer; Source, Target, Offset, Width: Cardinal);
  begin
    E[Index].SourceId := Source; E[Index].TargetId := Target;
    E[Index].Offset := Offset; E[Index].Width := Width;
  end;
begin
  SetLength(N, 4); SetLength(E, 4);
  for K := 0 to 3 do
  begin
    N[K].Id := Cardinal(K + 1); N[K].Kind := Cardinal(K + 1);
    N[K].Generation := 7; N[K].Alive := True;
  end;
  N[0].Span := 24; N[1].Span := 12; N[2].Span := 16; N[3].Span := 1;
  { Shared target 4, internal offsets, mixed pointer widths, exact span ends. }
  EdgeAt(0, 1, 2, 4, 4); EdgeAt(1, 1, 3, 16, 8);
  EdgeAt(2, 2, 4, 4, 8); EdgeAt(3, 3, 4, 12, 4);
end;
procedure GeneralGraphChain(Levels: Integer; out N: TCozyPointerNodes;
  out E: TCozyPointerEdges);
var K: Integer;
begin
  SetLength(N, Levels + 1); SetLength(E, Levels);
  for K := 0 to Levels do
  begin
    N[K].Id := Cardinal(K + 1); N[K].Kind := 1; N[K].Span := 8;
    N[K].Generation := 1; N[K].Alive := True;
    if K < Levels then
    begin
      E[K].SourceId := Cardinal(K + 1); E[K].TargetId := Cardinal(K + 2);
      E[K].Offset := 0; E[K].Width := 8;
    end;
  end;
end;
procedure GeneralCachedDepthGraph(ChainNodes: Integer; out N: TCozyPointerNodes;
  out E: TCozyPointerEdges);
var K, At: Integer;
  procedure Edge(Source, Target, Offset: Cardinal);
  begin
    E[At].SourceId := Source; E[At].TargetId := Target;
    E[At].Offset := Offset; E[At].Width := 8; Inc(At);
  end;
begin
  SetLength(N, 4 + ChainNodes); SetLength(E, 4 + ChainNodes); At := 0;
  for K := 0 to High(N) do
  begin
    N[K].Id := Cardinal(K + 1); N[K].Kind := 1; N[K].Span := 8;
    N[K].Generation := 1; N[K].Alive := True;
  end;
  N[0].Span := 16;
  { Visit tail 2->3->4 first, then reach that cached tail by a deeper branch. }
  Edge(1, 2, 0); Edge(1, 5, 8); Edge(2, 3, 0); Edge(3, 4, 0);
  for K := 5 to Length(N) - 1 do Edge(Cardinal(K), Cardinal(K + 1), 0);
  Edge(Cardinal(Length(N)), 2, 0);
end;
function RunGeneralPointerGraphContracts: Integer;
const
  GeneralSHA512 = CozyText_PointerGraphGeneralContracts_Digest_8d97eb57;
  GeneralCRC64 = CozyText_PointerGraphGeneralContracts_DA98C7AAAA10F742_e5e1f961;
var N: TCozyPointerNodes; E: TCozyPointerEdges; B: TBytes;
  D: Cardinal; K, Cases: Integer; Saved: TCozyPointerEdge;
  procedure RequireCase(Value: Boolean; const Name: string);
  begin
    if not Value then raise EInvalidOpException.Create(CozyText_PointerGraphGeneralContracts_GENERAL_GRAPH_9a6e86ca + Name);
  end;
  procedure Accept(ExpectedDepth: Cardinal; const Name: string);
  begin
    B := CozyPointerGraphBytes(N, E, D);
    RequireCase((Length(B) > 0) and (D = ExpectedDepth), Name); Inc(Cases);
  end;
  procedure Reject(const Name: string);
  var Unexpected: TBytes; ObservedDepth: Cardinal;
  begin
    try Unexpected := CozyPointerGraphBytes(N, E, ObservedDepth);
    except on Ex: EArgumentException do begin Inc(Cases); Exit; end; end;
    raise EInvalidOpException.Create(CozyText_PointerGraphGeneralContracts_GENERAL_GRAPH_9a6e86ca + Name +
      CozyText_PointerGraphGeneralContracts_ACCEPTED_DEPTH_71ec9588 + UIntToStr(ObservedDepth) +
      CozyText_PointerGraphGeneralContracts_BYTES_ae835201 + IntToStr(Length(Unexpected)));
  end;
begin
  Cases := 0;
  GeneralGraphSample(N, E); Accept(2, CozyText_PointerGraphGeneralContracts_SHARED_DAG_fce8fd5b);
  RequireCase((Length(B) = 178) and (SHA512Bytes(B) = GeneralSHA512) and
    (CrcBytes(ckEcma182, B) = GeneralCRC64), CozyText_PointerGraphGeneralContracts_INDEPENDENT_GOLDEN_1e3c12d9); Inc(Cases);
  for K := 1 to 21 do
  begin
    GeneralGraphSample(N, E);
    case K of
      1: N[0].Generation := 0;
      2: N[3].Generation := 8;
      3: N[2].Id := 2;
      4: N[2].Alive := False;
      5: N[2].Kind := 0;
      6: N[2].Kind := 17;
      7: N[2].Span := 0;
      8: N[2].Span := 1048577;
      9: E[0].SourceId := 0;
      10: E[0].SourceId := 5;
      11: E[0].TargetId := 0;
      12: E[0].TargetId := 5;
      13: E[0].Width := 0;
      14: E[0].Width := 16;
      15: E[1].Offset := 17;
      16: E[1].Offset := High(Cardinal);
      17: E[1].Offset := 6;
      18: begin Saved := E[0]; E[0] := E[1]; E[1] := Saved; end;
      19: E[1].TargetId := 1;
      20: E[2].TargetId := 1;
      21: E[1].TargetId := 2;
    end;
    Reject(CozyText_PointerGraphGeneralContracts_MUTATION_e92f5e7d + IntToStr(K));
  end;
  GeneralGraphSample(N, E);
  for K := 0 to High(N) do N[K].Generation := High(Cardinal);
  N[3].Kind := 16; Accept(2, CozyText_PointerGraphGeneralContracts_MAX_GENERATION_KIND_650273f9);
  GeneralGraphSample(N, E); N[0].Span := 1048576;
  E[1].Offset := 1048568; Accept(2, CozyText_PointerGraphGeneralContracts_MAX_SPAN_EXACT_END_3647abe1);
  GeneralGraphChain(0, N, E); Accept(0, CozyText_PointerGraphGeneralContracts_SINGLE_NODE_517dcfd6);
  GeneralGraphChain(16, N, E); Accept(16, CozyText_PointerGraphGeneralContracts_DEPTH_16_ffad80e6);
  GeneralGraphChain(17, N, E); Reject(CozyText_PointerGraphGeneralContracts_DEPTH_17_f45074fa);
  GeneralCachedDepthGraph(13, N, E); Accept(16, CozyText_PointerGraphGeneralContracts_CACHED_SHARED_DEPTH_16_bce4bfa3);
  GeneralCachedDepthGraph(14, N, E); Reject(CozyText_PointerGraphGeneralContracts_CACHED_SHARED_DEPTH_17_bbbbab56);
  SetLength(N, CozyPointerGraphMaxNodes); SetLength(E, CozyPointerGraphMaxEdges);
  for K := 0 to High(N) do
  begin
    N[K].Id := Cardinal(K + 1); N[K].Kind := 1; N[K].Span := 1;
    N[K].Generation := 1; N[K].Alive := True;
  end;
  N[0].Span := Cardinal(Length(E) * 4);
  for K := 0 to High(E) do
  begin
    E[K].SourceId := 1; E[K].TargetId := Cardinal(K + 2);
    E[K].Offset := Cardinal(K * 4); E[K].Width := 4;
  end;
  E[High(E)].TargetId := 2; Accept(1, CozyText_PointerGraphGeneralContracts_MAX_NODES_EDGES_990b3aa4);
  SetLength(E, CozyPointerGraphMaxEdges + 1); Reject(CozyText_PointerGraphGeneralContracts_EDGES_OVER_LIMIT_81f8ef21);
  SetLength(E, CozyPointerGraphMaxEdges);
  SetLength(N, CozyPointerGraphMaxNodes + 1); Reject(CozyText_PointerGraphGeneralContracts_NODES_OVER_LIMIT_1e2e5110);
  N := nil; E := nil; Reject(CozyText_PointerGraphGeneralContracts_EMPTY_GRAPH_6b547d09);
  Result := Cases;
end;
