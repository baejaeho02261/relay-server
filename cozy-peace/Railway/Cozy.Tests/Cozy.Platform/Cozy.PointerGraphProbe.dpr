program Cozy_PointerGraphProbe;
{$APPTYPE CONSOLE}
{$IFNDEF COZY_POINTER_GRAPH_PROBE}{$MESSAGE FATAL 'Test-only define required'}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
 Winapi.Windows, System.SysUtils, Cozy.PointerGraph, Cozy.Api.Pointer,
  Cozy.Hashes, Cozy.CrcLayers;
var Slots: array[0..1] of TEncodedApiPointer;
  Nodes: TCozyPointerNodes; Edges: TCozyPointerEdges;
  Bytes, Actual: TBytes; Depth, Count, I: Cardinal; Failed: Boolean;
procedure Check(Value: Boolean);
begin if not Value then raise Exception.Create(CozyText_PointerGraphProbe_POINTER_GRAPH_PROBE_FAILED_b03fe764);end;
{$I Cozy.PointerGraphLifecycleContracts.inc}
{$I Cozy.PointerGraphGeneralContracts.inc}
function Target: Cardinal; stdcall;
begin Result:=42;end;
function Encode(Value: Pointer): Pointer; stdcall;
begin Result:=Value;end;
function ReadError: Cardinal; stdcall;
begin Result:=Winapi.Windows.GetLastError;end;
procedure WriteError(Value: Cardinal); stdcall;
begin Winapi.Windows.SetLastError(Value);end;
begin
 try
  CozyApiGraphShape(2,Nodes,Edges); Bytes:=CozyPointerGraphBytes(Nodes,Edges,Depth);
  Check(Depth=3);
  Check(SHA512Bytes(Bytes)=CozyText_PointerGraphProbe_Digest_edebee38);
  Check(CrcBytes(ckEcma182,Bytes)=CozyText_PointerGraphProbe_BAE913D72444431A_8356981f);
  Edges[High(Edges)].TargetId:=1; Failed:=False;
  try Actual:=CozyPointerGraphBytes(Nodes,Edges,Depth);except on E:EArgumentException do Failed:=True;end;Check(Failed);
  CozyApiGraphShape(2,Nodes,Edges); Nodes[1].Alive:=False;Failed:=False;
  try Actual:=CozyPointerGraphBytes(Nodes,Edges,Depth);except on E:EArgumentException do Failed:=True;end;Check(Failed);
  InitializeApiPointerCodec(@Encode,@Encode,@ReadError,@WriteError);
  ConfigureApiPointerStorage(@Winapi.Windows.VirtualAlloc,@Winapi.Windows.VirtualProtect,
    @Winapi.Windows.VirtualFree,@Winapi.Windows.VirtualQuery);
  BindApiPointer(Slots[0],@Target);BindApiPointer(Slots[1],@Target);
  SealApiPointerStorage;
  Actual:=CaptureApiPointerGraph(Count,Depth);
  Check((Count=2) and (Depth=3) and (Length(Actual)=Length(Bytes)));
  Check(CompareMem(@Actual[0],@Bytes[0],Length(Bytes)));
  for I:=1 to 5 do begin
    Check(ProbeApiPointerGraphRejects(I));
    Actual:=CaptureApiPointerGraph(Count,Depth);
    Check((Count=2) and CompareMem(@Actual[0],@Bytes[0],Length(Bytes)));
  end;
  Writeln(CozyText_PointerGraphProbe_PASS_V1_registered_general_DAG_boundary_cases_a30275b0, RunGeneralPointerGraphContracts);
  RunPointerLifecycleContracts;
  Writeln(CozyText_PointerGraphProbe_PASS_owned_pointer_graph_V1_arena_and_V2_explici_7ec89dcd);
 except on E:Exception do begin Writeln(CozyText_PointerGraphProbe_FAIL_owned_pointer_graph_probe_4995fc46);ExitCode:=1;end;end;
end.
