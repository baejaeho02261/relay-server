program Cozy_ServerOperationsProtocolProbe;
{$APPTYPE CONSOLE}
{$B-}
uses
{ Cozy central text imports. }
  Cozy.Strings.Application in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Application.pas',
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Identity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Identity.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Overlay in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Overlay.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Protection in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Protection.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
{$IF (Defined(GAME_HANDOFF_CONTRACT_TESTS))}
  Cozy.Strings.TestsHandoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsHandoff.pas',
{$ENDIF}
{$IF (Defined(GAME_DEVICE_IDENTITY_PROBE))}
  Cozy.Strings.TestsIdentity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsIdentity.pas',
{$ENDIF}
{$IF ((Defined(GAME_RELAY_SOCKET_CONTRACT_TESTS))) or (((Defined(GAME_NATIVE_ABI_TESTS))) or ((Defined(GAME_TLS_CONTRACT_TESTS))))}
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$ENDIF}
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
  Cozy.Strings.TestsSecurity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsSecurity.pas',
 System.SysUtils, Cozy.Integrity, Cozy.Api.Types, Cozy.ServerOperations,
  Cozy.ServerOperations.Example;
const
  ArgsDigest = CozyText_ServerOperationsProtocolProbe_Digest_f2ab4822;
  BindingDigest = CozyText_ServerOperationsProtocolProbe_Digest_c67072c0;
  CanonicalDigest = CozyText_ServerOperationsProtocolProbe_Digest_aa6d774f;
  RequestID = CozyText_ServerOperationsProtocolProbe_11111111_2222_3333_4444_555555555555_f2305a96;
{$I Cozy.ServerOperationsProtocolVectors.inc}
var ArgsText, Binding, Canonical: string; Challenge: TServerOperationChallenge;
  Rejected: Boolean;
procedure Require(Value: Boolean);
begin
  if not Value then raise EInvalidOpException.Create(CozyText_ServerOperationsProtocolProbe_PROTOCOL_VECTOR_MISMATCH_92907ec3);
end;
function StandardChallenge: TServerOperationChallenge;
begin
  Result.ChallengeID := StringOfChar('1', 48);
  Result.Nonce := StringOfChar('2', 48); Result.Epoch := StringOfChar('3', 48);
  Result.Revision := 0; Result.OperationsRevision := 0;
  Result.ExpiresAt := 1790000000000;
end;
function ArgumentsFor(VariantIndex: Integer): TArray<Integer>;
begin
  case VariantIndex of
    0: Result := nil;
    1: begin
      SetLength(Result, 3); Result[0] := Low(Integer); Result[1] := 0;
      Result[2] := High(Integer);
    end;
    2: begin
      SetLength(Result, 8); Result[0] := Low(Integer); Result[1] := -1;
      Result[2] := 0; Result[3] := 1; Result[4] := 2; Result[5] := 3;
      Result[6] := 7; Result[7] := High(Integer);
    end;
  else
    raise EArgumentException.Create(CozyText_ServerOperationsProtocolProbe_UNKNOWN_PUBLIC_TEST_VECTOR_3fe78ec7);
  end;
end;
procedure RunRoleVectors;
var I: Integer; Inputs: TArray<Integer>; ArgsHash, Bound, Text: string;
  C: TServerOperationChallenge;
begin
  C := StandardChallenge;
  for I := Low(OperationVectors) to High(OperationVectors) do
  begin
    Inputs := ArgumentsFor(OperationVectors[I].ArgsVariant);
    try
      ArgsHash := IntegritySHA512Text(ServerOperationArgsJSON(Inputs));
      Require(ArgsHash = OperationVectors[I].ArgsSHA512);
      Bound := ServerOperationBinding(OperationVectors[I].Stage, StringOfChar('A',24),
        StringOfChar('B',64), StringOfChar('c',64), RequestID,
        OperationVectors[I].FunctionID, ArgsHash);
      Require(Bound = OperationVectors[I].BindingSHA512);
      Text := ServerOperationCanonical(OperationVectors[I].Stage, StringOfChar('A',24),
        StringOfChar('B',64), StringOfChar('c',64), RequestID,
        OperationVectors[I].FunctionID, ArgsHash, Bound, C);
      Require(IntegritySHA512Text(Text) = OperationVectors[I].CanonicalSHA512);
    finally ClearServerOperationArgs(Inputs); end;
  end;
end;
procedure RunTranscriptMutations;
var I: Integer; Stage, Session, Machine, Policy, Request, ArgsHash, Bound, Text: string;
  FunctionID: Word; C: TServerOperationChallenge;
begin
  for I := Low(OperationMutations) to High(OperationMutations) do
  begin
    Stage := 'B'; Session := StringOfChar('A',24); Machine := StringOfChar('B',64);
    Policy := StringOfChar('c',64); Request := RequestID;
    FunctionID := 2; ArgsHash := ArgsDigest; C := StandardChallenge;
    case I of
      0: Stage := 'A';
      1: Stage := 'O';
      2: Session := StringOfChar('C',24);
      3: Machine := StringOfChar('D',64);
      4: Policy := StringOfChar('e',64);
      5: Request := CozyText_ServerOperationsProtocolProbe_changed_request_07c2ea14;
      6: FunctionID := 65535;
      7: ArgsHash := IntegritySHA512Text(ServerOperationArgsJSON([]));
      8: C.ChallengeID := StringOfChar('4',48);
      9: C.Nonce := StringOfChar('5',48);
      10: C.Epoch := StringOfChar('6',48);
      11: C.Revision := 1;
      12: C.OperationsRevision := 1;
      13: C.ExpiresAt := 1790000000001;
    end;
    Bound := ServerOperationBinding(Stage, Session, Machine, Policy, Request, FunctionID, ArgsHash);
    Require(Bound = OperationMutations[I].BindingSHA512);
    Text := ServerOperationCanonical(Stage, Session, Machine, Policy, Request, FunctionID, ArgsHash, Bound, C);
    Require(IntegritySHA512Text(Text) = OperationMutations[I].CanonicalSHA512);
    Require(IntegritySHA512Text(Text) <> CanonicalDigest);
  end;
end;
procedure RunBindingRejections;
var I: Integer; Stage, Session, Machine, Policy, Request, ArgsHash: string;
  FunctionID: Word; Failed: Boolean;
begin
  for I := 0 to 24 do
  begin
    Stage := 'B'; Session := StringOfChar('A',24); Machine := StringOfChar('B',64);
    Policy := StringOfChar('c',64); Request := RequestID; FunctionID := 2; ArgsHash := ArgsDigest;
    case I of
      0: Stage := '';
      1: Stage := 'b';
      2: Stage := 'X';
      3: Stage := 'B' + #10;
      4: Session := StringOfChar('a',24);
      5: Session := StringOfChar('A',23);
      6: Session := StringOfChar('A',25);
      7: Session := Session + #13;
      8: Machine := StringOfChar('b',64);
      9: Machine := StringOfChar('B',63);
      10: Machine := Machine + #10;
      11: Policy := StringOfChar('C',64);
      12: Policy := StringOfChar('c',63);
      13: Policy := Policy + #0;
      14: Request := StringOfChar('a',7);
      15: Request := StringOfChar('a',81);
      16: Request := CozyText_ServerOperationsProtocolProbe_valid_id_6cb07c6b + #10;
      17: Request := CozyText_ServerOperationsProtocolProbe_valid_082f08bf + #0 + CozyText_ServerOperationsProtocolProbe_id_6e846bb4;
      18: Request := CozyText_ServerOperationsProtocolProbe_valid_id_da3e8ced;
      19: Request := CozyText_ServerOperationsProtocolProbe_valid_082f08bf + WideChar($D55C) + CozyText_ServerOperationsProtocolProbe_id_6e846bb4;
      20: FunctionID := 0;
      21: FunctionID := 1;
      22: ArgsHash := Copy(ArgsDigest,1,127);
      23: ArgsHash := UpperCase(ArgsDigest);
      24: ArgsHash := ArgsDigest + #10;
    end;
    Failed := False;
    try ServerOperationBinding(Stage, Session, Machine, Policy, Request, FunctionID, ArgsHash);
    except on E: EGameApi do Failed := True; end;
    Require(Failed);
  end;
  for I := 0 to 1 do
  begin
    if I = 0 then Request := StringOfChar('a',8) else Request := StringOfChar('_',80);
    Require(Length(ServerOperationBinding('A',StringOfChar('A',24),StringOfChar('B',64),
      StringOfChar('c',64),Request,65535,ArgsDigest))=128);
  end;
end;
procedure RunChallengeRejections;
var I: Integer; C: TServerOperationChallenge; Bound: string; Failed: Boolean;
begin
  for I := 0 to 16 do
  begin
    C := StandardChallenge; Bound := BindingDigest;
    case I of
      0: C.ChallengeID := StringOfChar('1',47);
      1: C.ChallengeID := C.ChallengeID + #10;
      2: C.ChallengeID := StringOfChar('A',48);
      3: C.Nonce := StringOfChar('2',49);
      4: C.Nonce := StringOfChar('G',48);
      5: C.Epoch := StringOfChar('3',47);
      6: C.Epoch := C.Epoch + #0;
      7: C.Revision := -1;
      8: C.Revision := 9007199254740992;
      9: C.OperationsRevision := -1;
      10: C.OperationsRevision := 9007199254740992;
      11: C.ExpiresAt := 0;
      12: C.ExpiresAt := -1;
      13: C.ExpiresAt := 9007199254740992;
      14: Bound := StringOfChar('0',128);
      15: Bound := Copy(BindingDigest,1,127);
      16: Bound := UpperCase(BindingDigest);
    end;
    Failed := False;
    try ServerOperationCanonical('B',StringOfChar('A',24),StringOfChar('B',64),
      StringOfChar('c',64),RequestID,2,ArgsDigest,Bound,C);
    except on E: EGameApi do Failed := True; end;
    Require(Failed);
  end;
  C := StandardChallenge; C.Revision := 9007199254740991;
  C.OperationsRevision := 9007199254740991; C.ExpiresAt := 9007199254740991;
  Require(Length(ServerOperationCanonical('B',StringOfChar('A',24),StringOfChar('B',64),
    StringOfChar('c',64),RequestID,2,ArgsDigest,BindingDigest,C))>0);
end;
procedure RunArgumentOwnership;
var Original, Snapshot: TArray<Integer>; Failed: Boolean;
begin
  Original := ArgumentsFor(2);
  Snapshot := SnapshotServerOperationArgs(65535,Original);
  try
    Require((Length(Snapshot)=8) and (Snapshot[0]=Low(Integer)));
    Original[0] := 17;
    Require((Snapshot[0]=Low(Integer)) and (Original[0]=17));
    ClearServerOperationArgs(Snapshot);
    Require((Length(Snapshot)=0) and (Original[0]=17));
  finally ClearServerOperationArgs(Snapshot); ClearServerOperationArgs(Original); end;
  Snapshot := SnapshotServerOperationArgs(2,[]);
  try Require(Length(Snapshot)=0); finally ClearServerOperationArgs(Snapshot); end;
  Failed := False;
  try Snapshot := SnapshotServerOperationArgs(1,[]);
  except on E: EGameApi do Failed := True; end;
  ClearServerOperationArgs(Snapshot); Require(Failed);
  Failed := False;
  try Snapshot := SnapshotServerOperationArgs(2,[1,2,3,4,5,6,7,8,9]);
  except on E: EGameApi do Failed := True; end;
  ClearServerOperationArgs(Snapshot); Require(Failed);
end;
begin
  { This probe performs no server connection, issuance or approval. Its success
    is encoding validation only, not a Windows product execution attestation. }
  try
    ArgsText := ServerOperationArgsJSON([-2147483648, 0, 2147483647]);
    Require(ArgsText = CozyText_ServerOperationsProtocolProbe_JsonFixture_4ae4c689);
    Require(IntegritySHA512Text(ArgsText) = ArgsDigest);
    Binding := ServerOperationBinding('B', StringOfChar('A', 24), StringOfChar('B', 64),
      StringOfChar('c', 64), RequestID, 2, ArgsDigest);
    Require(Binding = BindingDigest);
    Challenge.ChallengeID := StringOfChar('1', 48);
    Challenge.Nonce := StringOfChar('2', 48); Challenge.Epoch := StringOfChar('3', 48);
    Challenge.Revision := 0; Challenge.OperationsRevision := 0;
    Challenge.ExpiresAt := 1790000000000;
    Canonical := ServerOperationCanonical('B', StringOfChar('A', 24), StringOfChar('B', 64),
      StringOfChar('c', 64), RequestID, 2, ArgsDigest, Binding, Challenge);
    Require(IntegritySHA512Text(Canonical) = CanonicalDigest);
    Rejected := False;
    try ServerOperationArgsJSON([1,2,3,4,5,6,7,8,9]);
    except on E: EGameApi do Rejected := True; end;
    Require(Rejected);
    Rejected := False;
    try ServerOperationBinding('B', '', '', '', '', 1, '');
    except on E: EGameApi do Rejected := True; end;
    Require(Rejected);
    RunRoleVectors;
    RunTranscriptMutations;
    RunBindingRejections;
    RunChallengeRejections;
    RunArgumentOwnership;
    ExitCode := 0;
  except
    on E: Exception do ExitCode := 1;
  end;
end.
