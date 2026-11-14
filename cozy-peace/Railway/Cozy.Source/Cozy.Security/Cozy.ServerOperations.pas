unit Cozy.ServerOperations;

{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
{$IF SizeOf(Integer) <> 4}
  {$MESSAGE FATAL 'Server operations require signed 32-bit Integer.'}
{$ENDIF}

interface

uses
{ Cozy central text imports. }
  Cozy.Strings.Security,
 Cozy.Transport, Cozy.Security, Cozy.CodeIntegrity, Cozy.Integrity,
  Cozy.ServerAuthority, Cozy.OwnedRuntime;

type
  TServerOperationChallenge = record
    ChallengeID, Nonce, Epoch: string;
    Revision, OperationsRevision, ExpiresAt: Int64;
  end;

{ Public deterministic encodings shared with the server. They contain no
  operation implementation, policy program, key or local authorization. }
{ Callers snapshot before slow report work; the returned array has one owner.
  Clear the owned copy after the role lifetime gate has drained the call. }
function SnapshotServerOperationArgs(FunctionID: Word;
  const Args: array of Integer): TArray<Integer>;
procedure ClearServerOperationArgs(var Args: TArray<Integer>);
function ServerOperationArgsJSON(const Args: array of Integer): string;
function ServerOperationBinding(const Stage, SessionID, MachineID, PolicyID,
  RequestID: string; FunctionID: Word; const ArgsSHA512: string): string;
function ServerOperationCanonical(const Stage, SessionID, MachineID, PolicyID,
  RequestID: string; FunctionID: Word; const ArgsSHA512, Binding: string;
  const Challenge: TServerOperationChallenge): string;

{ Called through the A/B/O clients' lifetime gates after current integrity
  reporting. Function 1 is reserved. The server selects the artifact-bound
  private program and verifies authority again after queued signature proof.
  Never repeats invoke. A lost response permits one bounded result-only lookup
  using the original signed request; server authority is checked again.
  Role wrappers snapshot Args before slow integrity report refresh and retain
  borrowed context objects until the call drains; this procedure owns a second
  bounded snapshot while constructing and authenticating the V1 request. }
function InvokeCozyServerOperation(Transport: TConnectTransport;
  Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
  const Stage, SessionID, SessionToken, FileSHA512, FileCRC64: string;
  FunctionID: Word; const Args: array of Integer;
  const Cancelled: TAuthorityCancelled; OwnImage: TImageIntegrity;
  const Runtime: ICozyRuntimeMeasurement = nil): Integer;

implementation

uses System.SysUtils, System.JSON, System.Diagnostics, System.RegularExpressions,
  Cozy.Api.Types, Cozy.Api.Guid, Cozy.Protection.Engine;

const
  OperationDomain = CozyText_ServerOperations_COZY_SERVER_OPERATION_V1_86c494eb;
  OperationBudgetMs = 45000;

procedure Invalid;
begin
  raise EGameApi.Create(CozyText_ServerOperations_COZY_SERVER_OPERATION_RESPONSE_INVALID_842a3fd4, '');
end;

procedure ValidFunction(FunctionID: Word);
begin
  if FunctionID < 2 then
    raise EGameApi.Create(CozyText_ServerOperations_COZY_SERVER_OPERATION_FUNCTION_INVALID_3ccdcb22, '');
end;

procedure InputInvalid;
begin
  raise EGameApi.Create(CozyText_ServerOperations_COZY_SERVER_OPERATION_ARGUMENT_INVALID_fa040681, '');
end;

function IsHex(const Value: string; Count: Integer; UpperCase: Boolean): Boolean;
var I: Integer; C: Char;
begin
  Result := False;
  if Length(Value) <> Count then Exit;
  for I := 1 to Length(Value) do
  begin
    C := Value[I];
    if (C >= '0') and (C <= '9') then Continue;
    if UpperCase then
    begin if (C < 'A') or (C > 'F') then Exit; end
    else if (C < 'a') or (C > 'f') then Exit;
  end;
  Result := True;
end;

function IsRequestID(const Value: string): Boolean;
var I: Integer; C: Char;
begin
  Result := False;
  if (Length(Value) < 8) or (Length(Value) > 80) then Exit;
  for I := 1 to Length(Value) do
  begin
    C := Value[I];
    if not (((C >= 'A') and (C <= 'Z')) or
      ((C >= 'a') and (C <= 'z')) or ((C >= '0') and (C <= '9')) or
      (C = '-') or (C = '_')) then Exit;
  end;
  Result := True;
end;

procedure ValidateBindingFields(const Stage, SessionID, MachineID, PolicyID,
  RequestID: string; FunctionID: Word; const ArgsSHA512: string);
begin
  ValidFunction(FunctionID);
  if ((Stage <> 'A') and (Stage <> 'B') and (Stage <> 'O')) or
    not IsHex(SessionID, 24, True) or not IsHex(MachineID, 64, True) or
    not IsHex(PolicyID, 64, False) or not IsRequestID(RequestID) or
    not IsHex(ArgsSHA512, 128, False) then InputInvalid;
end;

procedure ValidateChallenge(const Challenge: TServerOperationChallenge);
begin
  if not IsHex(Challenge.ChallengeID, 48, False) or
    not IsHex(Challenge.Nonce, 48, False) or not IsHex(Challenge.Epoch, 48, False) or
    (Challenge.Revision < 0) or (Challenge.Revision > 9007199254740991) or
    (Challenge.OperationsRevision < 0) or
    (Challenge.OperationsRevision > 9007199254740991) or
    (Challenge.ExpiresAt < 1) or (Challenge.ExpiresAt > 9007199254740991) then
    InputInvalid;
end;

function SnapshotServerOperationArgs(FunctionID: Word;
  const Args: array of Integer): TArray<Integer>;
var I: Integer;
begin
  ValidFunction(FunctionID);
  if Length(Args) > 8 then InputInvalid;
  SetLength(Result, Length(Args));
  for I := 0 to High(Args) do Result[I] := Args[I];
end;

procedure ClearServerOperationArgs(var Args: TArray<Integer>);
begin
  if Length(Args) > 0 then FillChar(Args[0], Length(Args) * SizeOf(Integer), 0);
  Args := nil;
end;

function ServerOperationArgsJSON(const Args: array of Integer): string;
var I: Integer;
begin
  if Length(Args) > 8 then
    raise EGameApi.Create(CozyText_ServerOperations_COZY_SERVER_OPERATION_ARGUMENT_INVALID_fa040681, '');
  Result := '[';
  for I := 0 to High(Args) do
  begin
    if I > 0 then Result := Result + ',';
    Result := Result + IntToStr(Args[I]);
  end;
  Result := Result + ']';
end;

function ServerOperationBinding(const Stage, SessionID, MachineID, PolicyID,
  RequestID: string; FunctionID: Word; const ArgsSHA512: string): string;
begin
  ValidateBindingFields(Stage, SessionID, MachineID, PolicyID, RequestID,
    FunctionID, ArgsSHA512);
  Result := IntegritySHA512Text(OperationDomain + #10 + Stage + #10 +
    SessionID + #10 + MachineID + #10 + PolicyID + #10 +
    IntToStr(FunctionID) + #10 + RequestID + #10 + ArgsSHA512);
end;

function ServerOperationCanonical(const Stage, SessionID, MachineID, PolicyID,
  RequestID: string; FunctionID: Word; const ArgsSHA512, Binding: string;
  const Challenge: TServerOperationChallenge): string;
begin
  ValidateBindingFields(Stage, SessionID, MachineID, PolicyID, RequestID,
    FunctionID, ArgsSHA512);
  ValidateChallenge(Challenge);
  if not IsHex(Binding, 128, False) or
    (Binding <> ServerOperationBinding(Stage, SessionID, MachineID, PolicyID,
      RequestID, FunctionID, ArgsSHA512)) then InputInvalid;
  Result := OperationDomain + #10 + Stage + #10 + SessionID + #10 +
    MachineID + #10 + PolicyID + #10 + IntToStr(FunctionID) + #10 +
    RequestID + #10 + ArgsSHA512 + #10 + Binding + #10 +
    Challenge.ChallengeID + #10 + Challenge.Nonce + #10 + Challenge.Epoch + #10 +
    IntToStr(Challenge.Revision) + #10 + IntToStr(Challenge.OperationsRevision) +
    #10 + IntToStr(Challenge.ExpiresAt);
end;

function Text(Obj: TJSONObject; const Name, Pattern: string): string;
var Value: TJSONValue;
begin
  Value := Obj.GetValue(Name);
  if not (Value is TJSONString) then Invalid;
  Result := Value.Value;
  if (Length(Result) > 128) or (Pos(#0, Result) <> 0) or
    (Pos(#10, Result) <> 0) or (Pos(#13, Result) <> 0) or
    not TRegEx.IsMatch(Result, Pattern) then Invalid;
end;

function Number(Obj: TJSONObject; const Name: string;
  Minimum, Maximum: Int64): Int64;
var Value: TJSONValue;
begin
  Value := Obj.GetValue(Name);
  if not (Value is TJSONNumber) then Invalid;
  if not TryStrToInt64(Value.Value, Result) or
    (Result < Minimum) or (Result > Maximum) or
    (IntToStr(Result) <> Value.Value) then Invalid;
end;

function InvokeCozyServerOperation(Transport: TConnectTransport;
  Security: TDeviceSecurity; CodeIntegrity: TCodeIntegrity;
  const Stage, SessionID, SessionToken, FileSHA512, FileCRC64: string;
  FunctionID: Word; const Args: array of Integer;
  const Cancelled: TAuthorityCancelled; OwnImage: TImageIntegrity;
  const Runtime: ICozyRuntimeMeasurement): Integer;
var
  Clock: TStopwatch;
  ID: TGUID;
  PublicBinding: TCozyPolicyBinding;
  RequestID, MachineID, ArgsText, ArgsSHA512, Binding, Canonical, Signature: string;
  Challenge: TServerOperationChallenge;
  LocalArgs: TArray<Integer>;
  OutputValue: Integer;
  Body, Data: TJSONObject;

  function IsCancelled: Boolean;
  begin
    Result := (Assigned(Cancelled) and Cancelled()) or
      (Clock.ElapsedMilliseconds >= OperationBudgetMs);
  end;

  function Remaining: Cardinal;
  var Left: Int64;
  begin
    if IsCancelled then
      raise EGameApi.Create(CozyText_ServerOperations_COZY_SERVER_OPERATION_CANCELLED_09ad299c, '');
    Left := OperationBudgetMs - Clock.ElapsedMilliseconds;
    if Left <= 0 then
      raise EGameApi.Create(CozyText_ServerOperations_COZY_SERVER_OPERATION_CANCELLED_09ad299c, '');
    if Left > 10000 then Left := 10000;
    Result := Cardinal(Left);
  end;

  function CommonBody(const Action: string): TJSONObject;
  var Values: TJSONArray; I: Integer;
  begin
    Result := TJSONObject.Create;
    try
      Result.AddPair(CozyText_ServerOperations_action_e140259c, Action); Result.AddPair(CozyText_ServerOperations_stage_0a4eb366, Stage);
      Result.AddPair(CozyText_ServerOperations_sessionId_d05f0852, SessionID); Result.AddPair(CozyText_ServerOperations_sessionToken_1ce33cfb, SessionToken);
      Result.AddPair(CozyText_ServerOperations_machineId_56c42224, MachineID); Result.AddPair(CozyText_ServerOperations_requestId_60a0fd94, RequestID);
      Result.AddPair(CozyText_ServerOperations_policyId_6eee1741, PublicBinding.PolicyID);
      Result.AddPair(CozyText_ServerOperations_functionId_50c848cd, TJSONNumber.Create(Integer(FunctionID)));
      Values := TJSONArray.Create; Result.AddPair(CozyText_ServerOperations_args_c4a3346d, Values);
      for I := 0 to High(LocalArgs) do Values.AddElement(TJSONNumber.Create(LocalArgs[I]));
    except Result.Free; raise; end;
  end;

  function Post(Request: TJSONObject): TJSONObject;
  var Response: TJSONObject; Value: TJSONValue; Code: string;
  begin
    Response := Transport.PostJSON(CozyText_ServerOperations_policy_8c903ccc, Request, Remaining);
    try
      Remaining;
      if Response = nil then Invalid;
      Value := Response.GetValue(CozyText_ServerOperations_ok_a12076d3);
      if not (Value is TJSONBool) then Invalid;
      if not TJSONBool(Value).AsBoolean then
      begin
        Code := Text(Response, CozyText_ServerOperations_error_3fe1b525, CozyText_ServerOperations_Pattern_8b847247);
        raise EGameApi.Create(Code, '');
      end;
      Value := Response.GetValue(CozyText_ServerOperations_data_71a5ee08);
      if not (Value is TJSONObject) then Invalid;
      Result := TJSONObject(Value.Clone);
    finally Response.Free; end;
  end;

begin
  if (Transport = nil) or (Security = nil) or (CodeIntegrity = nil) or
    (OwnImage = nil) or ((Stage <> 'A') and (Stage <> 'B') and (Stage <> 'O')) or
    not IsHex(SessionID, 24, True) or
    (Length(SessionToken) < 16) or (Length(SessionToken) > 200) or
    not IsHex(FileSHA512, 128, False) or
    not IsHex(FileCRC64, 16, True) then Invalid;
  ValidFunction(FunctionID);
  Clock := TStopwatch.StartNew;
  Body := nil; Data := nil; PublicBinding := Default(TCozyPolicyBinding);
  Challenge := Default(TServerOperationChallenge);
  try
    LocalArgs := SnapshotServerOperationArgs(FunctionID, Args);
    ArgsText := ServerOperationArgsJSON(LocalArgs);
    PublicBinding := ReadCozyPolicyBinding(AnsiChar(Stage[1]));
    if WindowsApiCreateGUID(ID) <> 0 then Invalid;
    RequestID := LowerCase(Copy(GUIDToString(ID), 2, 36));
    MachineID := Security.MachineID;
    ArgsSHA512 := IntegritySHA512Text(ArgsText);
    Binding := ServerOperationBinding(Stage, SessionID, MachineID,
      PublicBinding.PolicyID, RequestID, FunctionID, ArgsSHA512);
    Body := CommonBody(CozyText_ServerOperations_challenge_3a044d15); Data := Post(Body); FreeAndNil(Body);
    if (Data.Count <> 9) or (Number(Data, CozyText_ServerOperations_version_a31f027e, 1, 1) <> 1) then Invalid;
    Challenge.ChallengeID := Text(Data, CozyText_ServerOperations_challengeId_41663b56, CozyText_ServerOperations_Pattern_7afc92c8);
    Challenge.Nonce := Text(Data, CozyText_ServerOperations_nonce_94916313, CozyText_ServerOperations_Pattern_7afc92c8);
    Challenge.Epoch := Text(Data, CozyText_ServerOperations_epoch_b3e447e7, CozyText_ServerOperations_Pattern_7afc92c8);
    Challenge.Revision := Number(Data, CozyText_ServerOperations_revision_9a9708c6, 0, 9007199254740991);
    Challenge.OperationsRevision := Number(Data, CozyText_ServerOperations_operationsRevision_7b18ca10, 0, 9007199254740991);
    Challenge.ExpiresAt := Number(Data, CozyText_ServerOperations_expiresAt_8f4f4554, 1, 9007199254740991);
    if (Text(Data, CozyText_ServerOperations_binding_b2d365bb, CozyText_ServerOperations_Pattern_a8dff57a) <> Binding) or
      (Text(Data, CozyText_ServerOperations_argsSha512_9bad8e76, CozyText_ServerOperations_Pattern_a8dff57a) <> ArgsSHA512) then Invalid;
    FreeAndNil(Data);
    RequireServerObservation(Transport, Security, CodeIntegrity, Stage,
      SessionID, SessionToken, CozyText_ServerOperations_observe_599a8378, Binding, FileSHA512, FileCRC64,
      function: Boolean
      begin
        Result := (Assigned(Cancelled) and Cancelled()) or
          (Clock.ElapsedMilliseconds >= OperationBudgetMs);
      end, OwnImage, Runtime);
    Remaining;
    Canonical := ServerOperationCanonical(Stage, SessionID, MachineID,
      PublicBinding.PolicyID, RequestID, FunctionID, ArgsSHA512, Binding, Challenge);
    Remaining;
    Signature := Security.Sign(Canonical);
    Remaining;
    Body := CommonBody(CozyText_ServerOperations_invoke_e4beb29a);
    Body.AddPair(CozyText_ServerOperations_challengeId_41663b56, Challenge.ChallengeID); Body.AddPair(CozyText_ServerOperations_signature_2faec8bd, Signature);
    try
      Data := Post(Body);
    except
      on E: EConnectTransport do
      begin
        { Only a missing response/deadline can enter recovery. TLS, authentication,
          malformed replies, explicit denials and cancellation still fail closed.
          This is one read of the original result, never another invocation. }
        if (E.Code <> CozyText_ServerOperations_CONNECT_RECEIVE_FAILED_aa008182) and
           (E.Code <> CozyText_ServerOperations_CONNECT_TIMEOUT_a4040567) then raise;
        Remaining;
        FreeAndNil(Body);
        Body := CommonBody(CozyText_ServerOperations_result_2a0548b1);
        Body.AddPair(CozyText_ServerOperations_challengeId_41663b56, Challenge.ChallengeID);
        Body.AddPair(CozyText_ServerOperations_signature_2faec8bd, Signature);
        Data := Post(Body);
      end;
    end;
    if (Data.Count <> 5) or (Number(Data, CozyText_ServerOperations_version_a31f027e, 1, 1) <> 1) or
      (Text(Data, CozyText_ServerOperations_requestId_60a0fd94, CozyText_ServerOperations_Pattern_31d70624) <> RequestID) or
      (Text(Data, CozyText_ServerOperations_policyId_6eee1741, CozyText_ServerOperations_Pattern_93496fd2) <> PublicBinding.PolicyID) or
      (Number(Data, CozyText_ServerOperations_functionId_50c848cd, 2, 65535) <> FunctionID) then Invalid;
    OutputValue := Integer(Number(Data, CozyText_ServerOperations_result_2a0548b1, -2147483648, 2147483647));
    Remaining;
    Result := OutputValue;
  finally
    Body.Free; Data.Free;
    ClearServerOperationArgs(LocalArgs);
    WipeText(ArgsText); WipeText(ArgsSHA512); WipeText(Canonical); WipeText(Signature);
    WipeText(RequestID); WipeText(MachineID); WipeText(Binding);
    WipeText(PublicBinding.PolicyID); WipeText(PublicBinding.PolicySHA512);
    WipeText(Challenge.ChallengeID); WipeText(Challenge.Nonce); WipeText(Challenge.Epoch);
    FillChar(ID, SizeOf(ID), 0);
  end;
end;

end.
