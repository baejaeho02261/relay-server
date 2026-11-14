unit Cozy.ServerOperations.Example;
{$B-}

{ Compile-time examples only; no operation is called automatically.
  Register reviewed server-only function 2 with two int32 arguments in each
  intended role's policy profile. See Relay Server/maintenance/server-operations.ko.md.
  Function bodies and secret constants belong on the server, not in this unit.
  RunForA/B/O show explicit function selection, input ownership, cancellation
  and one synchronous consumer call on the already-owned background worker.
  Consume the returned integer at the application's explicit business call site.
  The result is not a license token or permission to bypass later server checks. }

interface
uses
{ Cozy central text imports. }
  Cozy.Strings.TestsSecurity,
 Cozy.Bootstrap, Cozy.Api, Cozy.Overlay.Client, Cozy.Security,
  Cozy.CodeIntegrity, Cozy.Integrity, Cozy.ServerAuthority;

type
  TServerOperationResultConsumer = reference to procedure(Value: Integer);

{ Supply the real business function ID and its Int32 inputs. Consumer runs only
  after authenticated completion and a final cancellation check. It must not
  treat a result as a license/lease or queue access to borrowed client objects.
  No thread is spawned and no UI is written here. The caller owns this worker
  and joins it before freeing Client, Security or Code. }
procedure RunForA(Client: TBootstrapClient; const Flow: TBootstrapFlow;
  Security: TDeviceSecurity; Code: TCodeIntegrity; FunctionID: Word;
  const Args: array of Integer; const Consume: TServerOperationResultConsumer;
  const Cancelled: TAuthorityCancelled = nil);
procedure RunForB(Client: TGameApi; FunctionID: Word;
  const Args: array of Integer; const Consume: TServerOperationResultConsumer;
  const Cancelled: TAuthorityCancelled = nil);
procedure RunForO(Client: TOverlayClient; Security: TDeviceSecurity;
  Code: TCodeIntegrity; const Image: TImageDigest; FunctionID: Word;
  const Args: array of Integer; const Consume: TServerOperationResultConsumer;
  const Cancelled: TAuthorityCancelled = nil);

function ComputeForA(Client: TBootstrapClient; const Flow: TBootstrapFlow;
  Security: TDeviceSecurity; Code: TCodeIntegrity; X, Y: Integer): Integer;
function ComputeForB(Client: TGameApi; X, Y: Integer): Integer;
function ComputeForO(Client: TOverlayClient; Security: TDeviceSecurity;
  Code: TCodeIntegrity; const Image: TImageDigest; X, Y: Integer): Integer;

implementation

uses Cozy.Api.Types, Cozy.ServerOperations;

procedure CheckCancelled(const Cancelled: TAuthorityCancelled);
begin
  if Assigned(Cancelled) and Cancelled() then
    raise EGameApi.Create(CozyText_ServerOperations_Example_COZY_SERVER_OPERATION_CANCELLED_219e0920, '');
end;

procedure RequireClient(Present: Boolean);
begin
  if not Present then
    raise EGameApi.Create(CozyText_ServerOperations_Example_COZY_SERVER_OPERATION_ARGUMENT_INVALID_e8c2ffcf, '');
end;

procedure RunForA(Client: TBootstrapClient; const Flow: TBootstrapFlow;
  Security: TDeviceSecurity; Code: TCodeIntegrity; FunctionID: Word;
  const Args: array of Integer; const Consume: TServerOperationResultConsumer;
  const Cancelled: TAuthorityCancelled);
var LocalArgs: TArray<Integer>; Value: Integer;
begin
  { Authenticated A flow, after complete integrity/module reporting, before Finish. }
  RequireClient((Client <> nil) and (Security <> nil) and (Code <> nil) and Assigned(Consume));
  CheckCancelled(Cancelled);
  LocalArgs := SnapshotServerOperationArgs(FunctionID, Args);
  try
    Value := Client.InvokeServerPolicy(Flow, Security, Code, FunctionID, LocalArgs, Cancelled);
    CheckCancelled(Cancelled);
    Consume(Value);
  finally ClearServerOperationArgs(LocalArgs); end;
end;

procedure RunForB(Client: TGameApi; FunctionID: Word;
  const Args: array of Integer; const Consume: TServerOperationResultConsumer;
  const Cancelled: TAuthorityCancelled);
var LocalArgs: TArray<Integer>; Value: Integer;
begin
  { After Redeem, within B's current live license, on its serialized API worker. }
  RequireClient((Client <> nil) and Assigned(Consume));
  CheckCancelled(Cancelled);
  LocalArgs := SnapshotServerOperationArgs(FunctionID, Args);
  try
    Value := Client.InvokeServerPolicy(FunctionID, LocalArgs, Cancelled);
    CheckCancelled(Cancelled);
    Consume(Value);
  finally ClearServerOperationArgs(LocalArgs); end;
end;

procedure RunForO(Client: TOverlayClient; Security: TDeviceSecurity;
  Code: TCodeIntegrity; const Image: TImageDigest; FunctionID: Word;
  const Args: array of Integer; const Consume: TServerOperationResultConsumer;
  const Cancelled: TAuthorityCancelled);
var LocalArgs: TArray<Integer>; Value: Integer;
begin
  { After O claim and parent transfer commit, on O's existing serialized worker. }
  RequireClient((Client <> nil) and (Security <> nil) and (Code <> nil) and Assigned(Consume));
  CheckCancelled(Cancelled);
  LocalArgs := SnapshotServerOperationArgs(FunctionID, Args);
  try
    Value := Client.InvokeServerPolicy(Security, Code, Image, FunctionID, LocalArgs,
      function: Boolean
      begin Result := Assigned(Cancelled) and Cancelled(); end);
    CheckCancelled(Cancelled);
    Consume(Value);
  finally ClearServerOperationArgs(LocalArgs); end;
end;

function ComputeForA(Client: TBootstrapClient; const Flow: TBootstrapFlow;
  Security: TDeviceSecurity; Code: TCodeIntegrity; X, Y: Integer): Integer;
begin
  { After authenticated Begin + complete integrity/module reporting, before Finish. }
  RequireClient((Client <> nil) and (Security <> nil) and (Code <> nil));
  Result := Client.InvokeServerPolicy(Flow, Security, Code, 2, [X, Y]);
end;

function ComputeForB(Client: TGameApi; X, Y: Integer): Integer;
begin
  { After Redeem with a live license; use the existing background worker thread. }
  RequireClient(Client <> nil);
  Result := Client.InvokeServerPolicy(2, [X, Y]);
end;

function ComputeForO(Client: TOverlayClient; Security: TDeviceSecurity;
  Code: TCodeIntegrity; const Image: TImageDigest; X, Y: Integer): Integer;
begin
  { After O claim and complete reporting, on its existing serialized worker. }
  RequireClient((Client <> nil) and (Security <> nil) and (Code <> nil));
  Result := Client.InvokeServerPolicy(Security, Code, Image, 2, [X, Y]);
end;

end.
