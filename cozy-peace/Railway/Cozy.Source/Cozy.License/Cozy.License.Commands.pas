unit Cozy.License.Commands;
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.License,
 {$IFDEF FPC}SysUtils, SyncObjs{$ELSE}System.SysUtils, System.SyncObjs{$ENDIF}, Cozy.SensitiveText;
const
  WorkerIdle = 0;
  WorkerBusy = 1;
  WorkerFailed = 3;
  WorkerTransferred = 4;
  WorkerStopped = 5;
type
  { One input owner -> one mailbox -> one API worker. Terminal state is sticky.
    Stop does not wait for an in-flight network request and never kills threads. }
  TLicenseCommandMailbox = class
  private
    FLock: TCriticalSection;
    FPending: TCozySensitiveText;
    FState: Integer;
    FProgress: Integer;
    FStopping: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    function Submit(var Key: TCozySensitiveText): Boolean;
    function Take: TCozySensitiveText;
    procedure Complete(Outcome: Integer);
    procedure Stop;
    function State: Integer;
    procedure ReportProgress(Value: Integer);
    function Progress: Integer;
    function Stopping: Boolean;
  end;
implementation
constructor TLicenseCommandMailbox.Create;
begin inherited; FLock := TCriticalSection.Create; end;
destructor TLicenseCommandMailbox.Destroy;
begin Stop; FLock.Free; inherited; end;
function TLicenseCommandMailbox.Submit(var Key: TCozySensitiveText): Boolean;
begin
  Result := False;
  FLock.Acquire;
  try
    if FStopping or (FState <> WorkerIdle) or (Key = nil) or (Key.Count = 0) then Exit;
    { The key and its first completed UI milestone have one atomic owner.
      A duplicate submission cannot restart another accepted attempt. }
    FState := WorkerBusy;
    FProgress := 8;
    FPending := Key; Key := nil;
    Result := True;
  finally FLock.Release; end;
end;
function TLicenseCommandMailbox.Take: TCozySensitiveText;
begin
  Result := nil;
  FLock.Acquire;
  try
    if FStopping then Exit;
    Result := FPending; FPending := nil;
  finally FLock.Release; end;
end;
procedure TLicenseCommandMailbox.Complete(Outcome: Integer);
begin
  if (Outcome <> WorkerIdle) and (Outcome <> WorkerFailed) and
    (Outcome <> WorkerTransferred) then raise EArgumentException.Create(CozyText_License_Commands_COMMAND_OUTCOME_INVALID_3cbe40d1);
  FLock.Acquire;
  try
    { A committed transfer must still be recorded if stop raced with its ACK.
      The API owns the corresponding file-retirement decision. }
    if Outcome = WorkerTransferred then
    begin FState := WorkerTransferred; FProgress := 100; FStopping := True; end
    else if not FStopping then
    begin
      FState := Outcome; FProgress := 0;
      if Outcome = WorkerFailed then FStopping := True;
    end;
    if FStopping then FreeAndNil(FPending);
  finally FLock.Release; end;
end;
procedure TLicenseCommandMailbox.Stop;
begin
  if FLock = nil then Exit;
  FLock.Acquire;
  try
    FStopping := True;
    if FState <> WorkerTransferred then
    begin FState := WorkerStopped; FProgress := 0; end;
    FreeAndNil(FPending);
  finally FLock.Release; end;
end;
function TLicenseCommandMailbox.State: Integer;
begin FLock.Acquire; try Result := FState; finally FLock.Release; end; end;
procedure TLicenseCommandMailbox.ReportProgress(Value: Integer);
begin
  if Value < 0 then Exit;
  { A milestone cannot publish completion. Only an authenticated committed
    transfer reaches 100 through Complete(WorkerTransferred). }
  if Value > 99 then Value := 99;
  FLock.Acquire;
  try
    if not FStopping and (FState = WorkerBusy) and (Value > FProgress) then
      FProgress := Value;
  finally FLock.Release; end;
end;
function TLicenseCommandMailbox.Progress: Integer;
begin FLock.Acquire; try Result := FProgress; finally FLock.Release; end; end;
function TLicenseCommandMailbox.Stopping: Boolean;
begin FLock.Acquire; try Result := FStopping; finally FLock.Release; end; end;
end.
