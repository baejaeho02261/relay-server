program Cozy_LicenseOwnershipProbe;
{$APPTYPE CONSOLE}
uses
{ Cozy central text imports. }
  Cozy.Strings.License in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.License.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
  Cozy.Strings.TestsFaultInjection in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsFaultInjection.pas',
 System.SysUtils, System.Classes, System.SyncObjs,
  Cozy.Api.Contracts in '..\..\Cozy.Source\Cozy.Platform\Cozy.Api.Contracts.pas',
  Cozy.SensitiveText in '..\..\Cozy.Source\Cozy.Security\Cozy.SensitiveText.pas',
  Cozy.License.Commands in '..\..\Cozy.Source\Cozy.License\Cozy.License.Commands.pas';
var Passed: Integer;
procedure Require(Condition: Boolean; const Code: string);
begin if not Condition then raise Exception.Create(Code); Inc(Passed); end;
procedure SecretAliases;
var A, B: TCozySecret; Input, Paste: TCozySensitiveText; Text: string; Failed: Boolean;
begin
  A.Assign(CozyText_LicenseOwnershipProbe_test_capability_eb02aa4e, 32); B := A;
  try
    A.Release;
    Text := B.CopyText;
    Require(Text = CozyText_LicenseOwnershipProbe_test_capability_eb02aa4e, CozyText_LicenseOwnershipProbe_RELEASE_REVOKED_OTHER_OWNER_83f5e27d);
    WipeBoundaryText(Text);
    A := B; A.Clear;
    Require(B.IsEmpty, CozyText_LicenseOwnershipProbe_ALIAS_RETAINED_REVOKED_SECRET_9503dd55);
    Require(B.CopyText = '', CozyText_LicenseOwnershipProbe_REVOKED_SECRET_READABLE_4ced787e);
  finally A.Clear; B.Clear; end;
  Input := TCozySensitiveText.Create(4); Paste := TCozySensitiveText.Create(4);
  try
    Input.Append('A'); Input.Append('B'); Input.Backspace;
    Paste.Assign(CozyText_LicenseOwnershipProbe_CD_b352f4e4); Input.AppendBuffer(Paste); Paste.Clear;
    Text := Input.CopyText;
    Require(Text = CozyText_LicenseOwnershipProbe_ACD_e67ecad6, CozyText_LicenseOwnershipProbe_INPUT_COPY_OR_BACKSPACE_FAILED_c6986150); WipeBoundaryText(Text);
    Input.Append('E'); Failed := False;
    try Input.Append('F'); except on E: EArgumentOutOfRangeException do Failed := True; end;
    Require(Failed and (Input.Count = 4), CozyText_LicenseOwnershipProbe_OVERFLOW_MUTATED_INPUT_b651efdc);
    Input.Clear;
    Require(Input.Count = 0, CozyText_LicenseOwnershipProbe_CANCEL_RETAINED_INPUT_4bce0729);
  finally Input.Free; Paste.Free; WipeBoundaryText(Text); end;
end;
procedure CancelQueued;
var Mailbox: TLicenseCommandMailbox; Input, Taken: TCozySensitiveText;
begin
  Input := nil; Taken := nil; Mailbox := TLicenseCommandMailbox.Create;
  try
    Input := TCozySensitiveText.Create(100); Input.Assign(CozyText_LicenseOwnershipProbe_test_key_df35a21e);
    Require(Mailbox.Submit(Input) and (Input = nil), CozyText_LicenseOwnershipProbe_MAILBOX_DID_NOT_TRANSFER_OWNER_5ad4858e);
    Mailbox.Stop;
    Taken := Mailbox.Take;
    Require(Taken = nil, CozyText_LicenseOwnershipProbe_AUTH_STARTED_AFTER_STOP_a370fe3c);
    Mailbox.Complete(WorkerIdle); Mailbox.ReportProgress(90);
    Require((Mailbox.State = WorkerStopped) and (Mailbox.Progress = 0), CozyText_LicenseOwnershipProbe_LATE_REJECTION_REOPENED_INPUT_a268d8b2);
    Input := TCozySensitiveText.Create(100); Input.Assign(CozyText_LicenseOwnershipProbe_second_key_d96e1814);
    Require(not Mailbox.Submit(Input), CozyText_LicenseOwnershipProbe_SUBMIT_AFTER_STOP_fdfa691c);
    Require(Input <> nil, CozyText_LicenseOwnershipProbe_REJECTED_INPUT_OWNER_LOST_478ea3d0);
  finally Taken.Free; Input.Free; Mailbox.Free; end;
end;
procedure RetryAttempt;
var Mailbox: TLicenseCommandMailbox; Input, Taken: TCozySensitiveText;
begin
  Input := nil; Taken := nil; Mailbox := TLicenseCommandMailbox.Create;
  try
    Input := TCozySensitiveText.Create(100); Input.Assign(CozyText_LicenseOwnershipProbe_first_key_fd9373d5);
    Require(Mailbox.Submit(Input) and (Input = nil), CozyText_LicenseOwnershipProbe_RETRY_FIRST_OWNER_eba92d0f);
    Require(Mailbox.Progress = 8, CozyText_LicenseOwnershipProbe_PROGRESS_ENQUEUE_MISSING_e377e121);
    Mailbox.ReportProgress(45); Mailbox.ReportProgress(22);
    Require(Mailbox.Progress = 45, CozyText_LicenseOwnershipProbe_PROGRESS_REGRESSED_973f3640);
    Mailbox.ReportProgress(100);
    Require(Mailbox.Progress = 99, CozyText_LicenseOwnershipProbe_PROGRESS_COMPLETED_BEFORE_TRANSFER_49e616c0);
    Input := TCozySensitiveText.Create(100); Input.Assign(CozyText_LicenseOwnershipProbe_duplicate_key_f47a7406);
    Require(not Mailbox.Submit(Input), CozyText_LicenseOwnershipProbe_RETRY_DUPLICATE_ACCEPTED_fd0f1b12);
    Require((Input <> nil) and (Mailbox.Progress = 99), CozyText_LicenseOwnershipProbe_DUPLICATE_RESET_PROGRESS_4746b3ca);
    FreeAndNil(Input);
    Taken := Mailbox.Take;
    Require((Taken <> nil) and (Mailbox.State = WorkerBusy), CozyText_LicenseOwnershipProbe_RETRY_TAKE_STATE_ef862e20);
    FreeAndNil(Taken);
    Mailbox.Complete(WorkerIdle);
    Require((Mailbox.State = WorkerIdle) and (Mailbox.Progress = 0) and not Mailbox.Stopping, CozyText_LicenseOwnershipProbe_RETRY_CLOSED_AFTER_REJECTION_65cc0796);
    Input := TCozySensitiveText.Create(100); Input.Assign(CozyText_LicenseOwnershipProbe_second_key_d96e1814);
    Require(Mailbox.Submit(Input) and (Input = nil), CozyText_LicenseOwnershipProbe_RETRY_SECOND_OWNER_939f7bf3);
    Require(Mailbox.Progress = 8, CozyText_LicenseOwnershipProbe_PROGRESS_NEW_ATTEMPT_NOT_RESET_23ce7302);
    Taken := Mailbox.Take; FreeAndNil(Taken);
    Mailbox.Complete(WorkerTransferred); Mailbox.Stop;
    Require((Mailbox.State = WorkerTransferred) and (Mailbox.Progress = 100), CozyText_LicenseOwnershipProbe_RETRY_TRANSFER_NOT_STICKY_7556a176);
  finally Taken.Free; Input.Free; Mailbox.Free; end;
end;
procedure RaceResponse(Transfer: Boolean);
var Mailbox: TLicenseCommandMailbox; Input, Taken: TCozySensitiveText;
  Began, Reply, Stopped: TEvent; Worker: TThread; Failure: string;
begin
  Mailbox := TLicenseCommandMailbox.Create; Input := nil; Taken := nil; Worker := nil;
  Began := TEvent.Create(nil, True, False, '');
  Reply := TEvent.Create(nil, True, False, '');
  Stopped := TEvent.Create(nil, True, False, ''); Failure := '';
  try
    Input := TCozySensitiveText.Create(100); Input.Assign(CozyText_LicenseOwnershipProbe_race_key_70805df7);
    Require(Mailbox.Submit(Input), CozyText_LicenseOwnershipProbe_RACE_SUBMIT_FAILED_69e94a95);
    Worker := TThread.CreateAnonymousThread(
      procedure
      var Owned: TCozySensitiveText;
      begin
        Owned := nil;
        try
          Owned := Mailbox.Take;
          if Owned = nil then raise Exception.Create(CozyText_LicenseOwnershipProbe_RACE_OWNERSHIP_LOST_bffdceab);
          Began.SetEvent;
          if Reply.WaitFor(3000) <> wrSignaled then raise Exception.Create(CozyText_LicenseOwnershipProbe_RACE_REPLY_TIMEOUT_1dbba71c);
          if Transfer then Mailbox.Complete(WorkerTransferred)
          else Mailbox.Complete(WorkerIdle);
        except on E: Exception do Failure := E.Message; end;
        Owned.Free; Stopped.SetEvent;
      end);
    Worker.FreeOnTerminate := False; Worker.Start;
    Require(Began.WaitFor(3000) = wrSignaled, CozyText_LicenseOwnershipProbe_RACE_START_TIMEOUT_9f48cb7b);
    { Stop wins before a delayed auth rejection or committed transfer ACK. }
    Mailbox.Stop; Reply.SetEvent;
    Require(Stopped.WaitFor(3000) = wrSignaled, CozyText_LicenseOwnershipProbe_RACE_STOP_TIMEOUT_20017762); Worker.WaitFor;
    Require(Failure = '', CozyText_LicenseOwnershipProbe_RACE_WORKER_FAILED_b9180206);
    if Transfer then Require(Mailbox.State = WorkerTransferred, CozyText_LicenseOwnershipProbe_TRANSFER_OWNERSHIP_LOST_79454293)
    else Require(Mailbox.State = WorkerStopped, CozyText_LicenseOwnershipProbe_REJECTION_REOPENED_STOPPED_MAILBOX_2ee8c0a7);
    Input := TCozySensitiveText.Create(100); Input.Assign(CozyText_LicenseOwnershipProbe_late_key_bb25f43b);
    Require(not Mailbox.Submit(Input), CozyText_LicenseOwnershipProbe_REAUTH_AFTER_TERMINAL_6d6d27ca);
    Taken := Mailbox.Take; Require(Taken = nil, CozyText_LicenseOwnershipProbe_TERMINAL_QUEUE_NOT_EMPTY_9289aef1);
  finally
    Mailbox.Stop; Reply.SetEvent;
    if Worker <> nil then begin Worker.WaitFor; Worker.Free; end;
    Taken.Free; Input.Free; Mailbox.Free; Began.Free; Reply.Free; Stopped.Free;
  end;
end;
begin
  Passed := 0;
  try
    SecretAliases; CancelQueued; RetryAttempt; RaceResponse(False); RaceResponse(True);
    Writeln(CozyText_LicenseOwnershipProbe_CONSOLE_OWNERSHIP_PASS_c5618465, Passed);
  except on E: Exception do begin Writeln(CozyText_LicenseOwnershipProbe_CONSOLE_OWNERSHIP_FAIL_2475874b, E.Message); Halt(1); end; end;
end.
