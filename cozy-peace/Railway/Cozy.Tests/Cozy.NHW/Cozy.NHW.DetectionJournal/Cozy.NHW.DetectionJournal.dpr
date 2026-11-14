program Cozy_NHW_DetectionJournal_Regression;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}{$MESSAGE FATAL 'WIN64_REQUIRED'}{$ENDIF}
{$B-}{$R+}{$Q+}

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.SyncObjs,
  Cozy.NHW.Logging, Cozy.NHW.DetectionJournal, Cozy.NHW.Guard,
  Cozy.NHW.Observer.Protocol, Cozy.NHW.ResponsePath.Dispatch;

type
  TWorkerExit = (weUnexpectedReturn, weUnexpectedException, weCancelled);

  TGuardProbe = class(TCozyNHWGuard)
  protected
    procedure RunWorker; override;
  public
    Started: TEvent;
    ExitMode: TWorkerExit;
  end;

procedure TGuardProbe.RunWorker;
var State: TCozyNHWKernelState;
begin
  State := Default(TCozyNHWKernelState);
  State.Tick := ObserverClockTick;
  PublishKernelState(State);
  PublishIntegrityState(State);
  Started.SetEvent;
  case ExitMode of
    weUnexpectedException: raise EInvalidOpException.Create('fixture startup failure');
    weCancelled:
      while not Cancelled do Sleep(5);
  end;
end;

procedure Check(Value: Boolean; const MessageText: string);
begin if not Value then raise Exception.Create(MessageText); end;

procedure AllKindsAndPaths;
var Journals: array[0..2] of TNHWDetectionJournal;
  Batch: TNHWDetectionBatch; Kinds, Seen: TDetectionKinds;
  Kind: TDetectionKind; Path, I, Batches: Integer;
begin
  FillChar(Journals, SizeOf(Journals), 0);
  try
    Kinds := [];
    for Kind := Low(TDetectionKind) to High(TDetectionKind) do
    begin
      Include(Kinds, Kind);
      Check(Copy(NHWDetectionName(Kind), 1, 2) = 'dk', 'detection name missing');
    end;
    Check(Ord(High(TDetectionKind)) + 1 = 204, 'detection taxonomy changed');
    for Path := 0 to 2 do
    begin
      Journals[Path] := TNHWDetectionJournal.Create;
      Journals[Path].Append(Kinds, ndoKernelTrust, 1000, 7, $80, 0, False);
    end;
    for Path := 0 to 2 do
    begin
      Seen := []; Batches := 0;
      while Journals[Path].Read(Batch) do
      begin
        Inc(Batches);
        Check((Batch.Count > 0) and (Batch.Count <= NHWDetectionBatchCapacity), 'unbounded batch');
        for I := 0 to Batch.Count - 1 do
        begin
          Check(not (Batch.Records[I].Kind in Seen), 'duplicate committed event');
          Include(Seen, Batch.Records[I].Kind);
          Check(Batch.Records[I].Count = 1, 'unexpected initial count');
          Check(not Batch.Records[I].Correlated, 'local-only became corroborated');
          Check(Batch.Records[I].AttestationSequence = 7, 'attestation binding lost');
        end;
        Journals[Path].Acknowledge(Batch);
        Check(Batches <= 17, 'journal did not drain');
      end;
      Check((Seen = Kinds) and (Batches = 17), 'detection lost');
      if Path < 2 then Check(Journals[Path + 1].Pending, 'ack consumed another path');
    end;
  finally for Path := 0 to 2 do Journals[Path].Free; end;
end;

procedure AcknowledgeRaceAndFreshness;
var Journal: TNHWDetectionJournal; Before, After: TNHWDetectionBatch;
  Writer: TThread;
begin
  Journal := TNHWDetectionJournal.Create;
  try
    Journal.Append([dkWriteIntegrity], ndoEngine, 1000, 1, $09, 75, True);
    Check(Journal.Read(Before), 'initial event missing');
    Writer := TThread.CreateAnonymousThread(
      procedure begin
        Journal.Append([dkWriteIntegrity], ndoEngine, 1001, 2, $08, 10, False);
      end);
    Writer.FreeOnTerminate := False;
    try Writer.Start; Writer.WaitFor; finally Writer.Free; end;
    Journal.Acknowledge(Before);
    Check(Journal.Read(After), 'old acknowledgement swallowed racing evidence');
    Check((After.Count = 1) and (After.Records[0].Count = 2), 'racing count lost');
    Check(After.Records[0].FirstTick = 1000, 'first timestamp changed');
    Check(After.Records[0].LastTick = 1001, 'last timestamp lost');
    Check((After.Records[0].Families = $08) and
      (After.Records[0].Confidence = 10) and not After.Records[0].Correlated,
      'historical correlation leaked into a new observation');
    Journal.Append([dkWriteIntegrity], ndoEngine, 1001, 2, $08, 10, False);
    Journal.Append([dkWriteIntegrity], ndoEngine, 999, 1, $7f, 100, True);
    Journal.Acknowledge(After);
    Check(not Journal.Pending, 'duplicate or stale tick manufactured an event');
    Journal.Append([dkWriteIntegrity], ndoKernelTrust, 1002, 3, $80, 0, False);
    Check(Journal.Read(After) and (After.Records[0].Count = 1), 'source identities conflated');
  finally Journal.Free; end;
end;

procedure WorkerAvailability;
var Mode: TWorkerExit;
  Guard: TGuardProbe;
  Started: TEvent;
  StartedAt: UInt64;
  State: TCozyNHWKernelState;
  Batch: TNHWDetectionBatch;
begin
  Started := TEvent.Create(nil, True, False, '');
  try
    for Mode := Low(TWorkerExit) to High(TWorkerExit) do
    begin
      Started.ResetEvent;
      Guard := TGuardProbe.Create(nrClient);
      try
        Guard.Started := Started;
        Guard.ExitMode := Mode;
        Guard.Start;
        Check(Started.WaitFor(3000) = wrSignaled, 'guard worker did not start');
        if Mode = weCancelled then
        begin
          Guard.StopAndJoin;
          Check(not Guard.HasPendingDetections(rpcIntegrity),
            'normal worker stop reported as unavailable');
        end
        else
        begin
          StartedAt := ObserverClockTick;
          while not Guard.HasPendingDetections(rpcIntegrity) and
            (ObserverClockTick - StartedAt < 3000) do Sleep(5);
          Check(Guard.ReadDetectionBatch(rpcIntegrity, Batch) and
            (Batch.Count = 1), 'unexpected worker exit was not reported exactly once');
          Check((Batch.Records[0].Kind = dkObservationUncertain) and
            (NHWDetectionSource(Batch.Records[0].Origin) = 'Cozy.NHW.Guard') and
            (Batch.Records[0].Families = 0) and (Batch.Records[0].Confidence = 0) and
            not Batch.Records[0].Correlated, 'availability report became a detection vote');
          Check(not Guard.TryReadKernelState(State) and
            not Guard.TryReadPathState(rpcIntegrity, State),
            'unexpected exit retained stale authority state');
        end;
        Check(not Guard.Confirmed and not Guard.HasPendingDetections(rpcTrust) and
          not Guard.HasPendingDetections(rpcDriver), 'availability affected unrelated paths');
      finally
        Guard.Free;
      end;
    end;
  finally
    Started.Free;
  end;
end;

begin
  try
    AllKindsAndPaths;
    AcknowledgeRaceAndFreshness;
    WorkerAvailability;
    Writeln('PASS 204 kinds, 3 independent journals, bounded batches, concurrent ack, worker availability');
  except
    on E: Exception do begin Writeln('FAIL ', E.ClassName, ': ', E.Message); Halt(1); end;
  end;
end.
