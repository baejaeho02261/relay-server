program Cozy_Blake3ParallelProbe;
{ Portable real-thread contract test. Test-vector key/context are PUBLIC.
  Windows uses the actual encoded-API executor; FPC/Linux uses raw RTL threads. }
{$IFDEF FPC}{$MODE DELPHI}{$ELSE}{$APPTYPE CONSOLE}{$ENDIF}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsCrypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsCrypto.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

{$IFDEF FPC}cthreads, SysUtils,{$ELSE}System.SysUtils, Cozy.Hashes.Workers,{$ENDIF}
  Cozy.Hashes;
type
  TJob = record Work: TBlake3Work; Context: Pointer; Completed: Boolean; end;
  PJob = ^TJob;
var Batches, ThreadStarts, Cases: Integer;
{$IFDEF FPC}
function Entry(P: Pointer): PtrInt;
begin
  Result := 1;
  try PJob(P)^.Work(PJob(P)^.Context); PJob(P)^.Completed := True; Result := 0;
  except PJob(P)^.Completed := False; end;
end;
{$ENDIF}
procedure Execute(Work: TBlake3Work; const Contexts: array of Pointer);
{$IFDEF FPC}
var Jobs: array[0..3] of TJob; Handles: array[0..3] of TThreadID; I: Integer;
{$ENDIF}
begin
  Inc(Batches);
{$IFDEF FPC}
  FillChar(Jobs, SizeOf(Jobs), 0); FillChar(Handles, SizeOf(Handles), 0);
  try
    for I := 0 to High(Contexts) do begin
      Jobs[I].Work := Work; Jobs[I].Context := Contexts[I];
      Handles[I] := BeginThread(Entry, @Jobs[I]);
      if Handles[I] = 0 then raise Exception.Create(CozyText_Blake3ParallelProbe_Thread_start_failed_4137b1a8);
      Inc(ThreadStarts);
    end;
  finally
    for I := 0 to High(Contexts) do if Handles[I] <> 0 then
      WaitForThreadTerminate(Handles[I], 0);
  end;
  for I := 0 to High(Contexts) do if not Jobs[I].Completed then
    raise Exception.Create(CozyText_Blake3ParallelProbe_Worker_failed_ce84ed60);
{$ELSE}
  ExecuteBlake3Workers(Work, Contexts);
{$ENDIF}
end;
procedure Incomplete(Work: TBlake3Work; const Contexts: array of Pointer);
begin { Intentional contract failure: no thread started. } end;
procedure JoinedFailure(Work: TBlake3Work; const Contexts: array of Pointer);
begin Execute(Work, Contexts); raise Exception.Create(CozyText_Blake3ParallelProbe_Injected_joined_failure_c9788303); end;
function ASCIIBytes(const S: AnsiString): TBytes;
var I: Integer;
begin
  SetLength(Result, Length(S));
  for I := 1 to Length(S) do Result[I-1] := Byte(S[I]);
end;
var
  Data, Key, Context: TBytes;
  SerialHash, ParallelHash: TBlake3Hasher;
  SerialAll, ParallelAll: TIntegrityHasher;
  A, B: TIntegrityHashResult;
  I, Mode, Prefix, WorkerCount, SizeIndex, Failure: Integer;
  Prefixes: array[0..7] of Integer = (0,1,63,64,1023,1024,1025,4095);
  Sizes: array[0..5] of Integer = (0,1024,262144,262145,1048577,3146505);
  Used: NativeUInt;
  Before, After, Expected, Actual: string;
  Rejected: Boolean;
function NewHash(Mode: Integer): TBlake3Hasher;
begin
  case Mode of
    0: Result := TBlake3Hasher.Create;
    1: Result := TBlake3Hasher.CreateKeyed(Key);
    else Result := TBlake3Hasher.CreateDeriveKey(Context);
  end;
end;

function NextRandom(var State: UInt32): UInt32;
begin
  { Fixed-seed xorshift: failures are reproducible without wall-clock seeds. }
  State := State xor (State shl 13);
  State := State xor (State shr 17);
  State := State xor (State shl 5);
  Result := State;
end;

procedure RandomizedPartitions;
const
  SmallSteps: array[0..9] of Integer = (1, 7, 63, 64, 65, 1023, 1024, 1025, 4095, 4096);
var
  State: UInt32;
  Input: TBytes;
  Left, Right: TBlake3Hasher;
  CommonLeft, CommonRight: TIntegrityHasher;
  L, R: TIntegrityHashResult;
  Trial, HashMode, N, At, Take, Workers, J: Integer;
  Seek: UInt64;
  Snapshot: string;
begin
  State := $591DC72B;
  for HashMode := 0 to 2 do
    for Trial := 0 to 23 do
    begin
      N := 262145 + Integer(NextRandom(State) mod 786433);
      SetLength(Input, N);
      for J := 0 to High(Input) do Input[J] := Byte(NextRandom(State) and $FF);
      Left := NewHash(HashMode); Right := NewHash(HashMode);
      try
        At := 0;
        while At < N do
        begin
          if At = 0 then Take := 262145
          else if (NextRandom(State) and 3) = 0 then
            Take := SmallSteps[NextRandom(State) mod Length(SmallSteps)]
          else Take := 1 + Integer(NextRandom(State) mod 524289);
          if Take > N - At then Take := N - At;
          Workers := 1 + Integer(NextRandom(State) mod 4);
          Left.Update(Input[At], Take);
          Right.UpdateParallel(Input[At], Take, Execute, Workers);
          Inc(At, Take);
          Seek := NextRandom(State) mod 129;
          Snapshot := Right.FinishHex(131, Seek);
          if Left.FinishHex(131, Seek) <> Snapshot then
            raise Exception.CreateFmt(CozyText_Blake3ParallelProbe_Random_split_mismatch_mode_d_trial_d_offset_d_wo_f8c69c11,
              [HashMode, Trial, At, Workers]);
          if Snapshot <> Right.FinishHex(131, Seek) then
            raise Exception.Create(CozyText_Blake3ParallelProbe_Random_split_Finish_mutated_state_5832d717);
        end;
        { A final snapshot must still permit a subsequent update. }
        Left.Update(Input[0], 65); Right.Update(Input[0], 65);
        if Left.FinishHex <> Right.FinishHex then
          raise Exception.Create(CozyText_Blake3ParallelProbe_Random_split_continue_after_Finish_mismatch_3cbd02fc);
        Inc(Cases);
      finally Left.Free; Right.Free; end;
      if HashMode = 0 then
      begin
        CommonLeft := TIntegrityHasher.Create; CommonRight := TIntegrityHasher.Create;
        try
          CommonLeft.Update(Input[0], N);
          At := 0;
          while At < N do
          begin
            Take := 1 + Integer(NextRandom(State) mod 524289);
            if Take > N - At then Take := N - At;
            Workers := 1 + Integer(NextRandom(State) mod 4);
            CommonRight.UpdateParallel(Input[At], Take, Execute, Workers);
            Inc(At, Take);
            L := CommonRight.Finish; R := CommonRight.Finish;
            if (L.SHA512 <> R.SHA512) or (L.XXH3_128 <> R.XXH3_128) or
              (L.Blake3 <> R.Blake3) or (L.Size <> R.Size) then
              raise Exception.Create(CozyText_Blake3ParallelProbe_Random_integrated_Finish_mutated_state_e407d10c);
          end;
          L := CommonLeft.Finish; R := CommonRight.Finish;
          if (L.SHA512 <> R.SHA512) or (L.XXH3_128 <> R.XXH3_128) or
            (L.Blake3 <> R.Blake3) or (L.Size <> R.Size) then
            raise Exception.Create(CozyText_Blake3ParallelProbe_Random_integrated_split_result_mismatch_ff5dba1b);
          Inc(Cases);
        finally CommonLeft.Free; CommonRight.Free; end;
      end;
      FillChar(Input[0], Length(Input), 0);
    end;
end;

procedure FailedIntegratedReset;
var
  Trial: Integer;
  H: TIntegrityHasher;
  R, ExpectedReset: TIntegrityHashResult;
  Rejected: Boolean;
begin
  ExpectedReset := IntegrityHashesBytes(Data);
  for Trial := 0 to 7 do
  begin
    H := TIntegrityHasher.Create;
    try
      H.Update(Data[0], Trial * 63 + 1);
      Rejected := False;
      try
        if (Trial and 1) = 0 then H.UpdateParallel(Data[0], Length(Data), Incomplete)
        else H.UpdateParallel(Data[0], Length(Data), JoinedFailure);
      except Rejected := True; end;
      if not Rejected then raise Exception.Create(CozyText_Blake3ParallelProbe_Integrated_executor_failure_accepted_24fc74b3);
      Rejected := False;
      try H.Finish; except Rejected := True; end;
      if not Rejected then raise Exception.Create(CozyText_Blake3ParallelProbe_Failed_integrated_Finish_accepted_543a6b96);
      Rejected := False;
      try H.Update(Data[0], 1); except Rejected := True; end;
      if not Rejected then raise Exception.Create(CozyText_Blake3ParallelProbe_Failed_integrated_Update_accepted_dc244884);
      H.Reset;
      R := H.Finish;
      if R.Size <> 0 then raise Exception.Create(CozyText_Blake3ParallelProbe_Failed_integrated_Reset_did_not_clear_size_a20a6092);
      H.UpdateParallel(Data[0], Length(Data), Execute, 2 + Trial mod 3);
      R := H.Finish;
      if (R.SHA512 <> ExpectedReset.SHA512) or (R.XXH3_128 <> ExpectedReset.XXH3_128) or
        (R.Blake3 <> ExpectedReset.Blake3) or (R.Size <> ExpectedReset.Size) then
        raise Exception.Create(CozyText_Blake3ParallelProbe_Failed_integrated_Reset_did_not_restore_all_dige_1acf20f3);
      Inc(Cases);
    finally H.Free; end;
  end;
end;

begin
  try
    Key := ASCIIBytes(CozyText_Blake3ParallelProbe_whats_the_Elvish_word_for_friend_987eb351);
    Context := ASCIIBytes(CozyText_Blake3ParallelProbe_BLAKE3_2019_12_27_16_29_52_test_vectors_context_f665d433);
    SetLength(Data, 3146505);
    for I := 0 to High(Data) do Data[I] := Byte(I mod 251);
    for Mode := 0 to 2 do for SizeIndex := 0 to High(Sizes) do
    for Prefix in Prefixes do for WorkerCount := 2 to 4 do begin
      if Prefix > Sizes[SizeIndex] then Continue;
      SerialHash := NewHash(Mode); ParallelHash := NewHash(Mode);
      try
        SerialHash.Update(Data[0], Sizes[SizeIndex]);
        if Prefix > 0 then ParallelHash.Update(Data[0], Prefix);
        Before := ParallelHash.FinishHex;
        if Before <> ParallelHash.FinishHex then raise Exception.Create(CozyText_Blake3ParallelProbe_Snapshot_mutated_state_2201e806);
        if Sizes[SizeIndex] > Prefix then
          Used := ParallelHash.UpdateParallel(Data[Prefix], Sizes[SizeIndex]-Prefix, Execute, WorkerCount)
        else Used := 0;
        if (Sizes[SizeIndex]-Prefix >= 262144) and (Used = 0) then
          raise Exception.Create(CozyText_Blake3ParallelProbe_Expected_real_parallel_work_ae0923ea);
        Expected := SerialHash.FinishHex(131, 63); Actual := ParallelHash.FinishHex(131, 63);
        if Expected <> Actual then raise Exception.CreateFmt(CozyText_Blake3ParallelProbe_Mismatch_mode_d_prefix_d_size_d_workers_d_e0329370,
          [Mode, Prefix, Sizes[SizeIndex], WorkerCount]);
        After := ParallelHash.FinishHex;
        if After <> ParallelHash.FinishHex then raise Exception.Create(CozyText_Blake3ParallelProbe_Parallel_finalization_mutated_state_729e4248);
        SerialHash.Update(Data[0], 1025); ParallelHash.Update(Data[0], 1025);
        if SerialHash.FinishHex <> ParallelHash.FinishHex then raise Exception.Create(CozyText_Blake3ParallelProbe_Continued_update_mismatch_bfbe8e2e);
        Inc(Cases);
      finally SerialHash.Free; ParallelHash.Free; end;
    end;
    SerialAll := TIntegrityHasher.Create; ParallelAll := TIntegrityHasher.Create;
    try
      SerialAll.Update(Data[0], Length(Data));
      ParallelAll.UpdateParallel(Data[0], Length(Data), Execute);
      A := SerialAll.Finish; B := ParallelAll.Finish;
      if (A.SHA512 <> B.SHA512) or (A.XXH3_128 <> B.XXH3_128) or
        (A.Blake3 <> B.Blake3) or (A.Size <> B.Size) then
        raise Exception.Create(CozyText_Blake3ParallelProbe_Independent_digest_stream_mismatch_a822c968);
    finally SerialAll.Free; ParallelAll.Free; end;
    for Mode := 0 to 2 do for Failure := 0 to 1 do begin
      ParallelHash := NewHash(Mode);
      try
        Rejected := False;
        try
          if Failure = 0 then ParallelHash.UpdateParallel(Data[0], Length(Data), Incomplete)
          else ParallelHash.UpdateParallel(Data[0], Length(Data), JoinedFailure);
        except Rejected := True; end;
        if not Rejected then raise Exception.Create(CozyText_Blake3ParallelProbe_Executor_failure_accepted_0f2438ff);
        Rejected := False;
        try ParallelHash.FinishHex; except Rejected := True; end;
        if not Rejected then raise Exception.Create(CozyText_Blake3ParallelProbe_Failed_stream_remained_usable_032d265d);
        ParallelHash.Reset;
        ParallelHash.UpdateParallel(Data[0], Length(Data), Execute, 2 + Mode);
        SerialHash := NewHash(Mode);
        try
          SerialHash.Update(Data[0], Length(Data));
          if SerialHash.FinishHex(131, 63) <> ParallelHash.FinishHex(131, 63) then
            raise Exception.Create(CozyText_Blake3ParallelProbe_BLAKE3_failed_Reset_lost_key_derive_mode_72665f2c);
        finally SerialHash.Free; end;
        Inc(Cases);
      finally ParallelHash.Free; end;
    end;
    RandomizedPartitions;
    FailedIntegratedReset;
    for Mode := 0 to 2 do begin
      ParallelHash := NewHash(Mode);
      try
        ParallelHash.UpdateParallel(Data[0], Length(Data), Execute);
        WriteLn(CozyText_Blake3ParallelProbe_VECTOR_2347dc6b, Mode, ' ', ParallelHash.FinishHex(131, 63));
      finally ParallelHash.Free; end;
    end;
    WriteLn(CozyText_Blake3ParallelProbe_PASS_cases_8bb86ecb, Cases, CozyText_Blake3ParallelProbe_batches_f77b783b, Batches, CozyText_Blake3ParallelProbe_portableThreadStarts_8931cb63, ThreadStarts);
    FillChar(Key[0], Length(Key), 0); FillChar(Data[0], Length(Data), 0);
  except on E: Exception do begin WriteLn(E.ClassName, CozyText_Blake3ParallelProbe_Text_aa226d92, E.Message); Halt(1); end; end;
end.
