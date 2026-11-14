unit Cozy.NHW.HandleSnapshot.Decoder;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

// Internal read-only decoding layer; callers retain collection/handle ownership.
uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections,
  Cozy.NHW.Types, Cozy.NHW.Native;

function RealReference(H: THandle): Boolean; inline;
procedure ClearCollected(Holders: TDictionary<string, TTargetHolder>;
  Observed: TList<TObservedHandle>; TokenObserved: TList<TObservedTokenHandle>);
function ParseHandleSnapshot(const Data: TBytes; CurrentPID: Cardinal;
  TargetHandle: THandle; TargetPID: Cardinal;
  ThreadHandles: TList<THandle>; ThreadsEnumerated: Boolean;
  Holders: TDictionary<string, TTargetHolder>; Observed: TList<TObservedHandle>;
  TokenReference: THandle; TokenObserved: TList<TObservedTokenHandle>;
  out TokenValid, ThreadsValid: Boolean;
  out TotalHandles: NativeUInt; out Reason: string): Boolean;

implementation

function HolderMapKey(OwnerPID: Cardinal; IsThread: Boolean;
  ObjectIdentity: NativeUInt): string;
begin
  if IsThread then
    Result := 'T:' + IntToHex(UInt64(ObjectIdentity), 16) + ':'
  else
    Result := 'P:' + IntToHex(UInt64(ObjectIdentity), 16) + ':';
  Result := Result + IntToStr(OwnerPID);
end;

procedure AddHolder(Holders: TDictionary<string, TTargetHolder>;
  OwnerPID: Cardinal; IsThread: Boolean; ObjectIdentity: NativeUInt;
  GrantedAccess: Cardinal; HandleValue: NativeUInt);
var
  Key: string;
  H: TTargetHolder;
  L: Integer;
begin
  Key := HolderMapKey(OwnerPID, IsThread, ObjectIdentity);
  if not Holders.TryGetValue(Key, H) then
  begin
    H := Default(TTargetHolder);
    H.PID := OwnerPID;
    H.IsThread := IsThread;
    H.ObjectIdentity := ObjectIdentity;
    H.Level := -1;
  end;
  Inc(H.HandleCount);
  H.RightsUnion := H.RightsUnion or GrantedAccess;
  if IsThread then L := LevelForThreadRights(GrantedAccess)
  else L := LevelForProcessRights(GrantedAccess);
  if L > H.Level then
  begin
    H.Level := L;
    H.RepresentativeRights := GrantedAccess;
    H.RepresentativeHandle := HandleValue;
  end;
  Holders.AddOrSetValue(Key, H);
end;

type
  TThreadReference = record
    Seen: Boolean;
    ObjectIdentity: NativeUInt;
    ObjectType: Word;
  end;

function RealReference(H: THandle): Boolean; inline;
begin
  // A snapshot contains real handles, never current-process/thread pseudo handles.
  Result := (H <> 0) and (NativeUInt(H) <= NativeUInt(High(NativeInt)));
end;

procedure ClearCollected(Holders: TDictionary<string, TTargetHolder>;
  Observed: TList<TObservedHandle>; TokenObserved: TList<TObservedTokenHandle>);
begin
  if Holders <> nil then Holders.Clear;
  if Observed <> nil then Observed.Clear;
  if TokenObserved <> nil then TokenObserved.Clear;
end;

// Pure parser: current-process identity is captured once by the caller. No
// kernel object pointer from this buffer is ever dereferenced. Output is valid
// only after a complete successful parse; optional sub-snapshots have flags.
function ParseHandleSnapshot(const Data: TBytes; CurrentPID: Cardinal;
  TargetHandle: THandle; TargetPID: Cardinal;
  ThreadHandles: TList<THandle>; ThreadsEnumerated: Boolean;
  Holders: TDictionary<string, TTargetHolder>; Observed: TList<TObservedHandle>;
  TokenReference: THandle; TokenObserved: TList<TObservedTokenHandle>;
  out TokenValid, ThreadsValid: Boolean;
  out TotalHandles: NativeUInt; out Reason: string): Boolean;
var
  Count, I: NativeUInt;
  Entry: PNativeHandleEntry;
  J: Integer;
  ProcessObject, TokenObject: NativeUInt;
  ProcessType, TokenType, ThreadType, ThisType: Word;
  ProcessFound, TokenFound, TokenConsistent, ThreadsConsistent: Boolean;
  PID: Cardinal;
  KnownThreads: TDictionary<NativeUInt, TThreadReference>;
  ThreadObjects: TDictionary<NativeUInt, Word>;
  Ref: TThreadReference;
  Mapped: Integer;
  Obj: NativeUInt;
  Obs: TObservedHandle;
  Tok: TObservedTokenHandle;
begin
  Result := False;
  TokenValid := False;
  ThreadsValid := False;
  TotalHandles := 0;
  Reason := '';
  ClearCollected(Holders, Observed, TokenObserved);
  if (Holders = nil) or (Observed = nil) or (TokenObserved = nil) or
     (CurrentPID = 0) or (TargetPID = 0) or not RealReference(TargetHandle) then
  begin
    Reason := 'Invalid handle snapshot arguments.';
    Exit;
  end;
  if (SizeOf(TNativeHandleEntry) <> 40) or (SizeOf(NativeUInt) <> 8) then
  begin
    Reason := 'Unexpected x64 handle snapshot layout.';
    Exit;
  end;
  if Length(Data) < 16 then
  begin
    Reason := 'Truncated handle snapshot header.';
    Exit;
  end;
  Move(Data[0], Count, SizeOf(Count));
  if (Count = 0) or
     (Count > NativeUInt((Length(Data) - 16) div SizeOf(TNativeHandleEntry))) then
  begin
    Reason := 'Invalid handle snapshot entry count.';
    Exit;
  end;

  KnownThreads := nil;
  ThreadObjects := nil;
  try
    KnownThreads := TDictionary<NativeUInt, TThreadReference>.Create;
    ThreadObjects := TDictionary<NativeUInt, Word>.Create;
    ThreadsConsistent := ThreadsEnumerated and (ThreadHandles <> nil);
    if ThreadsConsistent then
    begin
      if ThreadHandles.Count > MAX_TARGET_THREADS then
        ThreadsConsistent := False
      else
        for J := 0 to ThreadHandles.Count - 1 do
        begin
          if not RealReference(ThreadHandles[J]) or
             (ThreadHandles[J] = TargetHandle) or
             (ThreadHandles[J] = TokenReference) then
          begin
            ThreadsConsistent := False;
            Continue;
          end;
          // Repeated references to one handle are not additional threads.
          if not KnownThreads.ContainsKey(NativeUInt(ThreadHandles[J])) then
            KnownThreads.Add(NativeUInt(ThreadHandles[J]), Default(TThreadReference));
        end;
    end;
    ProcessObject := 0;
    ProcessType := 0;
    ProcessFound := False;
    TokenObject := 0;
    TokenType := 0;
    TokenFound := False;
    TokenConsistent := RealReference(TokenReference) and
      (TokenReference <> TargetHandle);
    ThreadType := 0;
    Mapped := 0;
    Entry := PNativeHandleEntry(@Data[16]);
    for I := 0 to Count - 1 do
    begin
      if Entry^.OwnerPID = NativeUInt(CurrentPID) then
      begin
        Obj := NativeUInt(Entry^.ObjectPointer);
        if Entry^.HandleValue = NativeUInt(TargetHandle) then
        begin
          // A real (owner PID, handle value) occurs only once per snapshot.
          if ProcessFound then
          begin
            Reason := 'Duplicate target reference in handle snapshot.';
            Exit;
          end;
          ProcessFound := True;
          ProcessObject := Obj;
          ProcessType := Entry^.ObjectTypeIndex;
        end;
        if TokenConsistent and
           (Entry^.HandleValue = NativeUInt(TokenReference)) then
        begin
          if TokenFound then TokenConsistent := False;
          TokenFound := True;
          TokenObject := Obj;
          TokenType := Entry^.ObjectTypeIndex;
        end;
        if KnownThreads.TryGetValue(Entry^.HandleValue, Ref) then
        begin
          if Ref.Seen then ThreadsConsistent := False
          else
          begin
            Ref.Seen := True;
            Ref.ObjectIdentity := Obj;
            Ref.ObjectType := Entry^.ObjectTypeIndex;
            KnownThreads[Entry^.HandleValue] := Ref;
            Inc(Mapped);
            if (Obj = 0) or (Ref.ObjectType = 0) then
              ThreadsConsistent := False
            else
            begin
              if ThreadType = 0 then ThreadType := Ref.ObjectType
              else if ThreadType <> Ref.ObjectType then ThreadsConsistent := False;
              if ThreadObjects.TryGetValue(Obj, ThisType) then
              begin
                if ThisType <> Ref.ObjectType then ThreadsConsistent := False;
              end
              else ThreadObjects.Add(Obj, Ref.ObjectType);
            end;
          end;
        end;
      end;
      Entry := PNativeHandleEntry(NativeUInt(Entry) + NativeUInt(SizeOf(TNativeHandleEntry)));
    end;

    if not ProcessFound or (ProcessObject = 0) or (ProcessType = 0) then
    begin
      Reason := 'Target reference unavailable or object identity redacted.';
      Exit;
    end;
    TokenValid := TokenConsistent and TokenFound and (TokenObject <> 0) and
      (TokenType <> 0) and (TokenObject <> ProcessObject) and (TokenType <> ProcessType);
    ThreadsValid := ThreadsConsistent and (Mapped = KnownThreads.Count);
    if KnownThreads.Count > 0 then
    begin
      ThreadsValid := ThreadsValid and (ThreadType <> 0) and (ThreadType <> ProcessType);
      if ThreadObjects.ContainsKey(ProcessObject) then ThreadsValid := False;
      if TokenValid then
        if (ThreadType = TokenType) or ThreadObjects.ContainsKey(TokenObject) then
          ThreadsValid := False;
    end;

    Entry := PNativeHandleEntry(@Data[16]);
    for I := 0 to Count - 1 do
    begin
      if (Entry^.OwnerPID > 0) and
         (Entry^.OwnerPID <= NativeUInt(High(Cardinal))) then
      begin
        PID := Cardinal(Entry^.OwnerPID);
        if (PID <> TargetPID) and (PID <> CurrentPID) then
        begin
          Obj := NativeUInt(Entry^.ObjectPointer);
          if (Obj = ProcessObject) and (Entry^.ObjectTypeIndex = ProcessType) then
          begin
            AddHolder(Holders, PID, False, Obj, Entry^.GrantedAccess, Entry^.HandleValue);
            Obs := Default(TObservedHandle);
            Obs.OwnerPID := PID;
            Obs.ObjectIdentity := Obj;
            Obs.HandleValue := Entry^.HandleValue;
            Obs.GrantedAccess := Entry^.GrantedAccess;
            Obs.Attributes := Entry^.HandleAttributes;
            Observed.Add(Obs);
          end
          else if TokenValid and (Obj = TokenObject) and
                  (Entry^.ObjectTypeIndex = TokenType) then
          begin
            Tok := Default(TObservedTokenHandle);
            Tok.OwnerPID := PID;
            Tok.TokenObject := Obj;
            Tok.GrantedAccess := Entry^.GrantedAccess;
            TokenObserved.Add(Tok);
          end
          else if ThreadsValid and ThreadObjects.TryGetValue(Obj, ThisType) then
          begin
            if ThisType = Entry^.ObjectTypeIndex then
            begin
              AddHolder(Holders, PID, True, Obj, Entry^.GrantedAccess, Entry^.HandleValue);
              Obs := Default(TObservedHandle);
              Obs.OwnerPID := PID;
              Obs.ObjectIdentity := Obj;
              Obs.HandleValue := Entry^.HandleValue;
              Obs.GrantedAccess := Entry^.GrantedAccess;
              Obs.Attributes := Entry^.HandleAttributes;
              Obs.IsThread := True;
              Observed.Add(Obs);
            end;
          end;
        end;
      end;
      Entry := PNativeHandleEntry(NativeUInt(Entry) + NativeUInt(SizeOf(TNativeHandleEntry)));
    end;
    TotalHandles := Count;
    Result := True;
  finally
    ThreadObjects.Free;
    KnownThreads.Free;
    if not Result then
    begin
      ClearCollected(Holders, Observed, TokenObserved);
      TotalHandles := 0;
      TokenValid := False;
      ThreadsValid := False;
    end;
  end;
end;

end.
