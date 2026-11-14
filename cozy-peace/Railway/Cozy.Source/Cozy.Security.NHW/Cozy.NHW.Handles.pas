unit Cozy.NHW.Handles;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Types,
  Cozy.NHW.Native,
  Cozy.NHW.WinPointers;

function CollectHolders(TargetHandle: THandle; TargetPID: Cardinal;
  ThreadHandles: TList<THandle>; ThreadsEnumerated: Boolean;
  Holders: TDictionary<string, TTargetHolder>;
  Observed: TList<TObservedHandle>;
  TokenReference: THandle; TokenObserved: TList<TObservedTokenHandle>;
  IPCTypes: TDictionary<Word, TIPCObjectKind>;
  IPCObserved: TList<TIPCObservation>;
  out IPCSnapshotValid: Boolean;
  out TokenSnapshotValid: Boolean;
  out ThreadSnapshotValid: Boolean;
  out TotalHandles: NativeUInt; out Reason: string): Boolean;

{$IFDEF NHW_HARDENING_TESTS}
function TestHandleHardening(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.IPCNative, Cozy.NHW.HandleSnapshot.Decoder;

function CollectHolders(TargetHandle: THandle; TargetPID: Cardinal;
  ThreadHandles: TList<THandle>; ThreadsEnumerated: Boolean;
  Holders: TDictionary<string, TTargetHolder>;
  Observed: TList<TObservedHandle>;
  TokenReference: THandle; TokenObserved: TList<TObservedTokenHandle>;
  IPCTypes: TDictionary<Word, TIPCObjectKind>;
  IPCObserved: TList<TIPCObservation>;
  out IPCSnapshotValid: Boolean;
  out TokenSnapshotValid: Boolean;
  out ThreadSnapshotValid: Boolean;
  out TotalHandles: NativeUInt; out Reason: string): Boolean;
var
  Data: TBytes;
  Failure: TNTStatus;
  CurrentPID: Cardinal;
begin
  Result := False;
  Reason := '';
  TotalHandles := 0;
  IPCSnapshotValid := False;
  TokenSnapshotValid := False;
  ThreadSnapshotValid := False;
  ClearCollected(Holders, Observed, TokenObserved);
  if IPCObserved <> nil then IPCObserved.Clear;
  try
    if not FetchSnapshot(Data, Failure) then
    begin
      Reason := 'Native handle enumeration failed NTSTATUS=0x' +
        IntToHex(Cardinal(Failure), 8);
      Exit;
    end;
    CurrentPID := WinCurrentProcessId;
    if not ParseHandleSnapshot(Data, CurrentPID, TargetHandle, TargetPID,
      ThreadHandles, ThreadsEnumerated, Holders, Observed, TokenReference,
      TokenObserved, TokenSnapshotValid, ThreadSnapshotValid, TotalHandles, Reason) then Exit;
    if (IPCTypes <> nil) and (IPCObserved <> nil) then
    begin
      IPCSnapshotValid := CaptureIPCObjects(Data, TotalHandles, TargetPID,
        IPCTypes, IPCObserved);
      if not IPCSnapshotValid then IPCObserved.Clear;
    end;
    Result := True;
  finally
    if not Result then
    begin
      ClearCollected(Holders, Observed, TokenObserved);
      if IPCObserved <> nil then IPCObserved.Clear;
      TotalHandles := 0;
      IPCSnapshotValid := False;
      TokenSnapshotValid := False;
      ThreadSnapshotValid := False;
    end;
  end;
end;

{$IFDEF NHW_HARDENING_TESTS}
function TestHandleHardening(out Failure: string; out Checks: Integer): Boolean;
var
  Data: TBytes;
  H: TDictionary<string, TTargetHolder>;
  O: TList<TObservedHandle>;
  T: TList<TObservedTokenHandle>;
  R: TList<THandle>;
  Entry: TNativeHandleEntry;
  Total, N: NativeUInt;
  TV, RV, OK: Boolean;
  Why: string;

  procedure Check(Condition: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Condition then raise Exception.Create(Text);
  end;

  procedure Put(Index: Integer; Owner, Handle, Obj: NativeUInt; Kind: Word);
  begin
    Entry := Default(TNativeHandleEntry);
    Entry.OwnerPID := Owner;
    Entry.HandleValue := Handle;
    Entry.ObjectPointer := Pointer(Obj);
    Entry.ObjectTypeIndex := Kind;
    Entry.GrantedAccess := ACCESS_VM_READ;
    Move(Entry, Data[16 + Index * SizeOf(Entry)], SizeOf(Entry));
  end;

  function Parse: Boolean;
  begin
    Result := ParseHandleSnapshot(Data, 10, 20, 30, R, True,
      H, O, 24, T, TV, RV, Total, Why);
  end;

begin
  Result := False;
  Failure := '';
  Checks := 0;
  H := nil; O := nil; T := nil; R := nil;
  try
    try
      H := TDictionary<string, TTargetHolder>.Create;
      O := TList<TObservedHandle>.Create;
      T := TList<TObservedTokenHandle>.Create;
      R := TList<THandle>.Create;
      R.Add(28); R.Add(28); // same reference repeated is not an incomplete snapshot
      N := 6;
      SetLength(Data, 16 + Integer(N) * SizeOf(Entry));
      Move(N, Data[0], SizeOf(N));
      Put(0, 10, 20, $100000, 7);
      Put(1, 10, 24, $200000, 9);
      Put(2, 10, 28, $300000, 8);
      Put(3, 40, 40, $100000, 7);
      Put(4, 40, 44, $200000, 9);
      Put(5, 40, 48, $300000, 8);
      OK := Parse;
      Check(OK and TV and RV and (Total = 6), 'valid handle snapshot');
      Check((H.Count = 2) and (O.Count = 2) and (T.Count = 1), 'all observation categories preserved');
      Put(5, 40, 48, $300000, 99);
      Check(Parse and (O.Count = 1), 'object type mismatch is not a thread match');
      Put(2, 10, 28, 0, 8);
      Check(Parse and not RV and (O.Count = 1), 'redacted thread identity is incomplete');
      Put(2, 10, 28, $300000, 8);
      Put(5, 10, 20, $400000, 7);
      Check(not Parse, 'duplicate target handle rejected');
      Check((H.Count = 0) and (O.Count = 0) and (T.Count = 0) and
        (Total = 0) and not TV and not RV, 'failure clears all published state');
      Put(5, 40, 48, $300000, 8);
      N := High(NativeUInt); Move(N, Data[0], SizeOf(N));
      Check(not Parse, 'oversized count rejected');
      N := 0; Move(N, Data[0], SizeOf(N));
      Check(not Parse, 'empty snapshot rejected when a target handle must exist');
      SetLength(Data, 15);
      Check(not Parse, 'truncated header rejected');
      Check(not RealReference(THandle(High(NativeUInt))), 'pseudo handle rejected');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    R.Free; T.Free; O.Free; H.Free;
  end;
end;
{$ENDIF}

end.
