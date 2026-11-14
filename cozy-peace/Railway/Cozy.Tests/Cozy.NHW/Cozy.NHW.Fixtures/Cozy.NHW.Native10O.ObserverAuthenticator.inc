var
  O10Mode, O10Closed: Integer;
function O10Random(Algorithm: THandle; Buffer: Pointer;
  Bytes, Flags: Cardinal): LongInt; stdcall;
begin
  FillChar(Buffer^, Bytes, $A5);
  if O10Mode = 2 then raise Exception.Create('injected random exception');
  if O10Mode = 1 then Result := -1 else Result := 0;
end;
function O10Open(out Provider: THandle; Algorithm, ImplName: PWideChar;
  Flags: Cardinal): LongInt; stdcall;
begin
  Provider := 77;
  if O10Mode = 3 then Result := -1 else Result := 0;
end;
function O10Hash(Provider: THandle; Secret: Pointer;
  SecretSize: Cardinal; Input: Pointer; InputSize: Cardinal;
  Output: Pointer; OutputSize: Cardinal): LongInt; stdcall;
begin
  FillChar(Output^, OutputSize, $5A);
  if O10Mode = 5 then raise Exception.Create('injected hash exception');
  if O10Mode = 4 then Result := -1 else Result := 0;
end;
function O10Close(Provider: THandle; Flags: Cardinal): LongInt; stdcall;
begin
  Inc(O10Closed);
  if O10Mode = 7 then raise Exception.Create('injected close exception');
  if O10Mode = 6 then Result := -1 else Result := 0;
end;
const
  O10KnownMAC: TObserverSessionMAC = ($77, $B0, $34, $DD, $0A, $76, $05, $64, $B3, $FC, $B5, $08, $E6, $7F, $A4, $D3, $8F, $9C, $2B, $4C, $F6, $AA, $61, $E7, $BC, $8D, $57, $9B, $8A, $93, $D9, $1A);

function TestObserverAuthenticator10O(out Failure: string; out Checks: Integer): Boolean;
var
  Key, ZeroKey, SavedKey: TObserverSessionKey;
  MAC, ZeroMAC: TObserverSessionMAC;
  Proof: TObserverSessionEvidence;
  I: Integer;
  Raised: Boolean;
  procedure Check(Value: Boolean; const Text: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Text);
  end;

begin
  Result := False; Failure := ''; Checks := 0;
  ZeroKey := Default(TObserverSessionKey); ZeroMAC := Default(TObserverSessionMAC);
  Proof := Default(TObserverSessionEvidence); Key := ZeroKey; MAC := ZeroMAC;
  try
    try
      TestRandom := O10Random; TestOpen := O10Open; TestHash := O10Hash; TestClose := O10Close;
      O10Mode := 1; FillChar(Key, SizeOf(Key), $CC);
      Check(not NHWCreateSessionKey(Key), 'RNG status failure rejected');
      Check(CompareMem(@Key, @ZeroKey, SizeOf(Key)), 'partial RNG result never published');
      O10Mode := 2; Raised := False;
      try NHWCreateSessionKey(Key); except on X: Exception do Raised := True; end;
      Check(Raised and CompareMem(@Key, @ZeroKey, SizeOf(Key)), 'RNG exception cleans output');
      O10Mode := 0; Check(NHWCreateSessionKey(Key) and (Key[0] = $A5), 'successful RNG commits complete key');
      SavedKey := Key;
      O10Mode := 3; O10Closed := 0;
      Check(not NHWSessionMAC(Key, Proof, MAC), 'provider failure rejected');
      Check((O10Closed = 0) and CompareMem(@MAC, @ZeroMAC, SizeOf(MAC)), 'failed open has no owned close or published MAC');
      O10Mode := 4; O10Closed := 0;
      Check(not NHWSessionMAC(Key, Proof, MAC), 'partial hash failure rejected');
      Check((O10Closed = 1) and CompareMem(@MAC, @ZeroMAC, SizeOf(MAC)), 'hash failure closes owned provider and clears output');
      O10Mode := 5; O10Closed := 0; Raised := False;
      try NHWSessionMAC(Key, Proof, MAC); except on X: Exception do Raised := True; end;
      Check(Raised and (O10Closed = 1) and CompareMem(@MAC, @ZeroMAC, SizeOf(MAC)), 'hash exception closes and clears');
      O10Mode := 6; O10Closed := 0;
      Check(not NHWSessionMAC(Key, Proof, MAC) and (O10Closed = 1), 'close failure invalidates result without retry');
      Check(CompareMem(@MAC, @ZeroMAC, SizeOf(MAC)), 'close failure cannot publish MAC');
      O10Mode := 7; Raised := False;
      try NHWSessionMAC(Key, Proof, MAC); except on X: Exception do Raised := True; end;
      Check(Raised and CompareMem(@MAC, @ZeroMAC, SizeOf(MAC)), 'close exception clears output');
      O10Mode := 0;
      Check(NHWSessionMAC(Key, Proof, MAC) and (MAC[0] = $5A), 'complete successful MAC published');
      Check(CompareMem(@Key, @SavedKey, SizeOf(Key)), 'caller key is read-only');
      TestRandom := nil; TestOpen := nil; TestHash := nil; TestClose := nil;
      for I := 0 to High(Key) do Key[I] := Byte(I);
      Proof.Sequence := 2; Proof.OwnerPID := 123; Proof.ObserverPID := 456;
      Proof.OwnerCreated := 100; Proof.ObservedCreation := 100; Proof.ObservedTick := 200; Proof.State := 1;
      Check(SizeOf(Proof) = 44, 'packed evidence ABI unchanged');
      Check(NHWSessionMAC(Key, Proof, MAC), 'real CNG HMAC computes');
      Check(CompareMem(@MAC, @O10KnownMAC, SizeOf(MAC)), 'independent SHA256 HMAC known-answer vector');
      Check(NHWVerifySessionMAC(Key, Proof, MAC), 'real CNG verification');
      Inc(Proof.ObserverPID);
      Check(not NHWVerifySessionMAC(Key, Proof, MAC), 'changed evidence rejected');
      O10Mode := 4; TestHash := O10Hash;
      Check(not NHWVerifySessionMAC(Key, Proof, MAC), 'verification never accepts failed HMAC');
      ObserverWipe(@Key[0], SizeOf(Key));
      Check(CompareMem(@Key, @ZeroKey, SizeOf(Key)), 'explicit wipe clears owned key buffer');
      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    TestRandom := nil; TestOpen := nil; TestHash := nil; TestClose := nil;
    ObserverWipe(@Key[0], SizeOf(Key)); ObserverWipe(@SavedKey[0], SizeOf(SavedKey));
    ObserverWipe(@MAC[0], SizeOf(MAC));
  end;
end;
