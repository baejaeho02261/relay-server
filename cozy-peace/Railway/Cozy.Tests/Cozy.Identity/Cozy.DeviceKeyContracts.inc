{ Included only in the isolated device-identity probe. Calls the production
  staging helper without rebinding any production API pointer or creating a
  persistent key. No synthetic result is used as TPM evidence. }
var
  DeviceKeyContractPublished: PNativeUInt;
  DeviceKeyContractPhase, DeviceKeyContractFailAt, DeviceKeyContractFreed: Integer;
  DeviceKeyContractNullHandle: Boolean;

procedure DeviceKeyContractRequire(Value: Boolean; const Name: string);
begin
  if not Value then raise EInvalidOpException.Create(CozyText_DeviceKeyContracts_DEVICE_KEY_CONTRACT_40aade68 + Name);
end;

function DeviceKeyContractStep: LongInt;
begin
  DeviceKeyContractRequire((DeviceKeyContractPublished <> nil) and
    (DeviceKeyContractPublished^ = 0), CozyText_DeviceKeyContracts_PARTIAL_KEY_PUBLISHED_1d6d9a04);
  Inc(DeviceKeyContractPhase);
  if DeviceKeyContractPhase = DeviceKeyContractFailAt then Result := -1
  else Result := 0;
end;

function DeviceKeyContractCreate(Provider: NativeUInt; out Key: NativeUInt;
  Algorithm, Name: PWideChar; Legacy, Flags: Cardinal): LongInt; stdcall;
begin
  DeviceKeyContractRequire((Provider = 77) and (string(Algorithm) = CozyText_DeviceKeyContracts_RSA_818939c0) and
    (Name = nil) and (Legacy = 0) and (Flags = 0), CozyText_DeviceKeyContracts_CREATE_ARGUMENTS_77828785);
  Key := $A17;
  if DeviceKeyContractNullHandle then Key := 0;
  { Deliberately return an owned handle even for a create error. }
  Result := DeviceKeyContractStep;
end;

function DeviceKeyContractSet(Handle: NativeUInt; Name: PWideChar; Data: PByte;
  Size, Flags: Cardinal): LongInt; stdcall;
begin
  DeviceKeyContractRequire((Handle = $A17) and (Data <> nil) and
    (Size = SizeOf(Cardinal)) and (Flags = 0), CozyText_DeviceKeyContracts_SET_ARGUMENTS_1e5327d7);
  if DeviceKeyContractPhase = 1 then
    DeviceKeyContractRequire((string(Name) = CozyText_DeviceKeyContracts_Length_d23188d5) and
      (PCardinal(Data)^ = 2048), CozyText_DeviceKeyContracts_KEY_LENGTH_894823dc)
  else
    DeviceKeyContractRequire((DeviceKeyContractPhase = 2) and
      (string(Name) = CozyText_DeviceKeyContracts_PCP_KEY_USAGE_POLICY_b443c013) and
      (PCardinal(Data)^ = 8), CozyText_DeviceKeyContracts_KEY_USAGE_7cb90840);
  Result := DeviceKeyContractStep;
end;

function DeviceKeyContractFinalize(Key: NativeUInt; Flags: Cardinal): LongInt; stdcall;
begin
  DeviceKeyContractRequire((Key = $A17) and (Flags = Silent) and
    (DeviceKeyContractPhase = 3), CozyText_DeviceKeyContracts_FINALIZE_ARGUMENTS_5b4976e6);
  Result := DeviceKeyContractStep;
end;

function DeviceKeyContractFree(Key: NativeUInt): LongInt; stdcall;
begin
  DeviceKeyContractRequire((Key = $A17) and
    (DeviceKeyContractPublished^ = 0), CozyText_DeviceKeyContracts_CLEANUP_OWNERSHIP_8b46ced9);
  Inc(DeviceKeyContractFreed);
  Result := 0;
end;

{ Pure parser contracts. A synthetic TPMS_ATTEST is never submitted as TPM
  evidence. The platform test still needs a real activated key and server. }
procedure RunDeviceKeyQuoteContracts;
var Qualifier,Pcrs,Digest,Attest,Other,Signer:TBytes;
    I,ClockSafeOffset,SelectionOffset:Integer;Rejected:Boolean;
begin
 try
  SetLength(Qualifier,32);SetLength(Pcrs,256);SetLength(Signer,34);
  for I:=0 to High(Qualifier) do Qualifier[I]:=Byte(I+1);
  for I:=0 to High(Pcrs) do Pcrs[I]:=Byte(I);
  Signer[1]:=$0B;
  Digest:=DeviceSHA256(Pcrs);
  Put(Attest,$FF544347,4);Put(Attest,$8018,2);
  Put(Attest,Length(Signer),2);Append(Attest,Signer);
  Put(Attest,Length(Qualifier),2);Append(Attest,Qualifier);
  Put(Attest,0,8);Put(Attest,0,4);Put(Attest,0,4);
  ClockSafeOffset:=Length(Attest);Put(Attest,1,1);Put(Attest,0,8);
  Put(Attest,1,4);Put(Attest,$0B,2);Put(Attest,3,1);
  SelectionOffset:=Length(Attest);Put(Attest,$FF,1);Put(Attest,0,2);
  Put(Attest,Length(Digest),2);Append(Attest,Digest);
  DeviceKeyContractRequire(QuoteMatches(Attest,Qualifier,Pcrs),CozyText_DeviceKeyContracts_QUOTE_VALID_REJECTED_097c753f);
  DeviceKeyContractRequire(not QuoteMatches(Attest,nil,Pcrs),CozyText_DeviceKeyContracts_QUOTE_EMPTY_QUALIFIER_ACCEPTED_d61e5ddd);
  DeviceKeyContractRequire(not QuoteMatches(Attest,Copy(Qualifier,0,31),Pcrs),CozyText_DeviceKeyContracts_QUOTE_SHORT_QUALIFIER_ACCEPTED_103f5f16);
  DeviceKeyContractRequire(not QuoteMatches(Attest,Qualifier,Copy(Pcrs,0,255)),CozyText_DeviceKeyContracts_QUOTE_SHORT_PCRS_ACCEPTED_2a5c167c);
  for I:=0 to Length(Attest)-1 do
  begin
   Other:=Copy(Attest,0,I);Rejected:=False;
   try Rejected:=not QuoteMatches(Other,Qualifier,Pcrs);
   except on E:EDeviceSecurity do Rejected:=True;end;
   DeviceKeyContractRequire(Rejected,CozyText_DeviceKeyContracts_QUOTE_TRUNCATION_ACCEPTED_43a91772);
  end;
  Other:=Copy(Attest);Put(Other,0,1);
  DeviceKeyContractRequire(not QuoteMatches(Other,Qualifier,Pcrs),CozyText_DeviceKeyContracts_QUOTE_TRAILING_ACCEPTED_eeb843e4);
  Other:=Copy(Attest);Other[ClockSafeOffset]:=0;
  DeviceKeyContractRequire(QuoteMatches(Other,Qualifier,Pcrs),CozyText_DeviceKeyContracts_QUOTE_UNKNOWN_CLOCK_REJECTED_cfdd2d8a);
  Other[ClockSafeOffset]:=2;
  DeviceKeyContractRequire(not QuoteMatches(Other,Qualifier,Pcrs),CozyText_DeviceKeyContracts_QUOTE_INVALID_CLOCK_ACCEPTED_ce227c21);
  Other:=Copy(Attest);Other[SelectionOffset]:=$7F;
  DeviceKeyContractRequire(not QuoteMatches(Other,Qualifier,Pcrs),CozyText_DeviceKeyContracts_QUOTE_WRONG_PCR_SELECTION_dd2c0ffc);
  Qualifier[0]:=Qualifier[0] xor 1;
  DeviceKeyContractRequire(not QuoteMatches(Attest,Qualifier,Pcrs),CozyText_DeviceKeyContracts_QUOTE_WRONG_NONCE_ACCEPTED_1bfc8138);
  Qualifier[0]:=Qualifier[0] xor 1;Pcrs[0]:=Pcrs[0] xor 1;
  DeviceKeyContractRequire(not QuoteMatches(Attest,Qualifier,Pcrs),CozyText_DeviceKeyContracts_QUOTE_PCR_RACE_ACCEPTED_5342b929);
 finally
  WipeBytes(Qualifier);WipeBytes(Pcrs);WipeBytes(Digest);
  WipeBytes(Attest);WipeBytes(Other);WipeBytes(Signer);
 end;
end;

procedure RunDeviceKeyConstructionContracts;
var Key: NativeUInt; FailAt: Integer; Rejected: Boolean;
begin
  Key := 0;
  DeviceKeyContractPublished := @Key;
  DeviceKeyContractNullHandle := False;
  try
    for FailAt := 1 to 4 do
    begin
      Key := 0; DeviceKeyContractPhase := 0;
      DeviceKeyContractFailAt := FailAt; DeviceKeyContractFreed := 0;
      Rejected := False;
      try
        EnsureAttestationKey(Key, 77, DeviceKeyContractCreate,
          DeviceKeyContractSet, DeviceKeyContractFinalize, DeviceKeyContractFree);
      except on E: EDeviceSecurity do Rejected := True; end;
      DeviceKeyContractRequire(Rejected and (Key = 0) and
        (DeviceKeyContractPhase = FailAt) and (DeviceKeyContractFreed = 1),
        CozyText_DeviceKeyContracts_FAILED_STAGE_NOT_ROLLED_BACK_3a860729);
      DeviceKeyContractPhase := 0; DeviceKeyContractFailAt := 0;
      EnsureAttestationKey(Key, 77, DeviceKeyContractCreate,
        DeviceKeyContractSet, DeviceKeyContractFinalize, DeviceKeyContractFree);
      DeviceKeyContractRequire((Key = $A17) and (DeviceKeyContractPhase = 4) and
        (DeviceKeyContractFreed = 1), CozyText_DeviceKeyContracts_RETRY_NOT_FINALIZED_28fc1288);
      EnsureAttestationKey(Key, 77, DeviceKeyContractCreate,
        DeviceKeyContractSet, DeviceKeyContractFinalize, DeviceKeyContractFree);
      DeviceKeyContractRequire((DeviceKeyContractPhase = 4) and
        (DeviceKeyContractFreed = 1), CozyText_DeviceKeyContracts_COMMITTED_KEY_REINITIALIZED_102eaf2a);
    end;
    Key := 0; DeviceKeyContractPhase := 0; DeviceKeyContractFreed := 0;
    DeviceKeyContractNullHandle := True; Rejected := False;
    try
      EnsureAttestationKey(Key, 77, DeviceKeyContractCreate,
        DeviceKeyContractSet, DeviceKeyContractFinalize, DeviceKeyContractFree);
    except on E: EDeviceSecurity do Rejected := True; end;
    DeviceKeyContractRequire(Rejected and (Key = 0) and
      (DeviceKeyContractPhase = 1) and (DeviceKeyContractFreed = 0),
      CozyText_DeviceKeyContracts_NULL_KEY_ACCEPTED_033ca9c1);
  finally
    DeviceKeyContractPublished := nil;
    DeviceKeyContractNullHandle := False;
  end;
  RunDeviceKeyQuoteContracts;
end;
