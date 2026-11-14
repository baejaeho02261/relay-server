program Cozy_ServerProfileProbe;
{$APPTYPE CONSOLE}
{$RANGECHECKS ON}
{$OVERFLOWCHECKS ON}
{$B-}
uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Network in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Network.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsNetwork in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsNetwork.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}
 System.SysUtils, System.JSON, System.DateUtils,
  Cozy.Server.Profile in '..\..\Cozy.Source\Cozy.Network\Cozy.Server.Profile.pas';
{$I Cozy.ServerProfileFixture.inc}
var Checks: Integer;
procedure Check(Condition: Boolean; const Name: string);
begin if not Condition then raise Exception.Create(CozyText_ServerProfileProbe_FAIL_a08f1a49+Name); Inc(Checks); end;
function Obj(const Text: string): TJSONObject;
begin Result := TJSONObject(TJSONObject.ParseJSONValue(Text)); if Result=nil then raise Exception.Create(CozyText_ServerProfileProbe_FIXTURE_JSON_fb0b8182); end;
function Change(const Text, Name: string; Value: TJSONValue): string;
var O: TJSONObject; Old: TJSONPair;
begin
  O := Obj(Text);
  try Old := O.RemovePair(Name); Old.Free; O.AddPair(Name,Value); Result:=O.ToJSON;
  finally O.Free; end;
end;
function Remove(const Text, Name: string): string;
var O: TJSONObject; Old: TJSONPair;
begin O:=Obj(Text);try Old:=O.RemovePair(Name);Old.Free;Result:=O.ToJSON;finally O.Free;end;end;
procedure RejectProfile(const Text, Name: string);
var P: TConnectServerProfile; Rejected: Boolean;
begin
  P:=nil;Rejected:=False;
  try P:=TConnectServerProfile.FromJSON(Text);
  except on E:EConnectProfile do Rejected:=True;end;
  P.Free;Check(Rejected,Name+CozyText_ServerProfileProbe_parse_554f1cfa);
  Rejected:=False;
  try TConnectServerProfile.CanonicalizeJSON(Text);
  except on E:EConnectProfile do Rejected:=True;end;
  Check(Rejected,Name+CozyText_ServerProfileProbe_canonical_3cabf776);
end;
procedure RejectPeer(Profile: TConnectServerProfile; const Pin: string);
var Rejected:Boolean;
begin
  Rejected:=False;
  try Profile.CheckTlsPeer(Pin);
  except on E:EInvalidOpException do Rejected:=True;end;
  Check(Rejected,CozyText_ServerProfileProbe_old_or_unknown_peer_rejected_641a8029);
end;
function Plan(Profile:TConnectServerProfile; const CurrentPin,NextPin:string;
  Issued,NotBefore,OldNotAfter:Int64):string;
var O:TJSONObject;
begin
  O:=TJSONObject.Create;
  try
    O.AddPair(CozyText_ServerProfileProbe_version_c0967ed3,TJSONNumber.Create(1));O.AddPair(CozyText_ServerProfileProbe_generation_2a7978f9,TJSONNumber.Create(1));
    O.AddPair(CozyText_ServerProfileProbe_host_9953607d,Profile.Host);O.AddPair(CozyText_ServerProfileProbe_port_ffc7186e,TJSONNumber.Create(Profile.Port));
    O.AddPair(CozyText_ServerProfileProbe_serverKeyId_8f8fc712,Profile.ServerKeyId);O.AddPair(CozyText_ServerProfileProbe_tlsServerName_c7ba796b,Profile.TlsServerName);
    O.AddPair(CozyText_ServerProfileProbe_currentPin_a59bb634,CurrentPin);O.AddPair(CozyText_ServerProfileProbe_nextPin_957c104f,NextPin);
    O.AddPair(CozyText_ServerProfileProbe_issuedAt_9295085b,TJSONNumber.Create(Issued));O.AddPair(CozyText_ServerProfileProbe_notBefore_31a8ad7d,TJSONNumber.Create(NotBefore));
    O.AddPair(CozyText_ServerProfileProbe_oldNotAfter_83376fb6,TJSONNumber.Create(OldNotAfter));Result:=O.ToJSON;
  finally O.Free;end;
end;
function State(const PlanText:string; Floor:Int64; const Retired:string=''):string;
var O:TJSONObject;
begin
  O:=TJSONObject.Create;
  try O.AddPair(CozyText_ServerProfileProbe_contract_6a8ded32,CozyText_ServerProfileProbe_GAME_TLS_PIN_WINDOW_V1_f629c8a4);O.AddPair(CozyText_ServerProfileProbe_plan_3c3692ee,PlanText);
    O.AddPair(CozyText_ServerProfileProbe_floor_e5075f54,TJSONNumber.Create(Floor));O.AddPair(CozyText_ServerProfileProbe_retiredPins_ce3d6a3f,Retired);Result:=O.ToJSON;
  finally O.Free;end;
end;
function FloorOf(const ProfileText:string):Int64;
var O,S:TJSONObject;
begin
  O:=Obj(ProfileText);S:=nil;
  try S:=Obj(O.GetValue(CozyText_ServerProfileProbe_tlsPinState_6404dece).Value);Result:=StrToInt64(S.GetValue(CozyText_ServerProfileProbe_floor_e5075f54).Value);
  finally S.Free;O.Free;end;
end;
procedure Execute;
var P,C,R,Detached:TConnectServerProfile; Text,Canonical,Binding,First,Second,
  Root,NextPin,PlanText,Snap,Trusted,Name:string; O:TJSONObject; Pair:TJSONPair;
  Names:TArray<string>; I:Integer; D:TDateTime; NowMs:Int64; SameBytes:Boolean;
begin
  P:=nil;C:=nil;R:=nil;Detached:=nil;
  try
    P:=TConnectServerProfile.FromJSON(ServerProfileFixtureJSON);
    Binding:=P.BindingID;Canonical:=P.ToJSON;
    SameBytes:=TEncoding.UTF8.GetString(TEncoding.UTF8.GetBytes(Canonical))=Canonical;
    Check(SameBytes,CozyText_ServerProfileProbe_canonical_UTF8_bytes_roundtrip_5da1739f);
    Check(TConnectServerProfile.CanonicalizeJSON(Canonical)=Canonical,CozyText_ServerProfileProbe_fixed_profile_canonical_byte_identity_8b456e9f);
    R:=TConnectServerProfile.FromJSON(Canonical);Check(R.BindingID=Binding,CozyText_ServerProfileProbe_JSON_binding_identity_9a479a9b);FreeAndNil(R);
    C:=P.Clone;Check(C.BindingID=Binding,CozyText_ServerProfileProbe_clone_binding_identity_b7551bf1);
    Detached:=TConnectServerProfile.FromJSON(Canonical);
    Text:=Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_host_9953607d,TJSONString.Create(CozyText_ServerProfileProbe_PROFILE_Fixture_INVALID_f17c3c3b));
    R:=TConnectServerProfile.FromJSON(Text);Check(R.BindingID=Binding,CozyText_ServerProfileProbe_historical_uppercase_host_normalization_4653897d);FreeAndNil(R);
    Text:=Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_host_9953607d,TJSONString.Create(CozyText_ServerProfileProbe_127_0_0_1_7e5817a2));
    R:=TConnectServerProfile.FromJSON(Text);Check(R.Host=CozyText_ServerProfileProbe_127_0_0_1_7e5817a2,CozyText_ServerProfileProbe_IPv4_host_preserved_20fc9532);FreeAndNil(R);
    for I in TArray<Integer>.Create(1,65535) do
    begin Text:=Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_port_ffc7186e,TJSONNumber.Create(I));R:=TConnectServerProfile.FromJSON(Text);
      Check(R.Port=I,CozyText_ServerProfileProbe_valid_port_boundary_e0fe125e);FreeAndNil(R);end;
    O:=Obj(ServerProfileFixtureJSON);
    try
      SetLength(Names,O.Count);I:=0;for Pair in O do begin Names[I]:=Pair.JsonString.Value;Inc(I);end;
    finally O.Free;end;
    for Name in Names do
    begin
      RejectProfile(Remove(ServerProfileFixtureJSON,Name),CozyText_ServerProfileProbe_missing_8af4728b+Name);
      RejectProfile(Change(ServerProfileFixtureJSON,Name,TJSONNull.Create),CozyText_ServerProfileProbe_null_6e66fce8+Name);
      RejectProfile(Change(ServerProfileFixtureJSON,Name,TJSONObject.Create),CozyText_ServerProfileProbe_nested_09f7a8de+Name);
    end;
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_extra_4c9ed366,TJSONBool.Create(True)),CozyText_ServerProfileProbe_unknown_field_aae88956);
    Text:=Copy(ServerProfileFixtureJSON,1,Length(ServerProfileFixtureJSON)-1)+CozyText_ServerProfileProbe_host_profile_fixture_invalid_7fbc9cf5;
    RejectProfile(Text,CozyText_ServerProfileProbe_duplicate_field_3cf0ee68);
    RejectProfile(StringReplace(Text,CozyText_ServerProfileProbe_host_7092fc35,CozyText_ServerProfileProbe_h_u006fst_19cf3a95,[]),CozyText_ServerProfileProbe_escaped_duplicate_field_afa493cd);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_version_c0967ed3,TJSONNumber.Create(3)),CozyText_ServerProfileProbe_version_c0967ed3);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_protocol_f9bae232,TJSONString.Create(CozyText_ServerProfileProbe_GAME_CONNECT_3_d6055359)),CozyText_ServerProfileProbe_protocol_f9bae232);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_port_ffc7186e,TJSONString.Create(CozyText_ServerProfileProbe_443_440ee062)),CozyText_ServerProfileProbe_port_string_c611fc7d);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_port_ffc7186e,TJSONNumber.Create(0)),CozyText_ServerProfileProbe_zero_port_98100530);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_port_ffc7186e,TJSONNumber.Create(65536)),CozyText_ServerProfileProbe_large_port_96a17d85);
    RejectProfile(StringReplace(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_port_443_664f444e,CozyText_ServerProfileProbe_port_443_0_c24a0905,[]),CozyText_ServerProfileProbe_fraction_port_355bb8fc);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_host_9953607d,TJSONString.Create(CozyText_ServerProfileProbe_a_invalid_a712a31b)),CozyText_ServerProfileProbe_empty_host_label_d217b54a);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_tlsServerName_c7ba796b,TJSONString.Create(CozyText_ServerProfileProbe_UPPER_invalid_748a4897)),CozyText_ServerProfileProbe_TLS_uppercase_097b07d1);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_serverKeyId_8f8fc712,TJSONString.Create(StringOfChar('f',64))),CozyText_ServerProfileProbe_wrong_key_ID_4275e9c5);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_serverKeyId_8f8fc712,TJSONString.Create(UpperCase(P.ServerKeyId))),CozyText_ServerProfileProbe_uppercase_key_ID_66ee5587);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_serverPublicKey_5449c4d1,TJSONString.Create(P.ServerPublicKey+'=')),CozyText_ServerProfileProbe_noncanonical_public_key_3b97af6a);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_serverPublicKey_5449c4d1,TJSONString.Create(StringOfChar('A',376))),CozyText_ServerProfileProbe_invalid_public_key_structure_d9c0c3d4);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_tlsCertificateSha256_ff82a824,TJSONString.Create(StringOfChar('A',64))),CozyText_ServerProfileProbe_uppercase_pin_4c46ce0e);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_tlsPinState_6404dece,TJSONNumber.Create(0)),CozyText_ServerProfileProbe_state_type_25430ee7);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_tlsPinState_6404dece,TJSONString.Create('')),CozyText_ServerProfileProbe_empty_explicit_state_f364ce88);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_tlsPinState_6404dece,TJSONString.Create(CozyText_ServerProfileProbe_JsonFixture_17b2061a)),CozyText_ServerProfileProbe_state_shape_041c6b85);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_tlsPinState_6404dece,TJSONString.Create(StringOfChar('x',6145))),CozyText_ServerProfileProbe_oversized_state_ef3a8119);
    Root:=P.TlsCertificateSha256;NextPin:=StringOfChar('b',64);
    D:=Now;NowMs:=DateTimeToUnix(D,False)*1000+MilliSecondOf(D);
    PlanText:=Plan(P,Root,NextPin,NowMs-60000,NowMs-30000,NowMs+90000);
    C.LearnTlsPlan(PlanText,Root);P.SelectTlsPins(First,Second);
    Check((First=Root)and(Second=NextPin),CozyText_ServerProfileProbe_clone_learns_same_live_window_5cdaf563);
    Detached.SelectTlsPins(First,Second);Check((First=Root)and(Second=''),CozyText_ServerProfileProbe_JSON_copy_owns_independent_window_180f3647);
    Snap:=P.ToJSON;R:=TConnectServerProfile.FromJSON(Snap);
    Check(R.BindingID=Binding,CozyText_ServerProfileProbe_learned_state_binding_unchanged_d11f6f9b);
    R.SelectTlsPins(First,Second);Check((First=Root)and(Second=NextPin),CozyText_ServerProfileProbe_trusted_overlap_roundtrip_278bf145);
    Check(FloorOf(R.ToJSON)>=FloorOf(Snap),CozyText_ServerProfileProbe_trusted_floor_never_decreases_32fc336c);FreeAndNil(R);
    Canonical:=TConnectServerProfile.CanonicalizeJSON(Snap);
    Check(TConnectServerProfile.CanonicalizeJSON(Canonical)=Canonical,CozyText_ServerProfileProbe_fixed_pin_snapshot_byte_identity_b19eeb08);
    Trusted:=State(PlanText,NowMs+90000);
    Text:=Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_tlsPinState_6404dece,TJSONString.Create(Trusted));
    R:=TConnectServerProfile.FromJSON(Text);R.SelectTlsPins(First,Second);
    Check((First=NextPin)and(Second=''),CozyText_ServerProfileProbe_imported_floor_retires_old_pin_e7be1707);RejectPeer(R,Root);
    FreeAndNil(C);C:=R.Clone;FreeAndNil(R);
    C.CheckTlsPeer(NextPin);RejectPeer(C,Root);Check(C.BindingID=Binding,CozyText_ServerProfileProbe_clone_retains_retired_trust_after_parent_free_0d51c9be);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_tlsPinState_6404dece,TJSONString.Create(State(PlanText,NowMs-60001))),CozyText_ServerProfileProbe_floor_before_issuance_1ff5b52f);
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_tlsPinState_6404dece,TJSONString.Create(State(PlanText,NowMs,Root+'|'))),CozyText_ServerProfileProbe_retired_active_pin_7f3c5f48);
    PlanText:=Change(PlanText,CozyText_ServerProfileProbe_serverKeyId_8f8fc712,TJSONString.Create(StringOfChar('f',64)));
    RejectProfile(Change(ServerProfileFixtureJSON,CozyText_ServerProfileProbe_tlsPinState_6404dece,TJSONString.Create(State(PlanText,NowMs))),CozyText_ServerProfileProbe_pin_state_endpoint_mismatch_1618e90d);
  finally Detached.Free;R.Free;C.Free;P.Free;end;
end;
begin
  try Execute;Writeln(CozyText_ServerProfileProbe_SERVER_PROFILE_PROBE_PASS_26ba6208,Checks);Writeln(CozyText_ServerProfileProbe_Profile_and_pin_state_contracts_only_no_network__c75595a3);
  except on E:Exception do begin Writeln(E.ClassName+CozyText_ServerProfileProbe_Text_9304b830+E.Message);ExitCode:=1;end;end;
end.
