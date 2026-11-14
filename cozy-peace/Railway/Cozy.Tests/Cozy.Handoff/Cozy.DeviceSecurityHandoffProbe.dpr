program Cozy_DeviceSecurityHandoffProbe;

{$APPTYPE CONSOLE}
{$R+}
{$Q+}

uses
{ Cozy central text imports. }
  Cozy.Strings.Crypto in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Crypto.pas',
  Cozy.Strings.Handoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Handoff.pas',
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Lifecycle in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Lifecycle.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.Security in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Security.pas',
  Cozy.Strings.TestsHandoff in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsHandoff.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

  System.SysUtils, Cozy.Api.Pointer, Cozy.Security, Cozy.Handoff.Crypto;

{ Windows-only production CNG probe: distinct non-exportable A/B/O keys and
  one-use V3 delegation contract. No server or persistent key is created. }

procedure Check(Condition: Boolean; const MessageText: string);
begin
  if not Condition then raise EInvalidOpException.Create(MessageText);
end;

procedure MustReject(const Action: TProc);
var Rejected: Boolean;
begin
  Rejected := False;
  try Action; except on E: EDeviceSecurity do Rejected := True; end;
  Check(Rejected, CozyText_DeviceSecurityHandoffProbe_Invalid_delegation_operation_was_accepted_988b6341);
end;

procedure MustRejectClosed(const Action: TProc);
var Rejected: Boolean;
begin
  Rejected := False;
  try Action;
  except on E: EInvalidOpException do Rejected := E.Message = CozyText_DeviceSecurityHandoffProbe_OBJECT_CLOSING_be8ab3c2; end;
  Check(Rejected, CozyText_DeviceSecurityHandoffProbe_Closed_key_admitted_a_new_operation_10ddc4cc);
end;

procedure Delegate(Parent, Child: TDeviceSecurity; const Role, Claim: string);
var Nonce, Canonical, Signature, Expected, Actual: string;
begin
  Nonce := HandoffRandomNonce;
  try
    Canonical := HandoffCanonical(CozyText_DeviceSecurityHandoffProbe_DELEGATION_6e14202b, Role, Claim, Child.DeviceID, Nonce);
    Signature := Parent.Sign(Canonical);
    Child.AcceptDelegation(Parent.DeviceID, Role, Claim, Nonce, Signature);
    Check(Child.ParentDeviceID = Parent.DeviceID, CozyText_DeviceSecurityHandoffProbe_Parent_binding_changed_f1f6a147);
    Canonical := HandoffCanonical(CozyText_DeviceSecurityHandoffProbe_CLAIM_e324b6bf, Role, Claim, Child.DeviceID, Nonce);
    Expected := Child.Sign(Canonical);
    Actual := Child.SignHandoffClaim(Role, Claim);
    Check(Actual = Expected, CozyText_DeviceSecurityHandoffProbe_Child_claim_domain_differs_f70c6b3b);
    MustReject(procedure begin Child.SignHandoffClaim(Role, Claim + CozyText_DeviceSecurityHandoffProbe_changed_52bc1648); end);
    MustReject(procedure begin Child.SignHandoffClaim('A', Claim); end);
    MustReject(procedure begin Child.AcceptDelegation(Parent.DeviceID, Role, Claim, Nonce, Signature); end);
    Child.CompleteHandoff;
    Check((Child.ParentDeviceID = '') and (Child.HandoffNonce = '') and
      (Child.DelegationSignature = ''), CozyText_DeviceSecurityHandoffProbe_Delegation_was_not_cleared_4fe1f19d);
    MustReject(procedure begin Child.SignHandoffClaim(Role, Claim); end);
    MustReject(procedure begin Child.AcceptDelegation(Parent.DeviceID, Role, Claim, Nonce, Signature); end);
  finally
    WipeText(Nonce); WipeText(Canonical); WipeText(Signature);
    WipeText(Expected); WipeText(Actual);
  end;
end;

procedure KnownCanonicalVector;
const
  Claim = CozyText_DeviceSecurityHandoffProbe_GAME_B85_CLAIM_V2_4729b503 + #10 + CozyText_DeviceSecurityHandoffProbe_contract_vector_ec26fa63 + #10 + CozyText_DeviceSecurityHandoffProbe_UTF_8_150b21f4;
  ClaimHash = CozyText_DeviceSecurityHandoffProbe_Digest_994e7fe7;
  KeyID = CozyText_DeviceSecurityHandoffProbe_Digest_b9affd9e;
  Nonce = CozyText_DeviceSecurityHandoffProbe_Digest_3e2691ee;
var Actual, Expected: string;
begin
  try
    Actual := HandoffCanonical(CozyText_DeviceSecurityHandoffProbe_DELEGATION_6e14202b, 'B', Claim, KeyID, Nonce);
    Expected := CozyText_DeviceSecurityHandoffProbe_GAME_HANDOFF_DELEGATION_V3_044e6310 + #10 + 'B' + #10 + ClaimHash + #10 + KeyID + #10 + Nonce;
    Check(Actual = Expected, CozyText_DeviceSecurityHandoffProbe_Known_UTF_8_delegation_canonical_differs_from_se_581c3fd9);
    Actual := HandoffCanonical(CozyText_DeviceSecurityHandoffProbe_CLAIM_e324b6bf, 'B', Claim, KeyID, Nonce);
    Expected := CozyText_DeviceSecurityHandoffProbe_GAME_HANDOFF_CLAIM_V3_3c418bab + #10 + 'B' + #10 + ClaimHash + #10 + KeyID + #10 + Nonce;
    Check(Actual = Expected, CozyText_DeviceSecurityHandoffProbe_Known_UTF_8_claim_canonical_differs_from_server__9059d0ae);
  finally WipeText(Actual); WipeText(Expected); end;
end;

procedure RunProbe;
var A, B, O: TDeviceSecurity;
begin
  A := nil; B := nil; O := nil;
  try
    A := TDeviceSecurity.Create; B := TDeviceSecurity.Create; O := TDeviceSecurity.Create;
    Check((A.DeviceID <> B.DeviceID) and (B.DeviceID <> O.DeviceID) and
      (A.DeviceID <> O.DeviceID), CozyText_DeviceSecurityHandoffProbe_Role_signing_keys_must_be_independent_397e1366);
    Check((DevicePublicKeyID(A.PublicKeyBlob) = A.DeviceID) and
      (DevicePublicKeyID(B.PublicKeyBlob) = B.DeviceID) and
      (DevicePublicKeyID(O.PublicKeyBlob) = O.DeviceID), CozyText_DeviceSecurityHandoffProbe_Key_identity_mismatch_1834d82c);
    Check((A.MachineID = B.MachineID) and (B.MachineID = O.MachineID), CozyText_DeviceSecurityHandoffProbe_Machine_binding_changed_cb9b0486);
    Delegate(A, B, 'B', CozyText_DeviceSecurityHandoffProbe_Native_probe_parent_to_B_claim_bb12827b);
    FreeAndNil(A);
    Delegate(B, O, 'O', CozyText_DeviceSecurityHandoffProbe_Native_probe_parent_to_O_claim_da536bc8);
    B.Close;
    MustRejectClosed(procedure begin B.Sign(CozyText_DeviceSecurityHandoffProbe_afterclose_2cb9e7cd); end);
    FreeAndNil(B);
    Check(Length(O.Sign(CozyText_DeviceSecurityHandoffProbe_Independent_O_still_owns_its_key_80af392b)) = 344, CozyText_DeviceSecurityHandoffProbe_O_signing_failed_6d9ac619);
    O.Close;
    MustRejectClosed(procedure begin O.CompleteHandoff; end);
    MustRejectClosed(procedure begin O.Sign(CozyText_DeviceSecurityHandoffProbe_afterclose_2cb9e7cd); end);
    Writeln(CozyText_DeviceSecurityHandoffProbe_PASS_independent_role_keys_bound_delegation_wron_771494cb);
  finally O.Free; B.Free; A.Free; end;
end;

begin
  try
    SealApiPointerStorage;
    Check(ApiPointerStorageIsSealed, CozyText_DeviceSecurityHandoffProbe_API_pointer_storage_is_not_read_only_21a7b259);
    KnownCanonicalVector;
    RunProbe;
  except
    on E: Exception do begin
      Writeln(CozyText_DeviceSecurityHandoffProbe_FAIL_a5da5561, E.ClassName, CozyText_DeviceSecurityHandoffProbe_Text_f4d22b79, E.Message);
      ExitCode := 1;
    end;
  end;
end.
