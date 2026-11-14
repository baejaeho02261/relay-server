unit Cozy.Strings.TestsProtection;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:134 }
  CozyText_Protection_VmProbe_000102030405060708090a0b_310ef8fb = '000102030405060708090a0b';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:63 }
  CozyText_Protection_VmProbe_32_bit_add_wrap_differs_690b3e92 = '32-bit add wrap differs.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:70 }
  CozyText_Protection_VmProbe_AND_OR_true_vector_differs_1e703cae = 'AND/OR true vector differs.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:59 }
  CozyText_Protection_VmProbe_A_gate_failed_9db26f35 = 'A gate failed.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:86 }
  CozyText_Protection_VmProbe_An_unsealed_probe_was_allowed_to_pass_protected__e1706eea = 'An unsealed probe was allowed to pass protected startup.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:60 }
  CozyText_Protection_VmProbe_Authorization_flag_ignored_27ebfd99 = 'Authorization flag ignored.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:71 }
  CozyText_Protection_VmProbe_Boolean_normalization_differs_efcceb03 = 'Boolean normalization differs.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:141 }
  CozyText_Protection_VmProbe_CNG_golden_plaintext_differs_8e94084a = 'CNG golden plaintext differs.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:85 }
  CozyText_Protection_VmProbe_COZY_PROTECTION_UNSEALED_c8a9fa8a = 'COZY_PROTECTION_UNSEALED';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:149 }
  CozyText_Protection_VmProbe_Changed_AAD_was_accepted_134e284b = 'Changed AAD was accepted.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:153 }
  CozyText_Protection_VmProbe_Ciphertext_bound_was_ignored_65f616af = 'Ciphertext bound was ignored.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:16 }
  CozyText_Protection_VmProbe_Digest_39845e50 = '43564d31040000000100030028001b000200020043000c00030001004f0019000400020068000a00';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:17 }
  CozyText_Protection_VmProbe_Digest_7ff6aaa6 = '01000201000000030101020100000003040102020100000003040b010001010702df9b5713080b';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:137 }
  CozyText_Protection_VmProbe_Digest_8150340c = '046dac62e5b38f3bef2ee2e5d58c1c4de2a3f35c95152b155b0691e0794962cb7575dd';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:138 }
  CozyText_Protection_VmProbe_Digest_888894de = '4206c1d65aee1edc6a05f6430dbe909b';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:97 }
  CozyText_Protection_VmProbe_Digest_8ac66bd5 = '89df5d165c7f9112ec382c707336cb655d95522cfca353a47ba9be5cb23f0951';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:95 }
  CozyText_Protection_VmProbe_Digest_bb1c396f = 'f25273322e7f9c33ae87e01816dc2fadf54a5f0aa3dbcc51eed81af45349f03a3';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:136 }
  CozyText_Protection_VmProbe_Digest_c0ca4812 = '436f7a7920564d20626f756e6465642061757468656e74696361746564206279746573';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:133 }
  CozyText_Protection_VmProbe_Digest_c860748e = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:135 }
  CozyText_Protection_VmProbe_Digest_eb22bd5d = '636f7a792d766d2d636e672d676f6c64656e2d7631';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:18 }
  CozyText_Protection_VmProbe_Digest_f8a6adcc = '010002000000000309080002ffffffff0a050002070000000b0100010104010106050b';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:96 }
  CozyText_Protection_VmProbe_Digest_f958c14c = '0b73883f9d8fd48425bf0fa308b4ef583a4e1200d41277fff336d2486fb7107';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:67 }
  CozyText_Protection_VmProbe_False_branch_differs_86c44de0 = 'False branch differs.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:33 }
  CozyText_Protection_VmProbe_Invalid_probe_byte_b272cacf = 'Invalid probe byte.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:28 }
  CozyText_Protection_VmProbe_Invalid_probe_hex_1aaeee92 = 'Invalid probe hex.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:105 }
  CozyText_Protection_VmProbe_Invalid_public_policy_binding_was_accepted_3569c8da = 'Invalid public policy binding was accepted.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:51 }
  CozyText_Protection_VmProbe_Malformed_or_unbounded_VM_input_was_accepted_950ffa81 = 'Malformed or unbounded VM input was accepted.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:69 }
  CozyText_Protection_VmProbe_NOT_OR_false_vector_differs_c2fe0c3a = 'NOT/OR false vector differs.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:68 }
  CozyText_Protection_VmProbe_Negative_condition_differs_d0540f6e = 'Negative condition differs.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:65 }
  CozyText_Protection_VmProbe_Negative_wrap_differs_293d09c5 = 'Negative wrap differs.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:163 }
  CozyText_Protection_VmProbe_PASS_test_only_policy_IR_public_V2_binding_and_C_f0eca04e = 'PASS: test-only policy IR, public V2 binding and CNG transport vectors.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:118 }
  CozyText_Protection_VmProbe_Public_policy_golden_vector_differs_f2cf44d7 = 'Public policy golden vector differs.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:61 }
  CozyText_Protection_VmProbe_Role_flag_ignored_3452c9e6 = 'Role flag ignored.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:166 }
  CozyText_Protection_VmProbe_Text_172ee021 = ': ';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:66 }
  CozyText_Protection_VmProbe_True_branch_differs_2a1b13fa = 'True branch differs.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:145 }
  CozyText_Protection_VmProbe_Unauthenticated_CNG_bytes_escaped_88615f03 = 'Unauthenticated CNG bytes escaped.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:62 }
  CozyText_Protection_VmProbe_Version_flag_ignored_fbd512c1 = 'Version flag ignored.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmProbe.dpr:64 }
  CozyText_Protection_VmProbe_XOR_vector_differs_c7ae5f29 = 'XOR vector differs.';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmReference.pas:110 }
  CozyText_Protection_VmReference_COZY_VM_ARGUMENT_INVALID_3dd4847d = 'COZY_VM_ARGUMENT_INVALID';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmReference.pas:42 }
  CozyText_Protection_VmReference_COZY_VM_BOUNDS_INVALID_03787c29 = 'COZY_VM_BOUNDS_INVALID';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmReference.pas:89 }
  CozyText_Protection_VmReference_COZY_VM_BRANCH_INVALID_af336079 = 'COZY_VM_BRANCH_INVALID';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmReference.pas:187 }
  CozyText_Protection_VmReference_COZY_VM_FUNCTION_INVALID_8a1d53c9 = 'COZY_VM_FUNCTION_INVALID';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmReference.pas:261 }
  CozyText_Protection_VmReference_COZY_VM_FUNCTION_MISSING_a1100d00 = 'COZY_VM_FUNCTION_MISSING';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmReference.pas:78 }
  CozyText_Protection_VmReference_COZY_VM_OPCODE_INVALID_077acaf3 = 'COZY_VM_OPCODE_INVALID';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmReference.pas:114 }
  CozyText_Protection_VmReference_COZY_VM_PROGRAM_INVALID_5076b14f = 'COZY_VM_PROGRAM_INVALID';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmReference.pas:93 }
  CozyText_Protection_VmReference_COZY_VM_STACK_INVALID_f34ea14b = 'COZY_VM_STACK_INVALID';
  { Cozy.Tests/Cozy.Protection/Cozy.Protection.VmReference.pas:231 }
  CozyText_Protection_VmReference_COZY_VM_STEP_LIMIT_96aee27a = 'COZY_VM_STEP_LIMIT';

implementation
end.
