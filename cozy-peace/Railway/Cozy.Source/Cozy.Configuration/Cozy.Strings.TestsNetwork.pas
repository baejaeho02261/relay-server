unit Cozy.Strings.TestsNetwork;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:39 }
  CozyText_RelaySocketContracts_ADDRINFOEX_WIN64_ABI_ead90f4f = 'ADDRINFOEX_WIN64_ABI';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:139 }
  CozyText_RelaySocketContracts_CALLER_CANCEL_57fce8da = 'CALLER_CANCEL';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:77 }
  CozyText_RelaySocketContracts_CANCEL_BEATS_READY_196a79ba = 'CANCEL_BEATS_READY';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:79 }
  CozyText_RelaySocketContracts_CANCEL_RESULT_FREED_b0b1df0c = 'CANCEL_RESULT_FREED';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:92 }
  CozyText_RelaySocketContracts_CANCEL_RETURNS_WITHOUT_FREEING_PROVIDER_abe57e87 = 'CANCEL_RETURNS_WITHOUT_FREEING_PROVIDER';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:50 }
  CozyText_RelaySocketContracts_CANDIDATE_BOUND_c24d7984 = 'CANDIDATE_BOUND';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:144 }
  CozyText_RelaySocketContracts_CLOSED_RESOURCE_STATE_957f20c2 = 'CLOSED_RESOURCE_STATE';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:141 }
  CozyText_RelaySocketContracts_CLOSE_LATCH_e8fa7716 = 'CLOSE_LATCH';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:103 }
  CozyText_RelaySocketContracts_CONTROLLED_DNS_DRAIN_BOUND_1d42beda = 'CONTROLLED_DNS_DRAIN_BOUND';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:94 }
  CozyText_RelaySocketContracts_DNS_ADMISSION_RETAINED_WHILE_PROVIDER_PENDING_6c2c60fd = 'DNS_ADMISSION_RETAINED_WHILE_PROVIDER_PENDING';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:97 }
  CozyText_RelaySocketContracts_DNS_COMPLETION_DRAINED_d31324b3 = 'DNS_COMPLETION_DRAINED';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:90 }
  CozyText_RelaySocketContracts_DNS_ENTERED_1bf17d1f = 'DNS_ENTERED';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:106 }
  CozyText_RelaySocketContracts_DNS_OWNERS_DRAINED_64bf216c = 'DNS_OWNERS_DRAINED';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:119 }
  CozyText_RelaySocketContracts_DNS_RESOLVER_CAPACITY_2f22d45e = 'DNS_RESOLVER_CAPACITY';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:112 }
  CozyText_RelaySocketContracts_EXPIRED_DNS_NOT_STARTED_776e684b = 'EXPIRED_DNS_NOT_STARTED';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:130 }
  CozyText_RelaySocketContracts_FINAL_DNS_OWNER_COUNT_b1657e8d = 'FINAL_DNS_OWNER_COUNT';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:55 }
  CozyText_RelaySocketContracts_IPV4_COPY_0b11fc97 = 'IPV4_COPY';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:51 }
  CozyText_RelaySocketContracts_IPV6_COPY_aa3eb8be = 'IPV6_COPY';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:38 }
  CozyText_RelaySocketContracts_ISOLATED_PROCESS_REQUIRED_f4b5244c = 'ISOLATED_PROCESS_REQUIRED';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:98 }
  CozyText_RelaySocketContracts_LATE_CANCELLED_RESULT_REJECTED_92653872 = 'LATE_CANCELLED_RESULT_REJECTED';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:58 }
  CozyText_RelaySocketContracts_MALFORMED_LENGTH_REJECTED_90754c44 = 'MALFORMED_LENGTH_REJECTED';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:143 }
  CozyText_RelaySocketContracts_NO_PHASE_AFTER_CLOSE_4cee4879 = 'NO_PHASE_AFTER_CLOSE';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:137 }
  CozyText_RelaySocketContracts_ONE_DEADLINE_bbea7924 = 'ONE_DEADLINE';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:62 }
  CozyText_RelaySocketContracts_PROVIDER_CYCLE_SCAN_BOUND_AND_DEDUP_7ea22404 = 'PROVIDER_CYCLE_SCAN_BOUND_AND_DEDUP';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:34 }
  CozyText_RelaySocketContracts_RELAY_SOCKET_CONTRACT_c5049655 = 'RELAY_SOCKET_CONTRACT_';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:114 }
  CozyText_RelaySocketContracts_REPEATED_FAILURE_NO_OWNER_LEAK_15ed93a4 = 'REPEATED_FAILURE_NO_OWNER_LEAK';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:120 }
  CozyText_RelaySocketContracts_RESOLVER_ADMISSION_CAP_7c262d13 = 'RESOLVER_ADMISSION_CAP';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:70 }
  CozyText_RelaySocketContracts_RESULT_FREED_ONCE_2fb297f7 = 'RESULT_FREED_ONCE';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:16 }
  CozyText_RelaySocketContracts_SOCKET_TEST_MODE_398c27a7 = 'SOCKET_TEST_MODE';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:69 }
  CozyText_RelaySocketContracts_SUCCESS_OWNED_COPY_4b1b377a = 'SUCCESS_OWNED_COPY';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:84 }
  CozyText_RelaySocketContracts_TEST_EVENTS_71ef9e22 = 'TEST_EVENTS';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketContracts.inc:67 }
  CozyText_RelaySocketContracts_unit_invalid_d07ebcc0 = 'unit.invalid';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:28 }
  CozyText_RelaySocketProbe_JsonFixture_1be8a01d = '{"version":1,"contractProbeExecuted":true,"outcome":"PASS"}';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:48 }
  CozyText_RelaySocketProbe_JsonFixture_65f4fc3e = '{"nonce":"';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:82 }
  CozyText_RelaySocketProbe_JsonFixture_8702f2e4 = '{"version":1,"error":"SOCKET_PROBE_FAILED"}';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:31 }
  CozyText_RelaySocketProbe_SOCKET_PROBE_ARGUMENTS_d2732e08 = 'SOCKET_PROBE_ARGUMENTS';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:48 }
  CozyText_RelaySocketProbe_Text_be09698f = '"}';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:71 }
  CozyText_RelaySocketProbe_caseId_fd18a030 = 'caseId';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:75 }
  CozyText_RelaySocketProbe_closed_3a50791e = 'closed';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:72 }
  CozyText_RelaySocketProbe_connected_151d155e = 'connected';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:25 }
  CozyText_RelaySocketProbe_contracts_edbea367 = '--contracts';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:77 }
  CozyText_RelaySocketProbe_elapsedMs_b3aa894a = 'elapsedMs';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:76 }
  CozyText_RelaySocketProbe_line_4a91a826 = 'line';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:45 }
  CozyText_RelaySocketProbe_localhost_7916ab31 = 'localhost';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:70 }
  CozyText_RelaySocketProbe_nativeSocketExecuted_18214f57 = 'nativeSocketExecuted';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:71 }
  CozyText_RelaySocketProbe_nonce_596a8e93 = 'nonce';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:74 }
  CozyText_RelaySocketProbe_received_f079a037 = 'received';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:73 }
  CozyText_RelaySocketProbe_sent_e69c6829 = 'sent';
  { Cozy.Tests/Cozy.Network/Cozy.RelaySocketProbe.dpr:69 }
  CozyText_RelaySocketProbe_version_7af40718 = 'version';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:90 }
  CozyText_ServerProfileProbe_127_0_0_1_7e5817a2 = '127.0.0.1';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:111 }
  CozyText_ServerProfileProbe_443_440ee062 = '443';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:11 }
  CozyText_ServerProfileProbe_FAIL_a08f1a49 = 'FAIL: ';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:13 }
  CozyText_ServerProfileProbe_FIXTURE_JSON_fb0b8182 = 'FIXTURE_JSON';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:110 }
  CozyText_ServerProfileProbe_GAME_CONNECT_3_d6055359 = 'GAME-CONNECT-3';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:62 }
  CozyText_ServerProfileProbe_GAME_TLS_PIN_WINDOW_V1_f629c8a4 = 'GAME-TLS-PIN-WINDOW-V1';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:91 }
  CozyText_ServerProfileProbe_IPv4_host_preserved_20fc9532 = 'IPv4 host preserved';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:85 }
  CozyText_ServerProfileProbe_JSON_binding_identity_9a479a9b = 'JSON binding identity';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:131 }
  CozyText_ServerProfileProbe_JSON_copy_owns_independent_window_180f3647 = 'JSON copy owns independent window';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:124 }
  CozyText_ServerProfileProbe_JsonFixture_17b2061a = '{}';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:88 }
  CozyText_ServerProfileProbe_PROFILE_Fixture_INVALID_f17c3c3b = 'PROFILE-Fixture.INVALID';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:151 }
  CozyText_ServerProfileProbe_Profile_and_pin_state_contracts_only_no_network__c75595a3 = 'Profile and pin-state contracts only; no network, TLS handshake, or A/B/O execution.';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:151 }
  CozyText_ServerProfileProbe_SERVER_PROFILE_PROBE_PASS_26ba6208 = 'SERVER_PROFILE_PROBE_PASS ';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:116 }
  CozyText_ServerProfileProbe_TLS_uppercase_097b07d1 = 'TLS uppercase';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:152 }
  CozyText_ServerProfileProbe_Text_9304b830 = ': ';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:116 }
  CozyText_ServerProfileProbe_UPPER_invalid_748a4897 = 'UPPER.invalid';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:115 }
  CozyText_ServerProfileProbe_a_invalid_a712a31b = 'a..invalid';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:34 }
  CozyText_ServerProfileProbe_canonical_3cabf776 = ' canonical';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:83 }
  CozyText_ServerProfileProbe_canonical_UTF8_bytes_roundtrip_5da1739f = 'canonical UTF8 bytes roundtrip';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:86 }
  CozyText_ServerProfileProbe_clone_binding_identity_b7551bf1 = 'clone binding identity';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:130 }
  CozyText_ServerProfileProbe_clone_learns_same_live_window_5cdaf563 = 'clone learns same live window';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:143 }
  CozyText_ServerProfileProbe_clone_retains_retired_trust_after_parent_free_0d51c9be = 'clone retains retired trust after parent free';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:62 }
  CozyText_ServerProfileProbe_contract_6a8ded32 = 'contract';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:53 }
  CozyText_ServerProfileProbe_currentPin_a59bb634 = 'currentPin';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:107 }
  CozyText_ServerProfileProbe_duplicate_field_3cf0ee68 = 'duplicate field';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:123 }
  CozyText_ServerProfileProbe_empty_explicit_state_f364ce88 = 'empty explicit state';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:115 }
  CozyText_ServerProfileProbe_empty_host_label_d217b54a = 'empty host label';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:108 }
  CozyText_ServerProfileProbe_escaped_duplicate_field_afa493cd = 'escaped duplicate field';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:105 }
  CozyText_ServerProfileProbe_extra_4c9ed366 = 'extra';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:137 }
  CozyText_ServerProfileProbe_fixed_pin_snapshot_byte_identity_b19eeb08 = 'fixed pin snapshot byte identity';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:84 }
  CozyText_ServerProfileProbe_fixed_profile_canonical_byte_identity_8b456e9f = 'fixed profile canonical byte identity';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:144 }
  CozyText_ServerProfileProbe_floor_before_issuance_1ff5b52f = 'floor before issuance';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:63 }
  CozyText_ServerProfileProbe_floor_e5075f54 = 'floor';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:114 }
  CozyText_ServerProfileProbe_fraction_port_355bb8fc = 'fraction port';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:50 }
  CozyText_ServerProfileProbe_generation_2a7978f9 = 'generation';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:108 }
  CozyText_ServerProfileProbe_h_u006fst_19cf3a95 = '"h\u006fst":';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:89 }
  CozyText_ServerProfileProbe_historical_uppercase_host_normalization_4653897d = 'historical uppercase host normalization';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:108 }
  CozyText_ServerProfileProbe_host_7092fc35 = '"host":';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:51 }
  CozyText_ServerProfileProbe_host_9953607d = 'host';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:106 }
  CozyText_ServerProfileProbe_host_profile_fixture_invalid_7fbc9cf5 = ',"host":"profile-fixture.invalid"}';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:141 }
  CozyText_ServerProfileProbe_imported_floor_retires_old_pin_e7be1707 = 'imported floor retires old pin';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:120 }
  CozyText_ServerProfileProbe_invalid_public_key_structure_d9c0c3d4 = 'invalid public key structure';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:54 }
  CozyText_ServerProfileProbe_issuedAt_9295085b = 'issuedAt';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:113 }
  CozyText_ServerProfileProbe_large_port_96a17d85 = 'large port';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:133 }
  CozyText_ServerProfileProbe_learned_state_binding_unchanged_d11f6f9b = 'learned state binding unchanged';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:101 }
  CozyText_ServerProfileProbe_missing_8af4728b = 'missing ';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:103 }
  CozyText_ServerProfileProbe_nested_09f7a8de = 'nested ';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:53 }
  CozyText_ServerProfileProbe_nextPin_957c104f = 'nextPin';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:119 }
  CozyText_ServerProfileProbe_noncanonical_public_key_3b97af6a = 'noncanonical public key';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:54 }
  CozyText_ServerProfileProbe_notBefore_31a8ad7d = 'notBefore';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:102 }
  CozyText_ServerProfileProbe_null_6e66fce8 = 'null ';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:55 }
  CozyText_ServerProfileProbe_oldNotAfter_83376fb6 = 'oldNotAfter';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:42 }
  CozyText_ServerProfileProbe_old_or_unknown_peer_rejected_641a8029 = 'old or unknown peer rejected';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:125 }
  CozyText_ServerProfileProbe_oversized_state_ef3a8119 = 'oversized state';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:30 }
  CozyText_ServerProfileProbe_parse_554f1cfa = ' parse';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:147 }
  CozyText_ServerProfileProbe_pin_state_endpoint_mismatch_1618e90d = 'pin state endpoint mismatch';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:62 }
  CozyText_ServerProfileProbe_plan_3c3692ee = 'plan';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:114 }
  CozyText_ServerProfileProbe_port_443_0_c24a0905 = '"port":443.0';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:114 }
  CozyText_ServerProfileProbe_port_443_664f444e = '"port":443';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:51 }
  CozyText_ServerProfileProbe_port_ffc7186e = 'port';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:111 }
  CozyText_ServerProfileProbe_port_string_c611fc7d = 'port string';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:110 }
  CozyText_ServerProfileProbe_protocol_f9bae232 = 'protocol';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:63 }
  CozyText_ServerProfileProbe_retiredPins_ce3d6a3f = 'retiredPins';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:145 }
  CozyText_ServerProfileProbe_retired_active_pin_7f3c5f48 = 'retired active pin';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:52 }
  CozyText_ServerProfileProbe_serverKeyId_8f8fc712 = 'serverKeyId';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:119 }
  CozyText_ServerProfileProbe_serverPublicKey_5449c4d1 = 'serverPublicKey';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:124 }
  CozyText_ServerProfileProbe_state_shape_041c6b85 = 'state shape';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:122 }
  CozyText_ServerProfileProbe_state_type_25430ee7 = 'state type';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:121 }
  CozyText_ServerProfileProbe_tlsCertificateSha256_ff82a824 = 'tlsCertificateSha256';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:70 }
  CozyText_ServerProfileProbe_tlsPinState_6404dece = 'tlsPinState';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:52 }
  CozyText_ServerProfileProbe_tlsServerName_c7ba796b = 'tlsServerName';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:135 }
  CozyText_ServerProfileProbe_trusted_floor_never_decreases_32fc336c = 'trusted floor never decreases';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:134 }
  CozyText_ServerProfileProbe_trusted_overlap_roundtrip_278bf145 = 'trusted overlap roundtrip';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:105 }
  CozyText_ServerProfileProbe_unknown_field_aae88956 = 'unknown field';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:118 }
  CozyText_ServerProfileProbe_uppercase_key_ID_66ee5587 = 'uppercase key ID';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:121 }
  CozyText_ServerProfileProbe_uppercase_pin_4c46ce0e = 'uppercase pin';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:94 }
  CozyText_ServerProfileProbe_valid_port_boundary_e0fe125e = 'valid port boundary';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:50 }
  CozyText_ServerProfileProbe_version_c0967ed3 = 'version';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:117 }
  CozyText_ServerProfileProbe_wrong_key_ID_4275e9c5 = 'wrong key ID';
  { Cozy.Tests/Cozy.Network/Cozy.ServerProfileProbe.dpr:112 }
  CozyText_ServerProfileProbe_zero_port_98100530 = 'zero port';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:41 }
  CozyText_TlsAbiContract_CERT_CONTEXT_cbCertEncoded_9e7a929e = 'CERT_CONTEXT.cbCertEncoded=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:39 }
  CozyText_TlsAbiContract_CERT_CONTEXT_dwCertEncodingType_3a3d045f = 'CERT_CONTEXT.dwCertEncodingType=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:43 }
  CozyText_TlsAbiContract_CERT_CONTEXT_hCertStore_484d69b2 = 'CERT_CONTEXT.hCertStore=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:42 }
  CozyText_TlsAbiContract_CERT_CONTEXT_pCertInfo_66ba3c44 = 'CERT_CONTEXT.pCertInfo=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:40 }
  CozyText_TlsAbiContract_CERT_CONTEXT_pbCertEncoded_0b4fcef1 = 'CERT_CONTEXT.pbCertEncoded=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:38 }
  CozyText_TlsAbiContract_CERT_CONTEXT_sizeof_b3a36f1d = 'CERT_CONTEXT.sizeof=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:29 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_aphMappers_65719fdf = 'SCHANNEL_CRED.aphMappers=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:25 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_cCreds_ebc34fa8 = 'SCHANNEL_CRED.cCreds=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:28 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_cMappers_3b5bc368 = 'SCHANNEL_CRED.cMappers=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:30 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_cSupportedAlgs_d1ca3d16 = 'SCHANNEL_CRED.cSupportedAlgs=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:37 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_dwCredFormat_2ed9b0e7 = 'SCHANNEL_CRED.dwCredFormat=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:36 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_dwFlags_a66b9e99 = 'SCHANNEL_CRED.dwFlags=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:34 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_dwMaximumCipherStrength_c06c8f46 = 'SCHANNEL_CRED.dwMaximumCipherStrength=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:33 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_dwMinimumCipherStrength_113f4d40 = 'SCHANNEL_CRED.dwMinimumCipherStrength=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:35 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_dwSessionLifespan_2acf7daf = 'SCHANNEL_CRED.dwSessionLifespan=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:24 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_dwVersion_c8367623 = 'SCHANNEL_CRED.dwVersion=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:32 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_grbitEnabledProtocols_13af5188 = 'SCHANNEL_CRED.grbitEnabledProtocols=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:27 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_hRootStore_06a8d318 = 'SCHANNEL_CRED.hRootStore=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:26 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_paCred_84f00d3e = 'SCHANNEL_CRED.paCred=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:31 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_palgSupportedAlgs_5cf2bb8a = 'SCHANNEL_CRED.palgSupportedAlgs=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:23 }
  CozyText_TlsAbiContract_SCHANNEL_CRED_sizeof_90964761 = 'SCHANNEL_CRED.sizeof=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:21 }
  CozyText_TlsAbiContract_SecBufferDesc_cBuffers_e1376b19 = 'SecBufferDesc.cBuffers=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:22 }
  CozyText_TlsAbiContract_SecBufferDesc_pBuffers_fc379a1a = 'SecBufferDesc.pBuffers=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:19 }
  CozyText_TlsAbiContract_SecBufferDesc_sizeof_171e54e2 = 'SecBufferDesc.sizeof=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:20 }
  CozyText_TlsAbiContract_SecBufferDesc_ulVersion_d3c560f7 = 'SecBufferDesc.ulVersion=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:17 }
  CozyText_TlsAbiContract_SecBuffer_BufferType_c0f8c6f2 = 'SecBuffer.BufferType=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:16 }
  CozyText_TlsAbiContract_SecBuffer_cbBuffer_9698bfb3 = 'SecBuffer.cbBuffer=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:18 }
  CozyText_TlsAbiContract_SecBuffer_pvBuffer_db14137a = 'SecBuffer.pvBuffer=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:15 }
  CozyText_TlsAbiContract_SecBuffer_sizeof_ba08a5e4 = 'SecBuffer.sizeof=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:13 }
  CozyText_TlsAbiContract_SecHandle_dwLower_a1d6505e = 'SecHandle.dwLower=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:14 }
  CozyText_TlsAbiContract_SecHandle_dwUpper_2f5e782e = 'SecHandle.dwUpper=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:12 }
  CozyText_TlsAbiContract_SecHandle_sizeof_4e25d8eb = 'SecHandle.sizeof=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:52 }
  CozyText_TlsAbiContract_SecPkgContext_ConnectionInfo_aiCipher_5c6ea07f = 'SecPkgContext_ConnectionInfo.aiCipher=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:56 }
  CozyText_TlsAbiContract_SecPkgContext_ConnectionInfo_aiExch_c5f5b28f = 'SecPkgContext_ConnectionInfo.aiExch=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:54 }
  CozyText_TlsAbiContract_SecPkgContext_ConnectionInfo_aiHash_11e2ca14 = 'SecPkgContext_ConnectionInfo.aiHash=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:53 }
  CozyText_TlsAbiContract_SecPkgContext_ConnectionInfo_dwCipherStrength_740dd476 = 'SecPkgContext_ConnectionInfo.dwCipherStrength=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:57 }
  CozyText_TlsAbiContract_SecPkgContext_ConnectionInfo_dwExchStrength_9149e53b = 'SecPkgContext_ConnectionInfo.dwExchStrength=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:55 }
  CozyText_TlsAbiContract_SecPkgContext_ConnectionInfo_dwHashStrength_a078759f = 'SecPkgContext_ConnectionInfo.dwHashStrength=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:51 }
  CozyText_TlsAbiContract_SecPkgContext_ConnectionInfo_dwProtocol_c1a523a4 = 'SecPkgContext_ConnectionInfo.dwProtocol=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:50 }
  CozyText_TlsAbiContract_SecPkgContext_ConnectionInfo_sizeof_6e7122c4 = 'SecPkgContext_ConnectionInfo.sizeof=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:48 }
  CozyText_TlsAbiContract_SecPkgContext_StreamSizes_cBuffers_8c274da9 = 'SecPkgContext_StreamSizes.cBuffers=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:49 }
  CozyText_TlsAbiContract_SecPkgContext_StreamSizes_cbBlockSize_0387e5c6 = 'SecPkgContext_StreamSizes.cbBlockSize=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:45 }
  CozyText_TlsAbiContract_SecPkgContext_StreamSizes_cbHeader_07fcd0a6 = 'SecPkgContext_StreamSizes.cbHeader=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:47 }
  CozyText_TlsAbiContract_SecPkgContext_StreamSizes_cbMaximumMessage_c88d587b = 'SecPkgContext_StreamSizes.cbMaximumMessage=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:46 }
  CozyText_TlsAbiContract_SecPkgContext_StreamSizes_cbTrailer_aae9e9ad = 'SecPkgContext_StreamSizes.cbTrailer=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsAbiContract.inc:44 }
  CozyText_TlsAbiContract_SecPkgContext_StreamSizes_sizeof_4e1e12f5 = 'SecPkgContext_StreamSizes.sizeof=';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContractProbe.dpr:22 }
  CozyText_TlsContractProbe_CoCreateGuid_failed_in_native_ABI_probe_9609819c = 'CoCreateGuid failed in native ABI probe.';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContractProbe.dpr:24 }
  CozyText_TlsContractProbe_CoCreateGuid_returned_an_empty_GUID_5e2010d9 = 'CoCreateGuid returned an empty GUID.';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContractProbe.dpr:26 }
  CozyText_TlsContractProbe_Controlled_TLS_provider_faults_are_separate_from_b4871ab4 = 'Controlled TLS provider faults are separate from real Schannel ReceiveProbe fixtures.';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContractProbe.dpr:25 }
  CozyText_TlsContractProbe_PASS_real_Windows_GUID_ABI_and_success_output_a469591d = 'PASS: real Windows GUID ABI and success output.';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContractProbe.dpr:31 }
  CozyText_TlsContractProbe_Text_547d5bb7 = ': ';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContractProbe.dpr:27 }
  CozyText_TlsContractProbe_This_suite_does_not_claim_a_real_server_handshak_0a46fc18 = 'This suite does not claim a real server handshake or Schannel record-state result.';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:268 }
  CozyText_TlsContracts_DWORD_length_overflow_rejected_c24f6bba = 'DWORD length overflow rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:147 }
  CozyText_TlsContracts_PASS_bb33c9c1 = 'PASS: ';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:169 }
  CozyText_TlsContracts_TLS_TEST_DELETE_EXCEPTION_22fc42be = 'TLS_TEST_DELETE_EXCEPTION';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:162 }
  CozyText_TlsContracts_TLS_TEST_PARTIAL_CONTEXT_EXCEPTION_9c0964c4 = 'TLS_TEST_PARTIAL_CONTEXT_EXCEPTION';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:47 }
  CozyText_TlsContracts_TLS_TEST_PROVIDER_EXCEPTION_486bee08 = 'TLS_TEST_PROVIDER_EXCEPTION';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:179 }
  CozyText_TlsContracts_TLS_context_cleanup_67e041e4 = 'TLS context cleanup: ';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:244 }
  CozyText_TlsContracts_TLS_contract_462a883b = 'TLS contract: ';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:87 }
  CozyText_TlsContracts_TLS_state_fault_e1592d62 = 'TLS state fault: ';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:255 }
  CozyText_TlsContracts_Windows_x64_SSPI_sizes_and_member_offsets_c3096fc5 = 'Windows x64 SSPI sizes and member offsets';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:216 }
  CozyText_TlsContracts_active_first_owner_rejects_Clear_2314a426 = 'active first owner rejects Clear';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:263 }
  CozyText_TlsContracts_address_below_allocation_rejected_06930c74 = 'address below allocation rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:294 }
  CozyText_TlsContracts_adjacent_plaintext_spans_accepted_d26400d4 = 'adjacent plaintext spans accepted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:202 }
  CozyText_TlsContracts_buffers_wiped_after_handshake_or_cleanup_excepti_928b5930 = 'buffers wiped after handshake or cleanup exception';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:364 }
  CozyText_TlsContracts_busy_handshake_rejected_without_touching_context_d1bc73da = 'busy handshake rejected without touching context';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:367 }
  CozyText_TlsContracts_busy_operations_never_call_transport_faa31272 = 'busy operations never call transport';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:365 }
  CozyText_TlsContracts_busy_read_rejected_014347ef = 'busy read rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:366 }
  CozyText_TlsContracts_busy_write_rejected_f8c1c045 = 'busy write rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:375 }
  CozyText_TlsContracts_callback_recursion_rejected_without_deadlock_c3e51891 = 'callback recursion rejected without deadlock';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:133 }
  CozyText_TlsContracts_close_notify_recognized_5beebaaa = 'close_notify recognized';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:114 }
  CozyText_TlsContracts_coalesced_bytes_preserved_882ce063 = 'coalesced bytes preserved';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:113 }
  CozyText_TlsContracts_coalesced_second_record_69c0d7e5 = 'coalesced second record';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:110 }
  CozyText_TlsContracts_consumed_byte_wiped_1fffe1c0 = 'consumed byte wiped';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:118 }
  CozyText_TlsContracts_consumed_owners_wiped_5af47979 = 'consumed owners wiped';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:204 }
  CozyText_TlsContracts_context_faults_are_controlled_never_real_handles_09dc60f6 = 'context faults are controlled, never real handles';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:228 }
  CozyText_TlsContracts_controlled_TLS_partial_context_and_exception_cle_5ed12419 = ' controlled TLS partial-context and exception cleanup checks.';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:147 }
  CozyText_TlsContracts_controlled_TLS_state_fault_checks_provider_subst_cae37225 = ' controlled TLS state/fault checks; provider substituted only in this suite.';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:117 }
  CozyText_TlsContracts_controlled_provider_attribution_9a830629 = 'controlled provider attribution';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:218 }
  CozyText_TlsContracts_counts_reset_before_fallible_Clear_062b6487 = 'counts reset before fallible Clear';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:199 }
  CozyText_TlsContracts_credentials_freed_despite_context_failure_d1f2b8d1 = 'credentials freed despite context failure';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:108 }
  CozyText_TlsContracts_cursor_retains_pending_bytes_bf0666e0 = 'cursor retains pending bytes';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:286 }
  CozyText_TlsContracts_duplicate_extra_rejected_0c1c06f7 = 'duplicate extra rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:333 }
  CozyText_TlsContracts_empty_owned_allocation_rejected_e501e6eb = 'empty owned allocation rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:258 }
  CozyText_TlsContracts_entire_owned_buffer_accepted_77ff92a7 = 'entire owned buffer accepted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:196 }
  CozyText_TlsContracts_failed_handshake_never_succeeds_03693a7d = 'failed handshake never succeeds';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:382 }
  CozyText_TlsContracts_failed_stream_cannot_read_again_390c0b20 = 'failed stream cannot read again';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:381 }
  CozyText_TlsContracts_failed_stream_cannot_restart_handshake_ed34d9ee = 'failed stream cannot restart handshake';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:378 }
  CozyText_TlsContracts_failed_stream_immediately_clears_native_state_8f2fed14 = 'failed stream immediately clears native state';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:129 }
  CozyText_TlsContracts_fault_cannot_return_plaintext_4e959d9d = 'fault cannot return plaintext';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:130 }
  CozyText_TlsContracts_fault_output_sentinel_intact_f7a7cf69 = 'fault output sentinel intact';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:132 }
  CozyText_TlsContracts_fault_owners_wiped_efcf6fde = 'fault owners wiped';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:131 }
  CozyText_TlsContracts_fault_terminal_state_76fa46bc = 'fault terminal state';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:107 }
  CozyText_TlsContracts_first_plaintext_byte_e1616b17 = 'first plaintext byte';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:119 }
  CozyText_TlsContracts_fragmented_record_completed_fcf34d60 = 'fragmented record completed';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:120 }
  CozyText_TlsContracts_incomplete_status_exercised_28a83732 = 'incomplete status exercised';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:317 }
  CozyText_TlsContracts_invalid_final_fragment_rejected_before_send_0e5226f2 = 'invalid final fragment rejected before send';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:167 }
  CozyText_TlsContracts_invalid_handle_sent_to_delete_c8f1d264 = 'invalid handle sent to delete';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:358 }
  CozyText_TlsContracts_invalid_handshake_rejected_without_I_O_d6511a97 = 'invalid handshake rejected without I/O';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:361 }
  CozyText_TlsContracts_invalid_inputs_never_reach_transport_callbacks_57a7c25d = 'invalid inputs never reach transport callbacks';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:259 }
  CozyText_TlsContracts_last_byte_accepted_b53d435b = 'last byte accepted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:260 }
  CozyText_TlsContracts_last_byte_overflow_rejected_96460492 = 'last byte overflow rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:137 }
  CozyText_TlsContracts_localhost_a900532b = 'localhost';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:392 }
  CozyText_TlsContracts_native_TLS_ABI_and_buffer_contract_checks_55ab5fa6 = ' native TLS ABI and buffer contract checks.';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:347 }
  CozyText_TlsContracts_nil_read_callback_rejected_at_construction_4eb63b60 = 'nil read callback rejected at construction';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:261 }
  CozyText_TlsContracts_nil_span_rejected_f764742b = 'nil span rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:355 }
  CozyText_TlsContracts_nil_write_callback_rejected_at_construction_7c9756f2 = 'nil write callback rejected at construction';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:143 }
  CozyText_TlsContracts_no_provider_or_plaintext_before_authentication_4e6d1585 = 'no provider or plaintext before authentication';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:311 }
  CozyText_TlsContracts_nonoverlapping_fragment_gaps_accepted_after_outp_d0b11ddc = 'nonoverlapping fragment gaps accepted after output sizes shrink';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:265 }
  CozyText_TlsContracts_one_past_empty_span_accepted_9e02897d = 'one-past empty span accepted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:267 }
  CozyText_TlsContracts_one_past_nonempty_span_rejected_d60c1486 = 'one-past nonempty span rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:384 }
  CozyText_TlsContracts_operation_guard_released_on_failure_217ac1ef = 'operation guard released on failure';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:296 }
  CozyText_TlsContracts_out_of_allocation_plaintext_rejected_dc1d673c = 'out-of-allocation plaintext rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:315 }
  CozyText_TlsContracts_overlapping_encrypted_trailer_rejected_6c478623 = 'overlapping encrypted trailer rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:292 }
  CozyText_TlsContracts_overlapping_plaintext_rejected_cd7a10d8 = 'overlapping plaintext rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:282 }
  CozyText_TlsContracts_oversized_extra_rejected_92295115 = 'oversized extra rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:198 }
  CozyText_TlsContracts_partial_failed_handle_deleted_exactly_once_207172ef = 'partial failed handle deleted exactly once';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:106 }
  CozyText_TlsContracts_partial_plaintext_read_dea31f10 = 'partial plaintext read';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:329 }
  CozyText_TlsContracts_plaintext_aggregate_bound_accepted_5d82520a = 'plaintext aggregate bound accepted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:331 }
  CozyText_TlsContracts_plaintext_aggregate_overflow_rejected_8c6d26aa = 'plaintext aggregate overflow rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:289 }
  CozyText_TlsContracts_plaintext_alias_into_encrypted_tail_rejected_cc94e02c = 'plaintext alias into encrypted tail rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:111 }
  CozyText_TlsContracts_remaining_plaintext_read_e97b64f8 = 'remaining plaintext read';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:201 }
  CozyText_TlsContracts_retired_context_invalidated_2a6c6d95 = 'retired context invalidated';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:217 }
  CozyText_TlsContracts_second_owner_still_wiped_a134e57e = 'second owner still wiped';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:307 }
  CozyText_TlsContracts_smaller_returned_header_data_and_trailer_sizes_a_d58163af = 'smaller returned header, data and trailer sizes accepted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:112 }
  CozyText_TlsContracts_tail_without_copied_array_06a81df0 = 'tail without copied array';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:137 }
  CozyText_TlsContracts_terminal_handshake_rejected_69a2d100 = 'terminal handshake rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:138 }
  CozyText_TlsContracts_terminal_no_network_reuse_7efed750 = 'terminal no network reuse';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:200 }
  CozyText_TlsContracts_terminal_owner_flags_8f755f17 = 'terminal owner flags';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:135 }
  CozyText_TlsContracts_terminal_read_rejected_996f12ba = 'terminal read rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:383 }
  CozyText_TlsContracts_terminal_state_performs_no_network_IO_0759b78a = 'terminal state performs no network IO';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:136 }
  CozyText_TlsContracts_terminal_write_rejected_e6999b96 = 'terminal write rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:374 }
  CozyText_TlsContracts_transport_read_failure_propagated_0292e9c0 = 'transport read failure propagated';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:122 }
  CozyText_TlsContracts_truncated_record_rejected_6290af2e = 'truncated record rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:124 }
  CozyText_TlsContracts_truncation_clears_owners_359f18ca = 'truncation clears owners';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:123 }
  CozyText_TlsContracts_truncation_publishes_no_plaintext_833b479a = 'truncation publishes no plaintext';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:142 }
  CozyText_TlsContracts_unauthenticated_read_rejected_a01469b5 = 'unauthenticated read rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:360 }
  CozyText_TlsContracts_unauthenticated_write_rejected_11ca9c5a = 'unauthenticated write rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:321 }
  CozyText_TlsContracts_unexpected_fourth_output_rejected_539eb876 = 'unexpected fourth output rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:197 }
  CozyText_TlsContracts_untouched_invalid_handle_not_deleted_5278b008 = 'untouched invalid handle not deleted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:302 }
  CozyText_TlsContracts_valid_bounded_encrypted_fragments_559dd232 = 'valid bounded encrypted fragments';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:276 }
  CozyText_TlsContracts_valid_plaintext_with_counted_unprocessed_tail_bc3d3929 = 'valid plaintext with counted unprocessed tail';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:324 }
  CozyText_TlsContracts_wrong_encrypted_content_type_rejected_53904fef = 'wrong encrypted content type rejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:319 }
  CozyText_TlsContracts_zero_length_trailer_accepted_f040f00c = 'zero-length trailer accepted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsContracts.inc:279 }
  CozyText_TlsContracts_zero_plaintext_with_only_an_EXTRA_output_accepte_d6b77fa8 = 'zero plaintext with only an EXTRA output accepted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:26 }
  CozyText_TlsPinWindowProbe_127_0_0_1_de1c3de7 = '127.0.0.1';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:94 }
  CozyText_TlsPinWindowProbe_ACCEPTED_PLAN_GUARD_EXECUTED_ffa7891c = 'ACCEPTED_PLAN_GUARD_EXECUTED';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:95 }
  CozyText_TlsPinWindowProbe_ACCEPTED_SERVER_FLOOR_COMMITTED_61a317ed = 'ACCEPTED_SERVER_FLOOR_COMMITTED';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:135 }
  CozyText_TlsPinWindowProbe_BACKWARD_TICK_eeac5786 = 'BACKWARD_TICK';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:110 }
  CozyText_TlsPinWindowProbe_BEFORE_WINDOW_17ff5e72 = 'BEFORE_WINDOW';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:83 }
  CozyText_TlsPinWindowProbe_CANCELLED_FUTURE_PLAN_CANNOT_POISON_LATER_VALID__d457ca0d = 'CANCELLED_FUTURE_PLAN_CANNOT_POISON_LATER_VALID_PLAN';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:80 }
  CozyText_TlsPinWindowProbe_CANCEL_GUARD_PRESERVES_EMPTY_SHARED_STATE_f33d0e03 = 'CANCEL_GUARD_PRESERVES_EMPTY_SHARED_STATE';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:136 }
  CozyText_TlsPinWindowProbe_CLOSE_ELAPSED_b7c18542 = 'CLOSE_ELAPSED';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:134 }
  CozyText_TlsPinWindowProbe_CLOSE_RESERVE_ffa9e97a = 'CLOSE_RESERVE';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:136 }
  CozyText_TlsPinWindowProbe_CLOSE_WITHIN_935a7c28 = 'CLOSE_WITHIN';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:70 }
  CozyText_TlsPinWindowProbe_CONFLICT_REJECTED_BEFORE_GUARD_08d07ddf = 'CONFLICT_REJECTED_BEFORE_GUARD';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:92 }
  CozyText_TlsPinWindowProbe_ELAPSED_DEADLINE_CANNOT_PUBLISH_PLAN_244a341b = 'ELAPSED_DEADLINE_CANNOT_PUBLISH_PLAN';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:138 }
  CozyText_TlsPinWindowProbe_EXACT_CLOSE_DEADLINE_6271d639 = 'EXACT_CLOSE_DEADLINE';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:135 }
  CozyText_TlsPinWindowProbe_EXACT_DEADLINE_ce89ccc0 = 'EXACT_DEADLINE';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:137 }
  CozyText_TlsPinWindowProbe_EXACT_JOIN_DEADLINE_09b11ac4 = 'EXACT_JOIN_DEADLINE';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:17 }
  CozyText_TlsPinWindowProbe_EXPECTED_REJECTION_cbb8662c = 'EXPECTED_REJECTION';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:114 }
  CozyText_TlsPinWindowProbe_HANDOFF_COPY_6d5a5a76 = 'HANDOFF_COPY';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:97 }
  CozyText_TlsPinWindowProbe_IDEMPOTENT_PLAN_STILL_CHECKS_CALLER_GUARD_250a6978 = 'IDEMPOTENT_PLAN_STILL_CHECKS_CALLER_GUARD';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:73 }
  CozyText_TlsPinWindowProbe_INVALID_FUTURE_PLAN_CANNOT_ADVANCE_SERVER_FLOOR_4c95ac4f = 'INVALID_FUTURE_PLAN_CANNOT_ADVANCE_SERVER_FLOOR';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:72 }
  CozyText_TlsPinWindowProbe_INVALID_FUTURE_PLAN_CANNOT_RETIRE_SHARED_PIN_875de000 = 'INVALID_FUTURE_PLAN_CANNOT_RETIRE_SHARED_PIN';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:136 }
  CozyText_TlsPinWindowProbe_JOIN_WITHIN_1dfb32c7 = 'JOIN_WITHIN';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:146 }
  CozyText_TlsPinWindowProbe_JsonFixture_d906d563 = '{"suite":"Cozy.TlsPinWindowProbe","checks":';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:121 }
  CozyText_TlsPinWindowProbe_NEXT_GENERATION_670d8cf5 = 'NEXT_GENERATION';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:117 }
  CozyText_TlsPinWindowProbe_OLD_RETIRED_fcb0b973 = 'OLD_RETIRED';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:123 }
  CozyText_TlsPinWindowProbe_OLD_ROOT_VALID_HANDOFF_e55b1595 = 'OLD_ROOT_VALID_HANDOFF';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:115 }
  CozyText_TlsPinWindowProbe_OVERLAP_917d7c0b = 'OVERLAP';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:137 }
  CozyText_TlsPinWindowProbe_RESERVED_CLOSE_REMAINS_1fc3f0f8 = 'RESERVED_CLOSE_REMAINS';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:122 }
  CozyText_TlsPinWindowProbe_RETIRED_HISTORY_PRESERVED_2eb42a63 = 'RETIRED_HISTORY_PRESERVED';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:108 }
  CozyText_TlsPinWindowProbe_ROOT_ONLY_95a35e1d = 'ROOT_ONLY';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:139 }
  CozyText_TlsPinWindowProbe_SAFE_DRAIN_OVERRUN_8eed7484 = 'SAFE_DRAIN_OVERRUN';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:119 }
  CozyText_TlsPinWindowProbe_SAME_PLAN_CANNOT_REOPEN_c4238de6 = 'SAME_PLAN_CANNOT_REOPEN';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:140 }
  CozyText_TlsPinWindowProbe_SHUTDOWN_78145d4a = 'SHUTDOWN_';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:135 }
  CozyText_TlsPinWindowProbe_START_REMAINING_aac150b4 = 'START_REMAINING';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:11 }
  CozyText_TlsPinWindowProbe_TLS_PIN_85a6fa3f = 'TLS_PIN_';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:77 }
  CozyText_TlsPinWindowProbe_TLS_PIN_GUARD_CANCELLED_67b28350 = 'TLS_PIN_GUARD_CANCELLED';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:89 }
  CozyText_TlsPinWindowProbe_TLS_PIN_GUARD_DEADLINE_5969b380 = 'TLS_PIN_GUARD_DEADLINE';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:134 }
  CozyText_TlsPinWindowProbe_TOTAL_DEADLINE_8a85b758 = 'TOTAL_DEADLINE';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:49 }
  CozyText_TlsPinWindowProbe_TRUSTED_FLOOR_REQUIRED_97f726f7 = 'TRUSTED_FLOOR_REQUIRED';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:147 }
  CozyText_TlsPinWindowProbe_Text_fac21826 = ': ';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:37 }
  CozyText_TlsPinWindowProbe_contract_d10f91e5 = 'contract';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:28 }
  CozyText_TlsPinWindowProbe_currentPin_f5648371 = 'currentPin';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:38 }
  CozyText_TlsPinWindowProbe_floor_6c80812c = 'floor';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:25 }
  CozyText_TlsPinWindowProbe_generation_dcd87e65 = 'generation';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:26 }
  CozyText_TlsPinWindowProbe_host_d270c27a = 'host';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:29 }
  CozyText_TlsPinWindowProbe_issuedAt_389a23f9 = 'issuedAt';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:28 }
  CozyText_TlsPinWindowProbe_nextPin_21ee9bac = 'nextPin';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:29 }
  CozyText_TlsPinWindowProbe_notBefore_5ff1eb7a = 'notBefore';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:30 }
  CozyText_TlsPinWindowProbe_oldNotAfter_0f5b56a4 = 'oldNotAfter';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:27 }
  CozyText_TlsPinWindowProbe_pin_fixture_invalid_d5b74d42 = 'pin-fixture.invalid';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:37 }
  CozyText_TlsPinWindowProbe_plan_3902df9d = 'plan';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:26 }
  CozyText_TlsPinWindowProbe_port_a72973fa = 'port';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:38 }
  CozyText_TlsPinWindowProbe_retiredPins_4c688279 = 'retiredPins';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:27 }
  CozyText_TlsPinWindowProbe_serverKeyId_68b10d74 = 'serverKeyId';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:146 }
  CozyText_TlsPinWindowProbe_status_PASS_tlsHandshakeExecuted_false_gpuExecut_f9499dc9 = ',"status":"PASS","tlsHandshakeExecuted":false,"gpuExecuted":false,"scope":"ACTUAL_NATIVE_PIN_STATE_AND_SHUTDOWN_ACCOUNTING"}';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:27 }
  CozyText_TlsPinWindowProbe_tlsServerName_3c673a0b = 'tlsServerName';
  { Cozy.Tests/Cozy.Network/Cozy.TlsPinWindowProbe.dpr:25 }
  CozyText_TlsPinWindowProbe_version_c2d0bab1 = 'version';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:53 }
  CozyText_TlsReceiveProbe_127_0_0_1_ab208a13 = '127.0.0.1';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:57 }
  CozyText_TlsReceiveProbe_JsonFixture_4bde6631 = '{"nonce":"';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:103 }
  CozyText_TlsReceiveProbe_JsonFixture_52b99ea6 = '{"error":"RECEIVE_PROBE_SETUP_OR_IO"}';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:110 }
  CozyText_TlsReceiveProbe_JsonFixture_6d37cfcb = '{}';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:95 }
  CozyText_TlsReceiveProbe_JsonFixture_e1d5df92 = '{"error":"RECEIVE_PROBE_ARGUMENTS"}';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:40 }
  CozyText_TlsReceiveProbe_RECEIVE_PROBE_ARGUMENTS_c197d016 = 'RECEIVE_PROBE_ARGUMENTS';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:89 }
  CozyText_TlsReceiveProbe_RECEIVE_PROBE_CLOSED_DATA_9a8269f6 = 'RECEIVE_PROBE_CLOSED_DATA';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:112 }
  CozyText_TlsReceiveProbe_RECEIVE_PROBE_FAILED_CONTEXT_REUSED_d6d55933 = 'RECEIVE_PROBE_FAILED_CONTEXT_REUSED';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:73 }
  CozyText_TlsReceiveProbe_RECEIVE_PROBE_PE_BOUND_5169c93a = 'RECEIVE_PROBE_PE_BOUND';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:70 }
  CozyText_TlsReceiveProbe_RECEIVE_PROBE_PE_FIELD_dff55551 = 'RECEIVE_PROBE_PE_FIELD';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:51 }
  CozyText_TlsReceiveProbe_RECEIVE_PROBE_PREAUTH_DATA_9a2aaf59 = 'RECEIVE_PROBE_PREAUTH_DATA';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:58 }
  CozyText_TlsReceiveProbe_RECEIVE_PROBE_SEND_4a2faef4 = 'RECEIVE_PROBE_SEND';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:57 }
  CozyText_TlsReceiveProbe_Text_a0549aed = '"}';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:37 }
  CozyText_TlsReceiveProbe_arguments_9ce4d398 = 'arguments';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:117 }
  CozyText_TlsReceiveProbe_caseId_93d213c5 = 'caseId';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:86 }
  CozyText_TlsReceiveProbe_close_ba840388 = 'close';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:131 }
  CozyText_TlsReceiveProbe_contextExpired_833dc5b0 = 'contextExpired';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:135 }
  CozyText_TlsReceiveProbe_elapsedMs_360d7c98 = 'elapsedMs';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:128 }
  CozyText_TlsReceiveProbe_handshakeIncomplete_148e5d82 = 'handshakeIncomplete';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:121 }
  CozyText_TlsReceiveProbe_jsonAccepted_b6e0bdba = 'jsonAccepted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:44 }
  CozyText_TlsReceiveProbe_json_5a8ad8da = 'json';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:44 }
  CozyText_TlsReceiveProbe_json_close_bebd91ef = 'json-close';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:120 }
  CozyText_TlsReceiveProbe_lineReceived_2d6619dd = 'lineReceived';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:53 }
  CozyText_TlsReceiveProbe_localhost_07a66363 = 'localhost';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:118 }
  CozyText_TlsReceiveProbe_nativeReceiveExecuted_0f183d1e = 'nativeReceiveExecuted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:117 }
  CozyText_TlsReceiveProbe_nonce_495ad839 = 'nonce';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:122 }
  CozyText_TlsReceiveProbe_peAccepted_3d5b6406 = 'peAccepted';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:44 }
  CozyText_TlsReceiveProbe_pe_30911e43 = 'pe';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:126 }
  CozyText_TlsReceiveProbe_postFailureReadRejected_d43a17a8 = 'postFailureReadRejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:127 }
  CozyText_TlsReceiveProbe_postFailureWriteRejected_76bfe95a = 'postFailureWriteRejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:124 }
  CozyText_TlsReceiveProbe_preAuthenticationReadRejected_f2827f31 = 'preAuthenticationReadRejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:133 }
  CozyText_TlsReceiveProbe_providerOverrideCalls_51c1aa8c = 'providerOverrideCalls';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:130 }
  CozyText_TlsReceiveProbe_readExtra_e4b3fc3c = 'readExtra';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:129 }
  CozyText_TlsReceiveProbe_readIncomplete_88aad012 = 'readIncomplete';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:132 }
  CozyText_TlsReceiveProbe_realProviderCalls_dfa41e4e = 'realProviderCalls';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:59 }
  CozyText_TlsReceiveProbe_receive_c9dbd834 = 'receive';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:56 }
  CozyText_TlsReceiveProbe_send_c21d86de = 'send';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:134 }
  CozyText_TlsReceiveProbe_stage_7a94aaff = 'stage';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:125 }
  CozyText_TlsReceiveProbe_terminalReadRejected_323f0948 = 'terminalReadRejected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:119 }
  CozyText_TlsReceiveProbe_tlsConnected_04638418 = 'tlsConnected';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:52 }
  CozyText_TlsReceiveProbe_tls_f915843c = 'tls';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:123 }
  CozyText_TlsReceiveProbe_transportClosed_ee1df919 = 'transportClosed';
  { Cozy.Tests/Cozy.Network/Cozy.TlsReceiveProbe.dpr:116 }
  CozyText_TlsReceiveProbe_version_7bd3d051 = 'version';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:201 }
  CozyText_TransportProbe_00000000_0000_0000_0000_000000000000_e03ba063 = '00000000-0000-0000-0000-000000000000';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:166 }
  CozyText_TransportProbe_AES_ebd231d2 = 'AES';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:396 }
  CozyText_TransportProbe_AUTHENTICATED_PLAN_NOT_COMMITTED_8c63731a = 'AUTHENTICATED_PLAN_NOT_COMMITTED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:272 }
  CozyText_TransportProbe_BORROWED_BODY_MUTATED_e93b2df7 = 'BORROWED_BODY_MUTATED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:285 }
  CozyText_TransportProbe_BORROWED_BODY_OWNERSHIP_57b9384f = 'BORROWED_BODY_OWNERSHIP';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:326 }
  CozyText_TransportProbe_CANCELLED_NEW_REQUEST_REACHED_WIRE_32c72b95 = 'CANCELLED_NEW_REQUEST_REACHED_WIRE';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:388 }
  CozyText_TransportProbe_CANCELLED_PLAN_CHANGED_SHARED_TRUST_40ca00d0 = 'CANCELLED_PLAN_CHANGED_SHARED_TRUST';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:328 }
  CozyText_TransportProbe_CANCELLED_REQUEST_DID_NOT_DRAIN_cb313a69 = 'CANCELLED_REQUEST_DID_NOT_DRAIN';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:415 }
  CozyText_TransportProbe_CONNECT_AUTHENTICATION_FAILED_2b760dbd = 'CONNECT_AUTHENTICATION_FAILED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:325 }
  CozyText_TransportProbe_CONNECT_CANCELLED_7cb16165 = 'CONNECT_CANCELLED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:393 }
  CozyText_TransportProbe_CONNECT_FAILED_3097c983 = 'CONNECT_FAILED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:337 }
  CozyText_TransportProbe_CONNECT_INVALID_RESPONSE_2bea095f = 'CONNECT_INVALID_RESPONSE';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:406 }
  CozyText_TransportProbe_CONNECT_PROFILE_REQUIRED_674114e0 = 'CONNECT_PROFILE_REQUIRED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:390 }
  CozyText_TransportProbe_CONNECT_TIMEOUT_56345c06 = 'CONNECT_TIMEOUT';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:152 }
  CozyText_TransportProbe_ChainingModeGCM_fc66d3e7 = 'ChainingModeGCM';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:167 }
  CozyText_TransportProbe_ChainingMode_e93ace4c = 'ChainingMode';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:428 }
  CozyText_TransportProbe_DEADLINE_STAGE_NOT_REACHED_fcb07fd5 = 'DEADLINE_STAGE_NOT_REACHED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:351 }
  CozyText_TransportProbe_DESTROY_CANCEL_BARRIER_da1b6874 = 'DESTROY_CANCEL_BARRIER';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:348 }
  CozyText_TransportProbe_DESTROY_DECRYPT_BARRIER_3aa4771f = 'DESTROY_DECRYPT_BARRIER';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:359 }
  CozyText_TransportProbe_DESTROY_FAILED_66e96dde = 'DESTROY_FAILED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:352 }
  CozyText_TransportProbe_DESTROY_FREED_ADMITTED_CRYPTO_177bd8b1 = 'DESTROY_FREED_ADMITTED_CRYPTO';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:356 }
  CozyText_TransportProbe_DESTROY_GATE_NOT_DRAINED_e9a40baf = 'DESTROY_GATE_NOT_DRAINED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:358 }
  CozyText_TransportProbe_DESTROY_PUBLISHED_REPLY_3cd5029c = 'DESTROY_PUBLISHED_REPLY';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:354 }
  CozyText_TransportProbe_DESTROY_REQUEST_NOT_DRAINED_7906c359 = 'DESTROY_REQUEST_NOT_DRAINED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:302 }
  CozyText_TransportProbe_ENCODER_BORROWED_BODY_CHANGED_f5faf456 = 'ENCODER_BORROWED_BODY_CHANGED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:303 }
  CozyText_TransportProbe_ENCODER_SCOPE_REVOKED_70e82c8a = 'ENCODER_SCOPE_REVOKED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:392 }
  CozyText_TransportProbe_EXPIRED_PLAN_CHANGED_SHARED_TRUST_dfd864a1 = 'EXPIRED_PLAN_CHANGED_SHARED_TRUST';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:271 }
  CozyText_TransportProbe_FAILED_REQUEST_RETURNED_JSON_2ccc7644 = 'FAILED_REQUEST_RETURNED_JSON';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:196 }
  CozyText_TransportProbe_GAME_CONNECT_4_3698b017 = 'GAME-CONNECT-4'#10;
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:130 }
  CozyText_TransportProbe_GAME_CONNECT_4_81d13dc6 = 'GAME-CONNECT-4';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:171 }
  CozyText_TransportProbe_GAME_CONNECT_4_REQUEST_b79708ef = 'GAME-CONNECT-4'#10'REQUEST'#10;
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:183 }
  CozyText_TransportProbe_JsonFixture_10caf599 = '{"ok":true,"token":"probe-only-value","korean":"';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:186 }
  CozyText_TransportProbe_JsonFixture_14c3c2ac = '{"token":"first","token":"second"}';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:185 }
  CozyText_TransportProbe_JsonFixture_739e981d = '[]';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:330 }
  CozyText_TransportProbe_LATE_REPLY_PUBLISHED_a3a1a74e = 'LATE_REPLY_PUBLISHED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:160 }
  CozyText_TransportProbe_OUTER_REQUEST_ID_REUSED_88a9eea5 = 'OUTER_REQUEST_ID_REUSED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:307 }
  CozyText_TransportProbe_OWNED_ENCODER_EXACT_BOUND_89292af6 = 'OWNED_ENCODER_EXACT_BOUND';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:301 }
  CozyText_TransportProbe_OWNED_ENCODER_WIRE_EQUAL_99776fb0 = 'OWNED_ENCODER_WIRE_EQUAL';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:282 }
  CozyText_TransportProbe_OWNED_RESULT_INVALID_8dcdfc42 = 'OWNED_RESULT_INVALID';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:407 }
  CozyText_TransportProbe_PARTIAL_CONSTRUCTOR_CLEANUP_37a91890 = 'PARTIAL_CONSTRUCTOR_CLEANUP';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:442 }
  CozyText_TransportProbe_PASS_37705799 = 'PASS ';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:391 }
  CozyText_TransportProbe_PIN_EXPIRY_STAGE_NOT_REACHED_8e169028 = 'PIN_EXPIRY_STAGE_NOT_REACHED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:284 }
  CozyText_TransportProbe_PIN_METADATA_LEAKED_TO_API_ed207711 = 'PIN_METADATA_LEAKED_TO_API';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:224 }
  CozyText_TransportProbe_PROBE_BARRIER_TIMEOUT_5e522955 = 'PROBE_BARRIER_TIMEOUT';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:33 }
  CozyText_TransportProbe_PROBE_CNG_FAILED_4667be8b = 'PROBE_CNG_FAILED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:218 }
  CozyText_TransportProbe_PROBE_STAGE_FAILURE_c0cb9f28 = 'PROBE_STAGE_FAILURE';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:435 }
  CozyText_TransportProbe_PUBLICATION_EXCEPTION_NOT_OBSERVED_1dba5977 = 'PUBLICATION_EXCEPTION_NOT_OBSERVED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:244 }
  CozyText_TransportProbe_REPLY_BUFFER_SCOPE_REVOKED_e58e0fd9 = 'REPLY_BUFFER_SCOPE_REVOKED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:199 }
  CozyText_TransportProbe_REPLY_GCM_LENGTH_ef831665 = 'REPLY_GCM_LENGTH';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:165 }
  CozyText_TransportProbe_REQUEST_AES_KEY_LENGTH_8a21edfc = 'REQUEST_AES_KEY_LENGTH';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:243 }
  CozyText_TransportProbe_REQUEST_BUFFER_SCOPE_REVOKED_7516227c = 'REQUEST_BUFFER_SCOPE_REVOKED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:318 }
  CozyText_TransportProbe_REQUEST_DID_NOT_REACH_BARRIER_0933c12b = 'REQUEST_DID_NOT_REACH_BARRIER';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:306 }
  CozyText_TransportProbe_REQUEST_ENVELOPE_LIMIT_cceb3b89 = 'REQUEST_ENVELOPE_LIMIT';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:174 }
  CozyText_TransportProbe_REQUEST_GCM_LENGTH_26ebd598 = 'REQUEST_GCM_LENGTH';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:176 }
  CozyText_TransportProbe_REQUEST_WIRE_OPERATION_ab7075b7 = 'REQUEST_WIRE_OPERATION';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:179 }
  CozyText_TransportProbe_REQUEST_f43c025f = 'REQUEST';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:323 }
  CozyText_TransportProbe_RESET_BEFORE_JOIN_ACCEPTED_76a50322 = 'RESET_BEFORE_JOIN_ACCEPTED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:178 }
  CozyText_TransportProbe_RESPONSE_d1681164 = 'RESPONSE';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:126 }
  CozyText_TransportProbe_RSAPUBLICBLOB_e4010f5c = 'RSAPUBLICBLOB';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:124 }
  CozyText_TransportProbe_RSA_b8d429b3 = 'RSA';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:162 }
  CozyText_TransportProbe_SHA256_b7cfd0a9 = 'SHA256';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:283 }
  CozyText_TransportProbe_STRICT_UTF8_ROUNDTRIP_b0c957c5 = 'STRICT_UTF8_ROUNDTRIP';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:322 }
  CozyText_TransportProbe_TRANSPORT_STILL_IN_USE_cd19470f = 'TRANSPORT_STILL_IN_USE';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:447 }
  CozyText_TransportProbe_Text_2d5976cf = ': ';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:183 }
  CozyText_TransportProbe_Text_492865d1 = '"}';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:420 }
  CozyText_TransportProbe_UNAUTHENTICATED_PLAINTEXT_EXPOSED_405f6f7c = 'UNAUTHENTICATED_PLAINTEXT_EXPOSED';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:394 }
  CozyText_TransportProbe_UNPINNED_PEER_CHANGED_SHARED_TRUST_c8964278 = 'UNPINNED_PEER_CHANGED_SHARED_TRUST';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:270 }
  CozyText_TransportProbe_WRONG_FAILURE_0af5e708 = 'WRONG_FAILURE:';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:272 }
  CozyText_TransportProbe_action_09329459 = 'action';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:216 }
  CozyText_TransportProbe_authenticated_plain_6738c0cc = 'authenticated-plain';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:400 }
  CozyText_TransportProbe_before_decrypt_79fc0403 = 'before-decrypt';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:387 }
  CozyText_TransportProbe_before_publication_0e2ed9b6 = 'before-publication';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:52 }
  CozyText_TransportProbe_body_84e6be3a = 'body';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:176 }
  CozyText_TransportProbe_bootstrap_c7f6bcad = 'bootstrap';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:170 }
  CozyText_TransportProbe_ciphertext_4b31d9c8 = 'ciphertext';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:376 }
  CozyText_TransportProbe_currentPin_1078aab6 = 'currentPin';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:373 }
  CozyText_TransportProbe_generation_5b9795ac = 'generation';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:131 }
  CozyText_TransportProbe_host_50e970d0 = 'host';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:377 }
  CozyText_TransportProbe_issuedAt_42e8ddfc = 'issuedAt';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:272 }
  CozyText_TransportProbe_keylessPolicy_22a83910 = 'keylessPolicy';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:283 }
  CozyText_TransportProbe_korean_f2c2d143 = 'korean';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:376 }
  CozyText_TransportProbe_nextPin_f53c2a2c = 'nextPin';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:169 }
  CozyText_TransportProbe_nonce_e8044a4e = 'nonce';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:377 }
  CozyText_TransportProbe_notBefore_06251c1a = 'notBefore';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:378 }
  CozyText_TransportProbe_oldNotAfter_f39ba572 = 'oldNotAfter';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:176 }
  CozyText_TransportProbe_operation_5f40fd6f = 'operation';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:400 }
  CozyText_TransportProbe_parsed_json_d4bccdcf = 'parsed-json';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:131 }
  CozyText_TransportProbe_port_934328c5 = 'port';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:131 }
  CozyText_TransportProbe_probe_invalid_bd41846d = 'probe.invalid';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:282 }
  CozyText_TransportProbe_probe_only_value_33c42b0a = 'probe-only-value';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:130 }
  CozyText_TransportProbe_protocol_d012c037 = 'protocol';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:159 }
  CozyText_TransportProbe_requestId_7876e4c6 = 'requestId';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:215 }
  CozyText_TransportProbe_request_plain_5615992f = 'request-plain';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:132 }
  CozyText_TransportProbe_serverKeyId_3c4df898 = 'serverKeyId';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:132 }
  CozyText_TransportProbe_serverPublicKey_ea86d85f = 'serverPublicKey';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:169 }
  CozyText_TransportProbe_tag_6ac25e46 = 'tag';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:133 }
  CozyText_TransportProbe_tlsCertificateSha256_0effdbe6 = 'tlsCertificateSha256';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:191 }
  CozyText_TransportProbe_tlsPinPlan_f7849715 = 'tlsPinPlan';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:388 }
  CozyText_TransportProbe_tlsPinState_dd99c042 = 'tlsPinState';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:133 }
  CozyText_TransportProbe_tlsServerName_4e14a03d = 'tlsServerName';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:282 }
  CozyText_TransportProbe_token_9dea2991 = 'token';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:442 }
  CozyText_TransportProbe_transport_checks_actual_CNG_owned_UTF8_JSON_canc_7da26707 = ' transport checks: actual CNG, owned UTF8/JSON, cancellation, late reply, reuse and cleanup';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:130 }
  CozyText_TransportProbe_version_de275fe7 = 'version';
  { Cozy.Tests/Cozy.Network/Cozy.TransportProbe.dpr:161 }
  CozyText_TransportProbe_wrappedKey_731f7972 = 'wrappedKey';

implementation
end.
