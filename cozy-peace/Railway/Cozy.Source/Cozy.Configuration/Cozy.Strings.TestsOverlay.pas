unit Cozy.Strings.TestsOverlay;
{$IFDEF FPC}{$MODE DELPHI}{$CODEPAGE UTF8}{$ENDIF}

{ Public source constants. Edit values here; this is not encryption. }
interface
const
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:53 }
  CozyText_OverlayDownloadDeadlineProbe_Deadline_arithmetic_only_no_network_authorizatio_93baacd2 = 'Deadline arithmetic only; no network, authorization or rendering execution.';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:11 }
  CozyText_OverlayDownloadDeadlineProbe_FAIL_fa0e2f90 = 'FAIL: ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:52 }
  CozyText_OverlayDownloadDeadlineProbe_OVERLAY_DOWNLOAD_DEADLINE_PASS_07f38fdf = 'OVERLAY_DOWNLOAD_DEADLINE_PASS ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:29 }
  CozyText_OverlayDownloadDeadlineProbe_OVERLAY_DOWNLOAD_TICKET_EXPIRED_65af6405 = 'OVERLAY_DOWNLOAD_TICKET_EXPIRED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:26 }
  CozyText_OverlayDownloadDeadlineProbe_OVERLAY_DOWNLOAD_TIMEOUT_77863866 = 'OVERLAY_DOWNLOAD_TIMEOUT';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:57 }
  CozyText_OverlayDownloadDeadlineProbe_Text_7c986bf4 = ': ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:45 }
  CozyText_OverlayDownloadDeadlineProbe_a_changed_or_later_ticket_cannot_extend_the_loca_1f826f73 = 'a changed or later ticket cannot extend the local download budget';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:33 }
  CozyText_OverlayDownloadDeadlineProbe_deadline_rejected_with_the_expected_closed_failu_787d1b3a = 'deadline rejected with the expected closed failure kind';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:43 }
  CozyText_OverlayDownloadDeadlineProbe_earlier_signed_ticket_expiry_caps_the_in_flight__f2941f48 = 'earlier signed ticket expiry caps the in-flight request';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:39 }
  CozyText_OverlayDownloadDeadlineProbe_initial_request_keeps_the_original_300_second_do_d6f01969 = 'initial request keeps the original 300 second download limit';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:41 }
  CozyText_OverlayDownloadDeadlineProbe_last_millisecond_does_not_grant_a_fresh_request__e6150c82 = 'last millisecond does not grant a fresh request budget';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:30 }
  CozyText_OverlayDownloadDeadlineProbe_ticket_expiry_exposes_only_its_fixed_diagnostic__30836032 = 'ticket expiry exposes only its fixed diagnostic code';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayDownloadDeadlineProbe.dpr:27 }
  CozyText_OverlayDownloadDeadlineProbe_timeout_exposes_only_its_fixed_diagnostic_code_d8be3df4 = 'timeout exposes only its fixed diagnostic code';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:140 }
  CozyText_OverlayEnvironmentProbe_A_selects_the_preceding_sample_artwork_268eed7d = 'A selects the preceding sample artwork';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:330 }
  CozyText_OverlayEnvironmentProbe_After_all_transitions_inspect_position_and_hit_a_116043aa = 'After all transitions inspect position and hit alignment, then focus the overlay and release F10.';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:118 }
  CozyText_OverlayEnvironmentProbe_Backspace_retires_a_pending_surrogate_fa18a975 = 'Backspace retires a pending surrogate';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:169 }
  CozyText_OverlayEnvironmentProbe_COUNTDOWN_CARD_TAB_AND_WINDOW_INPUT_DISABLED_f8990afa = 'COUNTDOWN_CARD_TAB_AND_WINDOW_INPUT_DISABLED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:171 }
  CozyText_OverlayEnvironmentProbe_COUNTDOWN_DOES_NOT_FINISH_EARLY_cc1b8f73 = 'COUNTDOWN_DOES_NOT_FINISH_EARLY';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:177 }
  CozyText_OverlayEnvironmentProbe_COUNTDOWN_INPUT_RESTORED_5a835c4d = 'COUNTDOWN_INPUT_RESTORED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:174 }
  CozyText_OverlayEnvironmentProbe_COUNTDOWN_RETURNS_TO_INTERACTIVE_GALLERY_cf2efbf9 = 'COUNTDOWN_RETURNS_TO_INTERACTIVE_GALLERY';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:189 }
  CozyText_OverlayEnvironmentProbe_DPI_suggested_rectangle_applied_7e125eb8 = 'DPI suggested rectangle applied';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:329 }
  CozyText_OverlayEnvironmentProbe_Disconnect_reconnect_the_SAME_Windows_session_ov_7fb90abb = 'Disconnect/reconnect the SAME Windows session over real RDP; also return to the console.';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:326 }
  CozyText_OverlayEnvironmentProbe_Drag_the_real_ImGui_window_between_PHYSICAL_moni_e5b37097 = 'Drag the real ImGui window between PHYSICAL monitors with DIFFERENT Windows scale settings.';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:122 }
  CozyText_OverlayEnvironmentProbe_Enter_retires_a_pending_surrogate_d6b11f59 = 'Enter retires a pending surrogate';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:224 }
  CozyText_OverlayEnvironmentProbe_GALLERY_REMAINS_OPEN_AFTER_START_AND_DISPLAY_TES_37bb1a23 = 'GALLERY_REMAINS_OPEN_AFTER_START_AND_DISPLAY_TESTS';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:328 }
  CozyText_OverlayEnvironmentProbe_Hold_mouse_drag_or_a_key_switch_focus_verify_no__25ad78d0 = 'Hold mouse drag or a key, switch focus; verify no stuck input. Press F6 for a checkpoint.';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:135 }
  CozyText_OverlayEnvironmentProbe_INITIAL_UNLICENSED_PRODUCT_START_DISABLED_577f1903 = 'INITIAL_UNLICENSED_PRODUCT_START_DISABLED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:304 }
  CozyText_OverlayEnvironmentProbe_INTERACTIVE_WINDOW_MESSAGES_d8ff7e36 = 'INTERACTIVE_WINDOW_MESSAGES';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:80 }
  CozyText_OverlayEnvironmentProbe_INTRO_BLOCKS_HOST_AND_SCENE_INPUT_bbc37a20 = 'INTRO_BLOCKS_HOST_AND_SCENE_INPUT';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:92 }
  CozyText_OverlayEnvironmentProbe_INTRO_COMPLETES_BEFORE_INTERACTION_CONTRACT_2124418e = 'INTRO_COMPLETES_BEFORE_INTERACTION_CONTRACT';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:252 }
  CozyText_OverlayEnvironmentProbe_INTRO_COMPLETION_DEADLINE_16bce147 = 'INTRO_COMPLETION_DEADLINE';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:70 }
  CozyText_OverlayEnvironmentProbe_INTRO_FIRST_VISIBLE_FRAME_IS_PARTIAL_a57d76a6 = 'INTRO_FIRST_VISIBLE_FRAME_IS_PARTIAL';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:315 }
  CozyText_OverlayEnvironmentProbe_MEASURED_712fa572 = 'MEASURED ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:226 }
  CozyText_OverlayEnvironmentProbe_NOT_RUN_physical_monitors_and_real_RDP_transitio_0cfda407 = 'NOT_RUN physical monitors and real RDP transitions in contract mode';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:331 }
  CozyText_OverlayEnvironmentProbe_No_message_injection_test_automation_or_simulate_9bc1dfbe = 'No message injection, test automation or simulated monitor drivers for physical results.';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:303 }
  CozyText_OverlayEnvironmentProbe_OVERLAY_ENVIRONMENT_MEASUREMENT_d11c6f73 = 'OVERLAY_ENVIRONMENT_MEASUREMENT';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:25 }
  CozyText_OverlayEnvironmentProbe_OVERLAY_ENVIRONMENT_e186af34 = 'OVERLAY_ENVIRONMENT: ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:327 }
  CozyText_OverlayEnvironmentProbe_On_each_monitor_interact_with_the_artwork_cards__2a2e0384 = 'On each monitor: interact with the artwork cards, then drag only the empty top header.';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:182 }
  CozyText_OverlayEnvironmentProbe_PASS_owned_window_Korean_text_input_contracts_ph_46d03128 = 'PASS owned-window Korean text input contracts; physical IME typing NOT_RUN';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:225 }
  CozyText_OverlayEnvironmentProbe_PASS_synthetic_message_contracts_five_DPI_scales_9aa44bbb = 'PASS synthetic message contracts: five DPI scales, hit boundaries, focus, session input cancellation';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:298 }
  CozyText_OverlayEnvironmentProbe_REMOVED_SERVER_SHUTDOWN_CALLBACKS_UNUSED_16ff2d78 = 'REMOVED_SERVER_SHUTDOWN_CALLBACKS_UNUSED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:138 }
  CozyText_OverlayEnvironmentProbe_Right_selects_the_next_sample_artwork_41cf6cff = 'Right selects the next sample artwork';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:164 }
  CozyText_OverlayEnvironmentProbe_START_AUTHORIZED_COUNTDOWN_STAYS_OPEN_d5965597 = 'START_AUTHORIZED_COUNTDOWN_STAYS_OPEN';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:175 }
  CozyText_OverlayEnvironmentProbe_START_DOES_NOT_RESTART_INTRO_84f56168 = 'START_DOES_NOT_RESTART_INTRO';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:158 }
  CozyText_OverlayEnvironmentProbe_START_PENDING_INPUT_DISABLED_e648153f = 'START_PENDING_INPUT_DISABLED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:152 }
  CozyText_OverlayEnvironmentProbe_START_PRODUCT_AUTHORIZATION_QUEUED_8409f219 = 'START_PRODUCT_AUTHORIZATION_QUEUED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:337 }
  CozyText_OverlayEnvironmentProbe_Text_10b41730 = ': ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:102 }
  CozyText_OverlayEnvironmentProbe_Text_9a5dccdf = '한글';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:181 }
  CozyText_OverlayEnvironmentProbe_UNLICENSED_PRODUCT_CANNOT_QUEUE_START_698bf247 = 'UNLICENSED_PRODUCT_CANNOT_QUEUE_START';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:102 }
  CozyText_OverlayEnvironmentProbe_WM_IME_CHAR_default_processing_commits_exactly_o_217faa37 = 'WM_IME_CHAR default processing commits exactly once';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:114 }
  CozyText_OverlayEnvironmentProbe_a_eda41243 = '한글a';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:333 }
  CozyText_OverlayEnvironmentProbe_arguments_953b5f48 = 'arguments';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:47 }
  CozyText_OverlayEnvironmentProbe_bottom_10ed4a2d = 'bottom';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:203 }
  CozyText_OverlayEnvironmentProbe_bottom_exclusive_0c644e11 = 'bottom exclusive';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:52 }
  CozyText_OverlayEnvironmentProbe_buttonTracking_7ffd4dcb = 'buttonTracking';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:53 }
  CozyText_OverlayEnvironmentProbe_captureOwned_1da82c51 = 'captureOwned';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:51 }
  CozyText_OverlayEnvironmentProbe_clearBefore_2be06509 = 'clearBefore';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:50 }
  CozyText_OverlayEnvironmentProbe_clearCount_4e10dd44 = 'clearCount';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:132 }
  CozyText_OverlayEnvironmentProbe_compact_gallery_is_the_initial_and_only_product__8d06fdb6 = 'compact gallery is the initial and only product page';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:107 }
  CozyText_OverlayEnvironmentProbe_composition_cancel_never_fabricates_committed_te_ab46a136 = 'composition cancel never fabricates committed text';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:333 }
  CozyText_OverlayEnvironmentProbe_contract_53267b2e = '--contract';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:296 }
  CozyText_OverlayEnvironmentProbe_contract_executed_49b42724 = 'contract executed';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:214 }
  CozyText_OverlayEnvironmentProbe_disconnect_clears_input_and_pauses_6cd4a0a9 = 'disconnect clears input and pauses';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:97 }
  CozyText_OverlayEnvironmentProbe_display_only_ignores_characters_9671c46c = 'display-only ignores characters';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:44 }
  CozyText_OverlayEnvironmentProbe_dpi_baa614b7 = 'dpi';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:52 }
  CozyText_OverlayEnvironmentProbe_dragging_2291c119 = 'dragging';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:308 }
  CozyText_OverlayEnvironmentProbe_durationMs_648c3c42 = 'durationMs';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:129 }
  CozyText_OverlayEnvironmentProbe_editor_opt_out_immediately_disables_text_transpo_6f0704d0 = 'editor opt-out immediately disables text transport';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:218 }
  CozyText_OverlayEnvironmentProbe_empty_header_drag_owns_capture_cb448727 = 'empty header drag owns capture';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:311 }
  CozyText_OverlayEnvironmentProbe_events_2495b16c = 'events';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:220 }
  CozyText_OverlayEnvironmentProbe_focus_loss_clears_drag_5d78eda4 = 'focus loss clears drag';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:112 }
  CozyText_OverlayEnvironmentProbe_focus_loss_wipes_pending_UTF16_78e2609e = 'focus loss wipes pending UTF16';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:325 }
  CozyText_OverlayEnvironmentProbe_fresh_workflow_nonce_and_absolute_output_292d4807 = 'fresh workflow nonce and absolute output';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:306 }
  CozyText_OverlayEnvironmentProbe_hardwareAttested_2ed128a4 = 'hardwareAttested';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:61 }
  CozyText_OverlayEnvironmentProbe_hostButtonHit_ab3779e7 = 'hostButtonHit';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:114 }
  CozyText_OverlayEnvironmentProbe_input_resumes_only_after_new_focus_a3509a10 = 'input resumes only after new focus';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:321 }
  CozyText_OverlayEnvironmentProbe_interactive_b1e4717f = '--interactive';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:41 }
  CozyText_OverlayEnvironmentProbe_kind_8b51a854 = 'kind';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:46 }
  CozyText_OverlayEnvironmentProbe_left_cb59d493 = 'left';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:239 }
  CozyText_OverlayEnvironmentProbe_message_c0b1bfee = 'message';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:315 }
  CozyText_OverlayEnvironmentProbe_messages_Physical_results_require_independent_re_6451d6ea = ' messages. Physical results require independent report validation.';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:304 }
  CozyText_OverlayEnvironmentProbe_mode_5bd0498a = 'mode';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:45 }
  CozyText_OverlayEnvironmentProbe_monitor_f2203376 = 'monitor';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:37 }
  CozyText_OverlayEnvironmentProbe_monitor_workarea_readback_dca78ed0 = 'monitor workarea readback';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:43 }
  CozyText_OverlayEnvironmentProbe_msg_05fdd00c = 'msg';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:321 }
  CozyText_OverlayEnvironmentProbe_nonce_5acaeff0 = '--nonce';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:304 }
  CozyText_OverlayEnvironmentProbe_nonce_ce7ccaa7 = 'nonce';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:204 }
  CozyText_OverlayEnvironmentProbe_only_the_empty_header_area_drags_the_window_d0a0aec2 = 'only the empty header area drags the window';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:307 }
  CozyText_OverlayEnvironmentProbe_operatorFinished_899313b3 = 'operatorFinished';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:240 }
  CozyText_OverlayEnvironmentProbe_operator_checkpoint_7cd5e192 = 'operator-checkpoint';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:126 }
  CozyText_OverlayEnvironmentProbe_out_of_range_WM_CHAR_retires_a_pending_surrogate_7d3acd49 = 'out-of-range WM_CHAR retires a pending surrogate';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:321 }
  CozyText_OverlayEnvironmentProbe_output_fe11b4d2 = '--output';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:313 }
  CozyText_OverlayEnvironmentProbe_output_must_be_new_5d28dd8f = 'output must be new';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:100 }
  CozyText_OverlayEnvironmentProbe_owned_WM_CHAR_commits_Korean_de41012e = 'owned WM_CHAR commits Korean';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:93 }
  CozyText_OverlayEnvironmentProbe_owned_real_renderer_HWND_d9480fad = 'owned real renderer HWND';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:192 }
  CozyText_OverlayEnvironmentProbe_per_monitor_DPI_transition_keeps_the_complete_sc_0f504ad3 = 'per-monitor DPI transition keeps the complete scene inside the selected work area';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:216 }
  CozyText_OverlayEnvironmentProbe_reconnect_remains_input_clear_f103a95e = 'reconnect remains input clear';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:310 }
  CozyText_OverlayEnvironmentProbe_remoteAtFinish_f3257de7 = 'remoteAtFinish';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:293 }
  CozyText_OverlayEnvironmentProbe_renderer_clean_shutdown_0dbdf030 = 'renderer clean shutdown';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:63 }
  CozyText_OverlayEnvironmentProbe_revealComplete_165dc7cb = 'revealComplete';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:47 }
  CozyText_OverlayEnvironmentProbe_right_97c4f306 = 'right';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:202 }
  CozyText_OverlayEnvironmentProbe_right_exclusive_70538eb1 = 'right exclusive';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:259 }
  CozyText_OverlayEnvironmentProbe_sample_e0540f01 = 'sample';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:206 }
  CozyText_OverlayEnvironmentProbe_scaled_button_hit_owns_capture_8d48b5d4 = 'scaled button hit owns capture';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:309 }
  CozyText_OverlayEnvironmentProbe_screenCount_69792615 = 'screenCount';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:41 }
  CozyText_OverlayEnvironmentProbe_seq_6847db02 = 'seq';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:54 }
  CozyText_OverlayEnvironmentProbe_sessionPaused_2464779c = 'sessionPaused';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:55 }
  CozyText_OverlayEnvironmentProbe_sessionRegistered_3b217bcc = 'sessionRegistered';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:56 }
  CozyText_OverlayEnvironmentProbe_suggestedMatches_987e396f = 'suggestedMatches';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:305 }
  CozyText_OverlayEnvironmentProbe_syntheticMessages_a7f6a26f = 'syntheticMessages';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:42 }
  CozyText_OverlayEnvironmentProbe_tick_a34a7c48 = 'tick';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:46 }
  CozyText_OverlayEnvironmentProbe_top_8c1c2945 = 'top';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:201 }
  CozyText_OverlayEnvironmentProbe_top_left_inclusive_477ddded = 'top-left inclusive';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:335 }
  CozyText_OverlayEnvironmentProbe_user32_dll_860bcf67 = 'user32.dll';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:303 }
  CozyText_OverlayEnvironmentProbe_version_171ab317 = 'version';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:44 }
  CozyText_OverlayEnvironmentProbe_windowDpi_4cdda6e3 = 'windowDpi';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:49 }
  CozyText_OverlayEnvironmentProbe_workBottom_3fc99347 = 'workBottom';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:48 }
  CozyText_OverlayEnvironmentProbe_workLeft_a710126f = 'workLeft';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:49 }
  CozyText_OverlayEnvironmentProbe_workRight_703f3e4f = 'workRight';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:48 }
  CozyText_OverlayEnvironmentProbe_workTop_3ec18ac2 = 'workTop';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayEnvironmentProbe.dpr:43 }
  CozyText_OverlayEnvironmentProbe_wparam_979dbc9b = 'wparam';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:67 }
  CozyText_OverlayFirstFrameProbe_D3D_preauthorization_window_remains_hidden_10c9b647 = 'D3D preauthorization window remains hidden';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:38 }
  CozyText_OverlayFirstFrameProbe_DPI_change_leaves_no_capture_a917aa76 = 'DPI change leaves no capture';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:69 }
  CozyText_OverlayFirstFrameProbe_EXPECTED_AUTHORITY_REJECT_054f8cfd = 'EXPECTED_AUTHORITY_REJECT';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:62 }
  CozyText_OverlayFirstFrameProbe_EXPECTED_CLOSING_FAILURE_b897b35d = 'EXPECTED_CLOSING_FAILURE';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:8 }
  CozyText_OverlayFirstFrameProbe_OVERLAY_FIRST_FRAME_97b424d0 = 'OVERLAY_FIRST_FRAME: ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:110 }
  CozyText_OverlayFirstFrameProbe_PASS_actual_HWND_D3D11_expiry_and_readiness_no_s_51703732 = 'PASS actual HWND/D3D11 expiry and readiness; no server authority bypass';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:101 }
  CozyText_OverlayFirstFrameProbe_PASS_real_renderer_first_frame_READY_case_58d308b1 = 'PASS real renderer first-frame/READY case ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:93 }
  CozyText_OverlayFirstFrameProbe_READY_event_remained_unsignalled_e74fb9a3 = 'READY event remained unsignalled';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:111 }
  CozyText_OverlayFirstFrameProbe_Text_201a2895 = ': ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:75 }
  CozyText_OverlayFirstFrameProbe_actual_hidden_startup_authority_callback_execute_ceacbebc = 'actual hidden startup authority callback executed';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:81 }
  CozyText_OverlayFirstFrameProbe_authority_rejection_closes_hidden_graphics_resou_d60c748b = 'authority rejection closes hidden graphics resources';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:82 }
  CozyText_OverlayFirstFrameProbe_authority_rejection_never_signals_READY_e9ba0ea7 = 'authority rejection never signals READY';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:86 }
  CozyText_OverlayFirstFrameProbe_closing_callback_failure_reports_failure_after_c_f0371523 = 'closing callback failure reports failure after cleanup';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:77 }
  CozyText_OverlayFirstFrameProbe_closing_callback_runs_exactly_once_3c48ba71 = 'closing callback runs exactly once';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:99 }
  CozyText_OverlayFirstFrameProbe_consumer_observes_READY_event_8112f659 = 'consumer observes READY event';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:92 }
  CozyText_OverlayFirstFrameProbe_expiry_cannot_acknowledge_READY_4aef081c = 'expiry cannot acknowledge READY';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:91 }
  CozyText_OverlayFirstFrameProbe_expiry_injected_at_actual_frame_boundary_44d1e781 = 'expiry injected at actual frame boundary';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:87 }
  CozyText_OverlayFirstFrameProbe_failure_was_after_the_visible_frame_4dac2c26 = 'failure was after the visible frame';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:32 }
  CozyText_OverlayFirstFrameProbe_focus_loss_releases_capture_b2ba9e4c = 'focus loss releases capture';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:68 }
  CozyText_OverlayFirstFrameProbe_hidden_device_initialization_never_acknowledges__d93177b9 = 'hidden device initialization never acknowledges READY';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:50 }
  CozyText_OverlayFirstFrameProbe_initial_authority_callback_precedes_every_READY_d15c884b = 'initial authority callback precedes every READY';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:34 }
  CozyText_OverlayFirstFrameProbe_minimize_leaves_no_capture_2a9c019a = 'minimize leaves no capture';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:78 }
  CozyText_OverlayFirstFrameProbe_no_surviving_renderer_HWND_9b9660fe = 'no surviving renderer HWND';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:98 }
  CozyText_OverlayFirstFrameProbe_one_real_visible_frame_acknowledges_READY_89edaee3 = 'one real visible frame acknowledges READY';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:29 }
  CozyText_OverlayFirstFrameProbe_owned_real_renderer_HWND_9611e159 = 'owned real renderer HWND';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:97 }
  CozyText_OverlayFirstFrameProbe_real_focus_minimize_DPI_message_path_executed_aa9aa54d = 'real focus/minimize/DPI message path executed';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:76 }
  CozyText_OverlayFirstFrameProbe_real_visible_Present_must_occur_before_timeout_f905095f = 'real visible Present must occur before timeout';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayFirstFrameProbe.dpr:20 }
  CozyText_OverlayFirstFrameProbe_test_owned_readiness_event_291aee8b = 'test-owned readiness event';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:44 }
  CozyText_OverlayGpuFaultProbe_CREATE_98e063bb = 'CREATE';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:115 }
  CozyText_OverlayGpuFaultProbe_FAILED_85976e1a = 'FAILED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:199 }
  CozyText_OverlayGpuFaultProbe_FLOATING_POINT_99833e6e = 'FLOATING_POINT';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:211 }
  CozyText_OverlayGpuFaultProbe_GPU_BEGIN_263ba954 = 'GPU_BEGIN';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:57 }
  CozyText_OverlayGpuFaultProbe_Injection_441f79ea = 'Injection';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:30 }
  CozyText_OverlayGpuFaultProbe_Native_overlay_fault_probe_1d64fdd8 = 'Native overlay fault probe';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:238 }
  CozyText_OverlayGpuFaultProbe_OS_exception_propagates_unchanged_5ec340e2 = 'OS exception propagates unchanged';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:11 }
  CozyText_OverlayGpuFaultProbe_OVERLAY_GPU_FAULT_5ddf5ce5 = 'OVERLAY_GPU_FAULT: ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:252 }
  CozyText_OverlayGpuFaultProbe_PASS_actual_Windows_D3D_resource_failure_unwind__78dda565 = 'PASS actual Windows D3D resource failure/unwind matrix';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:248 }
  CozyText_OverlayGpuFaultProbe_PASS_bounded_startup_OS_exception_diagnostics_65054ca2 = 'PASS bounded startup OS exception diagnostics';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:62 }
  CozyText_OverlayGpuFaultProbe_PASS_real_D3D11_create_resize_present_failure_3c45942f = 'PASS real D3D11 create/resize/present failure ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:181 }
  CozyText_OverlayGpuFaultProbe_PASS_renderer_startup_diagnostics_precede_closin_aade80fe = 'PASS renderer startup diagnostics precede closing and preserve failures';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:214 }
  CozyText_OverlayGpuFaultProbe_PRIVATE_TEST_MESSAGE_0x8007000E_193e81cf = 'PRIVATE_TEST_MESSAGE 0x8007000E';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:86 }
  CozyText_OverlayGpuFaultProbe_RESIZE_8c426906 = 'RESIZE';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:30 }
  CozyText_OverlayGpuFaultProbe_STATIC_4ce096cd = 'STATIC';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:155 }
  CozyText_OverlayGpuFaultProbe_TEST_POST_READY_FAILURE_386e760e = 'TEST_POST_READY_FAILURE';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:100 }
  CozyText_OverlayGpuFaultProbe_TEST_STARTUP_DIAGNOSTIC_UNAVAILABLE_42d7a714 = 'TEST_STARTUP_DIAGNOSTIC_UNAVAILABLE';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:253 }
  CozyText_OverlayGpuFaultProbe_Text_1d5caa9a = ': ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:51 }
  CozyText_OverlayGpuFaultProbe_actual_Resize_failure_688b8cc4 = 'actual Resize failure';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:55 }
  CozyText_OverlayGpuFaultProbe_actual_backend_NewFrame_d295243f = 'actual backend NewFrame';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:20 }
  CozyText_OverlayGpuFaultProbe_all_context_reservation_ownership_retired_978de361 = 'all context reservation ownership retired';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:22 }
  CozyText_OverlayGpuFaultProbe_backend_and_swap_chain_released_external_device__94965756 = 'backend and swap-chain released external device references';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:19 }
  CozyText_OverlayGpuFaultProbe_context_ownership_retired_13667f49 = 'context ownership retired';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:44 }
  CozyText_OverlayGpuFaultProbe_create_HRESULT_classification_f0e9ebaf = 'create HRESULT classification';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:42 }
  CozyText_OverlayGpuFaultProbe_create_keeps_failure_stage_f17e89cc = 'create keeps failure stage';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:43 }
  CozyText_OverlayGpuFaultProbe_create_keeps_original_HRESULT_9f9eb44c = 'create keeps original HRESULT';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:41 }
  CozyText_OverlayGpuFaultProbe_create_keeps_typed_graphics_failure_4c72c486 = 'create keeps typed graphics failure';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:96 }
  CozyText_OverlayGpuFaultProbe_detailed_callback_keeps_exact_create_or_initial__380c2510 = 'detailed callback keeps exact create or initial resize stage';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:97 }
  CozyText_OverlayGpuFaultProbe_detailed_callback_keeps_exact_signed_HRESULT_13d47808 = 'detailed callback keeps exact signed HRESULT';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:127 }
  CozyText_OverlayGpuFaultProbe_diagnostic_failure_does_not_replace_original_saf_c3d67e40 = 'diagnostic failure does not replace original safe graphics code';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:236 }
  CozyText_OverlayGpuFaultProbe_external_exception_propagates_unchanged_1c09892f = 'external exception propagates unchanged';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:48 }
  CozyText_OverlayGpuFaultProbe_failed_Create_releases_committed_arena_335fb457 = 'failed Create releases committed arena';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:59 }
  CozyText_OverlayGpuFaultProbe_failed_real_Present_cannot_be_visible_9fae952c = 'failed real Present cannot be visible';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:239 }
  CozyText_OverlayGpuFaultProbe_floating_point_exception_propagates_unchanged_04042af0 = 'floating point exception propagates unchanged';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:227 }
  CozyText_OverlayGpuFaultProbe_numeric_exception_keeps_its_closed_active_stage_6d567a5e = 'numeric exception keeps its closed active stage';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:228 }
  CozyText_OverlayGpuFaultProbe_numeric_exception_keeps_only_its_OS_code_or_zero_9e1bca3f = 'numeric exception keeps only its OS code or zero';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:245 }
  CozyText_OverlayGpuFaultProbe_numeric_failure_is_reported_once_before_normal_t_6a56c8fd = 'numeric failure is reported once before normal teardown';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:136 }
  CozyText_OverlayGpuFaultProbe_one_closing_callback_after_startup_failure_777cf2fe = 'one closing callback after startup failure';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:135 }
  CozyText_OverlayGpuFaultProbe_one_detailed_diagnostic_or_one_legacy_phase_fall_aa881dc8 = 'one detailed diagnostic or one legacy phase fallback, never both';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:237 }
  CozyText_OverlayGpuFaultProbe_ordinary_exception_propagates_unchanged_bcc2305d = 'ordinary exception propagates unchanged';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:60 }
  CozyText_OverlayGpuFaultProbe_present_HRESULT_preserved_9dcbb3d8 = 'present HRESULT preserved';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:47 }
  CozyText_OverlayGpuFaultProbe_real_allocation_then_injected_Create_failure_0cdd3473 = 'real allocation then injected Create failure';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:32 }
  CozyText_OverlayGpuFaultProbe_real_test_owned_HWND_2bd80fcb = 'real test-owned HWND';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:125 }
  CozyText_OverlayGpuFaultProbe_renderer_preserves_original_create_or_initial_re_048c7538 = 'renderer preserves original create or initial resize failure after callback';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:132 }
  CozyText_OverlayGpuFaultProbe_renderer_propagates_original_startup_error_d49bd272 = 'renderer propagates original startup error';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:140 }
  CozyText_OverlayGpuFaultProbe_renderer_startup_diagnostic_path_releases_native_0d688266 = 'renderer startup diagnostic path releases native reservation';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:52 }
  CozyText_OverlayGpuFaultProbe_resize_HRESULT_preserved_4aa3a417 = 'resize HRESULT preserved';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:17 }
  CozyText_OverlayGpuFaultProbe_retain_independent_real_device_reference_f58f259b = 'retain independent real device reference';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:138 }
  CozyText_OverlayGpuFaultProbe_startup_diagnostic_precedes_cancellation_in_OnCl_a76bf0b7 = 'startup diagnostic precedes cancellation in OnClosing';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:246 }
  CozyText_OverlayGpuFaultProbe_synthetic_exception_retains_no_native_reservatio_1d544182 = 'synthetic exception retains no native reservation';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:177 }
  CozyText_OverlayGpuFaultProbe_visible_first_frame_and_post_ready_teardown_neve_064e9044 = 'visible first-frame and post-ready teardown never call startup diagnostic transport';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:175 }
  CozyText_OverlayGpuFaultProbe_visible_first_second_ready_callback_fails_as_int_10f2b6cf = 'visible first/second ready callback fails as intended';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:171 }
  CozyText_OverlayGpuFaultProbe_visible_frame_failure_remains_original_failure_dcdb0262 = 'visible frame failure remains original failure';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGpuFaultProbe.dpr:179 }
  CozyText_OverlayGpuFaultProbe_visible_renderer_failure_releases_native_reserva_85f8b44b = 'visible renderer failure releases native reservation';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dpr:65 }
  CozyText_OverlayGraphicsProbe_0x_bb0fdab2 = ' 0x';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dpr:37 }
  CozyText_OverlayGraphicsProbe_BINDING_2f6f2922 = 'BINDING';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dpr:38 }
  CozyText_OverlayGraphicsProbe_CREATE_4c9b4535 = 'CREATE';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dpr:65 }
  CozyText_OverlayGraphicsProbe_FAIL_811edb21 = 'FAIL ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dpr:40 }
  CozyText_OverlayGraphicsProbe_FLOATING_POINT_186ee301 = 'FLOATING_POINT';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dpr:38 }
  CozyText_OverlayGraphicsProbe_FONT_DATA_5dd297e3 = 'FONT_DATA';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dpr:37 }
  CozyText_OverlayGraphicsProbe_FONT_READ_a5ceef9e = 'FONT_READ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dpr:40 }
  CozyText_OverlayGraphicsProbe_GPU_IDENTITY_a67668be = 'GPU_IDENTITY';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dpr:120 }
  CozyText_OverlayGraphicsProbe_PASS_REAL_WINDOWS_GRAPHICS_visibleFrames_1b290434 = 'PASS REAL_WINDOWS_GRAPHICS visibleFrames=';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dpr:39 }
  CozyText_OverlayGraphicsProbe_RESIZE_de9d6aba = 'RESIZE';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayGraphicsProbe.dpr:36 }
  CozyText_OverlayGraphicsProbe_UNKNOWN_a7225ca9 = 'UNKNOWN';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:49 }
  CozyText_OverlayMitigationProbe_FAIL_3b31819e = 'FAIL';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:64 }
  CozyText_OverlayMitigationProbe_FAIL_MITIGATION_COMPATIBILITY_0048d2b5 = 'FAIL MITIGATION_COMPATIBILITY';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:65 }
  CozyText_OverlayMitigationProbe_FAIL_fac28b21 = 'FAIL ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:39 }
  CozyText_OverlayMitigationProbe_GPU_IDENTITY_UNAVAILABLE_d152d451 = 'GPU_IDENTITY_UNAVAILABLE';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:41 }
  CozyText_OverlayMitigationProbe_MITIGATION_READBACK_FAILED_31f5245f = 'MITIGATION_READBACK_FAILED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:56 }
  CozyText_OverlayMitigationProbe_MITIGATION_VISIBLE_FRAME_FAILED_128bb20e = 'MITIGATION_VISIBLE_FRAME_FAILED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:40 }
  CozyText_OverlayMitigationProbe_PASS_a51e1038 = 'PASS';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:63 }
  CozyText_OverlayMitigationProbe_PASS_real_D3D_renderer_under_selected_OS_policy_deaa2528 = 'PASS real D3D renderer under selected OS policy';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:58 }
  CozyText_OverlayMitigationProbe_REAL_RENDERER_POLICY_AND_VISIBLE_PRESENT_927155c2 = 'REAL_RENDERER_POLICY_AND_VISIBLE_PRESENT';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:57 }
  CozyText_OverlayMitigationProbe_environment_3d2a2ca8 = 'environment';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:38 }
  CozyText_OverlayMitigationProbe_gpuIdentitySha512_17c8574e = 'gpuIdentitySha512';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:58 }
  CozyText_OverlayMitigationProbe_scope_392822fd = 'scope';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayMitigationProbe.dpr:59 }
  CozyText_OverlayMitigationProbe_visibleFrames_c77f3b54 = 'visibleFrames';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:13 }
  CozyText_OverlayPrivacyProbe_OVERLAY_PRIVACY_STATUS_INVALID_168d508c = 'OVERLAY_PRIVACY_STATUS_INVALID';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:72 }
  CozyText_OverlayPrivacyProbe_PASS_9_capture_privacy_status_cases_750efa6e = 'PASS: 9 capture-privacy status cases';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:52 }
  CozyText_OverlayPrivacyProbe_PASS_own_window_affinity_setter_readback_request_3d9a394f = 'PASS own-window affinity setter/readback requested=';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:26 }
  CozyText_OverlayPrivacyProbe_PRIVACY_OWN_WINDOW_MISSING_570dc45a = 'PRIVACY_OWN_WINDOW_MISSING';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:57 }
  CozyText_OverlayPrivacyProbe_PRIVACY_READBACK_MISMATCH_d2e79e4f = 'PRIVACY_READBACK_MISMATCH: ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:49 }
  CozyText_OverlayPrivacyProbe_PRIVACY_RENDERER_LIFECYCLE_FAILED_96b1fa4c = 'PRIVACY_RENDERER_LIFECYCLE_FAILED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:45 }
  CozyText_OverlayPrivacyProbe_PRIVACY_WINDOW_SHOWN_BEFORE_CONFIGURATION_cc3e2b31 = 'PRIVACY_WINDOW_SHOWN_BEFORE_CONFIGURATION';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:56 }
  CozyText_OverlayPrivacyProbe_SKIP_exact_own_window_affinity_readback_requeste_fc73dade = 'SKIP exact own-window affinity readback requested=';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:79 }
  CozyText_OverlayPrivacyProbe_Scope_own_window_affinity_API_result_only_extern_f5fcef20 = 'Scope: own-window affinity API result only; external capture blocking is not attested.';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:50 }
  CozyText_OverlayPrivacyProbe_Text_261babee = '화면 보호: 꺼짐';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:51 }
  CozyText_OverlayPrivacyProbe_Text_2a34d06b = '화면 보호: 캡처 제외 요청됨';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:64 }
  CozyText_OverlayPrivacyProbe_Text_90ab771d = '화면 보호: 설정 불일치';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:54 }
  CozyText_OverlayPrivacyProbe_Text_ae188367 = '화면 보호: 확인 불가';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:55 }
  CozyText_OverlayPrivacyProbe_Text_bb0ed578 = '화면 보호: 모니터 전용';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:53 }
  CozyText_OverlayPrivacyProbe_Text_d6ece64e = '화면 보호: 사용 불가';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:52 }
  CozyText_OverlayPrivacyProbe_Text_f8eb7824 = ': ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayPrivacyProbe.dpr:74 }
  CozyText_OverlayPrivacyProbe_Windows_affinity_NOT_RUN_on_this_portable_host_7f0402cc = 'Windows affinity NOT_RUN on this portable host';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:50 }
  CozyText_OverlayRenewalScheduleProbe_CONNECT_AUTHENTICATION_FAILED_d5a78617 = 'CONNECT_AUTHENTICATION_FAILED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:49 }
  CozyText_OverlayRenewalScheduleProbe_CONNECT_CANCELLED_3e2b73af = 'CONNECT_CANCELLED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:53 }
  CozyText_OverlayRenewalScheduleProbe_CONNECT_RECEIVE_FAILED_e7a134e3 = 'CONNECT_RECEIVE_FAILED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:45 }
  CozyText_OverlayRenewalScheduleProbe_CONNECT_TIMEOUT_3d7cdbe0 = 'CONNECT_TIMEOUT';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:52 }
  CozyText_OverlayRenewalScheduleProbe_CONNECT_UNAVAILABLE_a8d3bf4d = 'CONNECT_UNAVAILABLE';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:11 }
  CozyText_OverlayRenewalScheduleProbe_FAIL_7000878b = 'FAIL: ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:51 }
  CozyText_OverlayRenewalScheduleProbe_INTEGRITY_REJECTED_648afd6a = 'INTEGRITY_REJECTED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:22 }
  CozyText_OverlayRenewalScheduleProbe_OVERLAY_LEASE_EXPIRED_739dd6c8 = 'OVERLAY_LEASE_EXPIRED';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:13 }
  CozyText_OverlayRenewalScheduleProbe_PASS_7a5abcc9 = 'PASS: ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:56 }
  CozyText_OverlayRenewalScheduleProbe_SCHEDULING_PROBE_PASS_df352c54 = 'SCHEDULING_PROBE_PASS ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:57 }
  CozyText_OverlayRenewalScheduleProbe_Scheduling_only_not_an_overlay_rendering_server__f6dfc869 = 'Scheduling only: not an overlay rendering, server or B file deletion test.';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:61 }
  CozyText_OverlayRenewalScheduleProbe_Text_f3fc9c97 = ': ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:52 }
  CozyText_OverlayRenewalScheduleProbe_ambiguous_TLS_handshake_failure_never_retried_524d9b36 = 'ambiguous TLS handshake failure never retried';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:53 }
  CozyText_OverlayRenewalScheduleProbe_ambiguous_TLS_record_failure_never_retried_6853e1fe = 'ambiguous TLS record failure never retried';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:41 }
  CozyText_OverlayRenewalScheduleProbe_ample_snapshot_window_does_not_force_scan_efa72230 = 'ample snapshot window does not force scan';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:50 }
  CozyText_OverlayRenewalScheduleProbe_authentication_rejection_never_retried_38b15c17 = 'authentication rejection never retried';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:33 }
  CozyText_OverlayRenewalScheduleProbe_backward_tick_schedules_fresh_measurement_withou_af2b71ab = 'backward tick schedules fresh measurement without underflow';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:39 }
  CozyText_OverlayRenewalScheduleProbe_bounded_margin_between_batches_9b2763e5 = 'bounded margin between batches';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:49 }
  CozyText_OverlayRenewalScheduleProbe_cancellation_never_retried_c611d391 = 'cancellation never retried';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:35 }
  CozyText_OverlayRenewalScheduleProbe_cheap_renewal_estimate_allows_first_frame_73702377 = 'cheap renewal estimate allows first frame';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:32 }
  CozyText_OverlayRenewalScheduleProbe_complete_snapshot_due_at_15s_ceiling_7de91528 = 'complete snapshot due at 15s ceiling';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:30 }
  CozyText_OverlayRenewalScheduleProbe_confirm_transfer_before_full_rescan_2be3436b = 'confirm transfer before full rescan';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:42 }
  CozyText_OverlayRenewalScheduleProbe_do_not_repeat_proofs_at_unchanged_snapshot_ceili_a56db3d0 = 'do not repeat proofs at unchanged snapshot ceiling';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:48 }
  CozyText_OverlayRenewalScheduleProbe_expired_retry_refused_bbeb5d5c = 'expired retry refused';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:43 }
  CozyText_OverlayRenewalScheduleProbe_explicit_pre_scan_force_is_still_checked_20b66f35 = 'explicit pre-scan force is still checked';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:29 }
  CozyText_OverlayRenewalScheduleProbe_initial_snapshot_mandatory_8da0a40a = 'initial snapshot mandatory';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:36 }
  CozyText_OverlayRenewalScheduleProbe_initial_zero_grant_is_not_authorization_4be74644 = 'initial zero grant is not authorization';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:51 }
  CozyText_OverlayRenewalScheduleProbe_integrity_rejection_never_retried_8144a605 = 'integrity rejection never retried';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:54 }
  CozyText_OverlayRenewalScheduleProbe_large_estimate_cannot_overflow_retry_admission_94dcfa31 = 'large estimate cannot overflow retry admission';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:24 }
  CozyText_OverlayRenewalScheduleProbe_maintenance_cannot_resurrect_expiry_c478eead = 'maintenance cannot resurrect expiry';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:44 }
  CozyText_OverlayRenewalScheduleProbe_new_own_proof_useful_below_snapshot_ceiling_91db6b41 = 'new own proof useful below snapshot ceiling';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:38 }
  CozyText_OverlayRenewalScheduleProbe_no_unnecessary_batch_renewal_c2efe1d3 = 'no unnecessary batch renewal';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:31 }
  CozyText_OverlayRenewalScheduleProbe_not_due_before_15s_completion_ceiling_6d96427f = 'not due before 15s completion ceiling';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:34 }
  CozyText_OverlayRenewalScheduleProbe_old_full_cost_estimate_renewed_immediately_d41d525a = 'old full-cost estimate renewed immediately';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:45 }
  CozyText_OverlayRenewalScheduleProbe_one_transient_retry_within_old_grant_f4cafa2c = 'one transient retry within old grant';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:37 }
  CozyText_OverlayRenewalScheduleProbe_renew_before_periodic_scan_0e15ad5d = 'renew before periodic scan';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:47 }
  CozyText_OverlayRenewalScheduleProbe_retry_reserve_boundary_refused_d4355358 = 'retry reserve boundary refused';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:46 }
  CozyText_OverlayRenewalScheduleProbe_second_retry_refused_75b315ee = 'second retry refused';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayRenewalScheduleProbe.dpr:40 }
  CozyText_OverlayRenewalScheduleProbe_short_snapshot_bound_schedules_before_ceiling_40305007 = 'short snapshot bound schedules before ceiling';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:7 }
  CozyText_OverlayShutdownProbe_OVERLAY_SHUTDOWN_0f9ce2fe = 'OVERLAY_SHUTDOWN: ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:74 }
  CozyText_OverlayShutdownProbe_PASS_actual_process_shutdown_deadline_and_cancel_730d544d = 'PASS actual process shutdown deadline and cancellation';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:76 }
  CozyText_OverlayShutdownProbe_Text_ea3ec7fb = ': ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:50 }
  CozyText_OverlayShutdownProbe_Text_febbe197 = '" ';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:13 }
  CozyText_OverlayShutdownProbe_UI_cannot_extend_worker_deadline_86528808 = 'UI cannot extend worker deadline';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:14 }
  CozyText_OverlayShutdownProbe_already_expired_deadline_grants_no_wait_ffa64d3b = 'already-expired deadline grants no wait';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:67 }
  CozyText_OverlayShutdownProbe_blocked_5db33749 = '--blocked';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:68 }
  CozyText_OverlayShutdownProbe_cancel_b9bded32 = '--cancel';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:12 }
  CozyText_OverlayShutdownProbe_earlier_worker_deadline_preserves_close_reserve_77d217fb = 'earlier worker deadline preserves close reserve';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:55 }
  CozyText_OverlayShutdownProbe_expected_terminal_process_status_2b91cb1a = 'expected terminal process status';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:56 }
  CozyText_OverlayShutdownProbe_guard_does_not_terminate_before_deadline_77006835 = 'guard does not terminate before deadline';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:54 }
  CozyText_OverlayShutdownProbe_own_process_deadline_is_bounded_ff83e568 = 'own-process deadline is bounded';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:15 }
  CozyText_OverlayShutdownProbe_repeat_expiry_cannot_underflow_into_new_lifetime_013e3931 = 'repeat expiry cannot underflow into new lifetime';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:52 }
  CozyText_OverlayShutdownProbe_start_test_owned_child_763a27ac = 'start test-owned child';
  { Cozy.Tests/Cozy.Overlay/Cozy.OverlayShutdownProbe.dpr:69 }
  CozyText_OverlayShutdownProbe_worker_ui_blocked_27a3c050 = '--worker-ui-blocked';

implementation
end.
