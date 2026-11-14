{ Probe hooks must never be compiled into A/B/O. The project and each main
  program define GAME_APPLICATION_BUILD before including this file. }
{$IFDEF GAME_APPLICATION_BUILD}
  {$IFDEF GAME_STARTUP_ROLE_PROBE}
    {$MESSAGE FATAL 'Startup role probe entry points are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_DEVICE_SECURITY_TESTS}
    {$MESSAGE FATAL 'Device security probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_OWN_MEASUREMENT_TESTS}
    {$MESSAGE FATAL 'Own measurement fault hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_LIFECYCLE_CONTRACT_TESTS}
    {$MESSAGE FATAL 'Lifecycle probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_MEASUREMENT_TESTS}
    {$MESSAGE FATAL 'Measurement probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF COZY_HASH_WORKER_TESTS}
    {$MESSAGE FATAL 'Hash worker fault hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_ISSUED_A_TESTS}
    {$MESSAGE FATAL 'Issued A signature probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_RELAY_SOCKET_CONTRACT_TESTS}
    {$MESSAGE FATAL 'Relay socket probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF COZY_POINTER_GRAPH_PROBE}
    {$MESSAGE FATAL 'Pointer graph mutation probes are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF DEBUG}
    {$IFDEF RELEASE}
      {$MESSAGE FATAL 'Application build configuration cannot be both Debug and Release.'}
    {$ENDIF}
  {$ELSE}
    {$IFNDEF RELEASE}
      {$MESSAGE FATAL 'Application build configuration must define Debug or Release.'}
    {$ENDIF}
  {$ENDIF}
  {$IFDEF GAME_PRODUCT_FAULT_TESTS}
    {$MESSAGE FATAL 'Product fault hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_HANDOFF_CONTRACT_TESTS}
    {$MESSAGE FATAL 'Handoff probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_LICENSE_CONTRACT_TESTS}
    {$MESSAGE FATAL 'License probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_TLS_CONTRACT_TESTS}
    {$MESSAGE FATAL 'TLS probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_TRANSPORT_TESTS}
    {$MESSAGE FATAL 'Transport probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_IMGUI_FAULT_TESTS}
    {$MESSAGE FATAL 'ImGui fault hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_OVERLAY_CONTRACT_TESTS}
    {$MESSAGE FATAL 'Overlay probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_DEVICE_IDENTITY_PROBE}
    {$MESSAGE FATAL 'Device identity probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_RECOVERY_DEVICE_PROBE}
    {$MESSAGE FATAL 'Recovery device probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_DEVICE_KEY_PROBE}
    {$MESSAGE FATAL 'Device key probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_CRC_PE_PROBE}
    {$MESSAGE FATAL 'CRC PE probe hooks are forbidden in application builds.'}
  {$ENDIF}
  {$IFDEF GAME_NATIVE_ABI_TESTS}
    {$MESSAGE FATAL 'ABI probe hooks are forbidden in application builds.'}
  {$ENDIF}
{$ENDIF}
{ Project-owned types only. Include once near the start of EACH source unit.
  Release metadata minimization, not encryption or compiler-identity spoofing.
  Never patch PEB, PE directories, IAT, exception tables, or runtime type data.
  Keep Debug and the portable FPC hash test unchanged. }
{$IFNDEF FPC}
  {$IFDEF RELEASE}
    {$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
    {$WEAKLINKRTTI ON}
    {$D-}
    {$L-}
    {$Y-}
  {$ENDIF}
{$ENDIF}
