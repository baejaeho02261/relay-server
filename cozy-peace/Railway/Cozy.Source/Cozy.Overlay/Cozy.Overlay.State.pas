unit Cozy.Overlay.State;
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Overlay,
 {$IFDEF FPC}SysUtils{$ELSE}System.SysUtils{$ENDIF};
const
  OverlayRunSettleMilliseconds = 160;
  OverlayRunGrantMarginMilliseconds = 250;
type TOverlayState = (osCreated, osAuthorized, osVisible, osTransferred, osClosing, osClosed);
function OverlayCanTransition(Current, Next: TOverlayState): Boolean;
procedure OverlayTransition(var Current: TOverlayState; Next: TOverlayState);
function OverlayNextRenewal(NowTick, Deadline, LastDuration: UInt64): UInt64;
function OverlaySnapshotDue(NowTick, LastAcceptedTick: UInt64;
  Transferred: Boolean; SnapshotDeadline: UInt64 = 0;
  LastSnapshotDuration: UInt64 = 0): Boolean;
function OverlayLeaseNeedsMaintenance(NowTick, Deadline, LastDuration: UInt64;
  Force: Boolean; SnapshotDeadline: UInt64 = 0): Boolean;
function OverlayTransientRetryAllowed(NowTick, Deadline, LastDuration: UInt64;
  AlreadyRetried: Boolean; const TransportCode: string): Boolean;
function OverlayGraphicsFailure(ErrorCode: Integer; const Operation: string): string;
{ Display affinity is best-effort OS privacy, never an authorization signal. }
function OverlayCapturePrivacyStatus(Requested, SetSucceeded, ReadSucceeded: Boolean;
  ObservedAffinity: Cardinal): string;
{ Immutable presentation catalogue; unknown/legacy-unassigned means no START.
  The server independently checks the same product ID against the license. }
function OverlayProductID(Card: Integer): string;
function OverlayProductCard(const ProductID: string): Integer;
function OverlayCategoryCard(Category, Card: Integer): Integer;
function OverlayProductCanStart(LicensedCard, SelectedCard: Integer): Boolean;
function OverlayProductRunMilliseconds(Card: Integer): Cardinal;
implementation
function OverlayProductID(Card: Integer): string;
begin
  case Card of
    0: Result := CozyText_Overlay_State_cleaner_pubg_e307bc5f;
    1: Result := CozyText_Overlay_State_cleaner_talesrunner_95ba8aa1;
    2: Result := CozyText_Overlay_State_cleaner_lost_saga_1f12cd54;
    3: Result := CozyText_Overlay_State_cleaner_apex_fcf35fa8;
    4: Result := CozyText_Overlay_State_cleaner_overwatch_cd9d1305;
    5: Result := CozyText_Overlay_State_cleaner_counter_strike_6f2f20e0;
    6: Result := CozyText_Overlay_State_spoofer_battleye_4715993c;
    7: Result := CozyText_Overlay_State_spoofer_xigncode3_f98af8d4;
    8: Result := CozyText_Overlay_State_spoofer_easy_anti_cheat_8f2cdf17;
    9: Result := CozyText_Overlay_State_spoofer_vanguard_ec73c0ac;
    10: Result := CozyText_Overlay_State_spoofer_ricochet_671d995c;
    11: Result := CozyText_Overlay_State_spoofer_ace_4a87a8b3;
    12: Result := CozyText_Overlay_State_mobile_roblox_a24043c3;
    13: Result := CozyText_Overlay_State_mobile_brawl_stars_e2b20288;
    14: Result := CozyText_Overlay_State_mobile_pubg_mobile_d0203f1a;
    15: Result := CozyText_Overlay_State_mobile_genshin_impact_27291568;
    16: Result := CozyText_Overlay_State_mobile_pokemon_go_fbe6e15a;
    17: Result := CozyText_Overlay_State_mobile_clash_royale_194b0bf8;
  else Result := '';
  end;
end;
function OverlayProductCard(const ProductID: string): Integer;
var I: Integer;
begin
  Result := -1;
  if ProductID = '' then Exit;
  for I := 0 to 17 do
    if ProductID = OverlayProductID(I) then Exit(I);
end;
function OverlayCategoryCard(Category, Card: Integer): Integer;
begin
  if (Card < 0) or (Card > 5) then Exit(-1);
  case Category of
    0: Result := Card;
    1: Result := 12 + Card;
    2: Result := 6 + Card;
  else Result := -1;
  end;
end;
function OverlayProductCanStart(LicensedCard, SelectedCard: Integer): Boolean;
begin
  Result := (LicensedCard >= 0) and (LicensedCard < 18) and
    (SelectedCard = LicensedCard);
end;
function OverlayProductRunMilliseconds(Card: Integer): Cardinal;
begin
  { Presentation only; signed START approval and runtime authority remain
    mandatory. Each product has its own bounded animation duration. }
  if (Card < 0) or (Card > 17) then Exit(0);
  Result := 2400 + ((Card * 7) mod 18) * 110;
end;
function OverlayCapturePrivacyStatus(Requested, SetSucceeded, ReadSucceeded: Boolean;
  ObservedAffinity: Cardinal): string;
begin
  if not SetSucceeded then Exit(CozyText_Overlay_State_Text_dad0123c);
  if not ReadSucceeded then Exit(CozyText_Overlay_State_Text_bb7b2f7c);
  if not Requested then
  begin
    if ObservedAffinity = 0 then Exit(CozyText_Overlay_State_Text_86fbc0f4);
    Exit(CozyText_Overlay_State_Text_4a5af965);
  end;
  case ObservedAffinity of
    $11: Result := CozyText_Overlay_State_Text_f4f302df;
    $01: Result := CozyText_Overlay_State_Text_8d84fce3;
  else Result := CozyText_Overlay_State_Text_4a5af965;
  end;
end;
function OverlayCanTransition(Current, Next: TOverlayState): Boolean;
begin
  Result := False;
  case Current of
    osCreated: Result := Next in [osAuthorized, osClosing];
    osAuthorized: Result := Next in [osVisible, osClosing];
    osVisible: Result := Next in [osTransferred, osClosing];
    osTransferred: Result := Next = osClosing;
    osClosing: Result := Next = osClosed;
  end;
end;
procedure OverlayTransition(var Current: TOverlayState; Next: TOverlayState);
begin
  if not OverlayCanTransition(Current, Next) then
    raise EInvalidOpException.Create(CozyText_Overlay_State_OVERLAY_STATE_TRANSITION_INVALID_7c3ea00c);
  Current := Next;
end;
function OverlayNextRenewal(NowTick, Deadline, LastDuration: UInt64): UInt64;
var Remaining, Margin, Delay: UInt64;
begin
  if Deadline <= NowTick then raise EInvalidOpException.Create(CozyText_Overlay_State_OVERLAY_LEASE_EXPIRED_60078b1c);
  Remaining := Deadline - NowTick;
  if LastDuration > 120000 then LastDuration := 120000;
  Margin := LastDuration * 2 + 1000;
  if Remaining <= Margin then Exit(NowTick);
  Delay := Remaining div 2;
  if Delay > 10000 then Delay := 10000;
  if Delay > Remaining - Margin then Delay := Remaining - Margin;
  Result := NowTick + Delay;
end;
function OverlaySnapshotDue(NowTick, LastAcceptedTick: UInt64;
  Transferred: Boolean; SnapshotDeadline, LastSnapshotDuration: UInt64): Boolean;
var Estimate, Reserve: UInt64;
begin
  Result := LastAcceptedTick = 0;
  if Result or not Transferred then Exit;
  if NowTick < LastAcceptedTick then Exit(True);
  { Bound planning only: this helper never supplies runtime permission.
    Account for collection AND all report uploads/renewals, not just disk I/O.
    The 15s ceiling avoids waiting 45s before another 35-60s full transaction. }
  if NowTick - LastAcceptedTick >= 15000 then Exit(True);
  if SnapshotDeadline = 0 then Exit(False); { older server: conservative ceiling }
  if SnapshotDeadline <= NowTick then Exit(True);
  Estimate := LastSnapshotDuration;
  if Estimate < 45000 then Estimate := 45000;
  if Estimate > 120000 then Estimate := 120000;
  Reserve := Estimate + Estimate div 2 + 5000;
  Result := SnapshotDeadline - NowTick <= Reserve;
end;
function OverlayLeaseNeedsMaintenance(NowTick, Deadline, LastDuration: UInt64;
  Force: Boolean; SnapshotDeadline: UInt64): Boolean;
var Margin: UInt64;
begin
  if Deadline = 0 then Exit(False);
  if Deadline <= NowTick then
    raise EInvalidOpException.Create(CozyText_Overlay_State_OVERLAY_LEASE_EXPIRED_60078b1c);
  { A fresh own-image proof cannot extend the SAME snapshot's expiry.
    Repeating it before every remaining batch can starve that very snapshot.
    Force is reserved for one pre-scan/transfer confirmation, not every batch. }
  if not Force and (SnapshotDeadline <> 0) and
    ((SnapshotDeadline <= Deadline) or (SnapshotDeadline - Deadline <= 1000)) then
    Exit(False);
  if LastDuration > 120000 then LastDuration := 120000;
  Margin := LastDuration * 2 + 2000;
  if Margin < 20000 then Margin := 20000;
  Result := Force or (Deadline - NowTick <= Margin);
end;
function OverlayTransientRetryAllowed(NowTick, Deadline, LastDuration: UInt64;
  AlreadyRetried: Boolean; const TransportCode: string): Boolean;
var Reserve: UInt64;
begin
  Result := False;
  if AlreadyRetried or (Deadline <= NowTick) then Exit;
  { Broad socket failure codes also cover TLS handshake/record rejection.
    Only the transport's explicit elapsed-deadline code is retryable. }
  if TransportCode <> CozyText_Overlay_State_CONNECT_TIMEOUT_e6a05508 then Exit;
  if LastDuration > 120000 then LastDuration := 120000;
  Reserve := LastDuration * 2 + 1000;
  if Reserve < 12000 then Reserve := 12000;
  { This is only retry admission. It never supplies or extends authority. }
  Result := Deadline - NowTick > Reserve;
end;
function OverlayGraphicsFailure(ErrorCode: Integer; const Operation: string): string;
begin
  case Cardinal(ErrorCode) of
    { FACILITY_ITF codes identify our own CPU resource admission gates. They
      must not be interpreted as an observed Windows/GPU memory failure. }
    $8004C201, $8004C202, $8004C203, $8004C204:
      Result := CozyText_Overlay_State_OVERLAY_GRAPHICS_RESOURCE_ADMISSION_FAILED_a5573b55;
    $8007000E: Result := CozyText_Overlay_State_OVERLAY_GRAPHICS_OUT_OF_MEMORY_ea251a40;
    $887A0005, $887A0006, $887A0007: Result := CozyText_Overlay_State_OVERLAY_GRAPHICS_DEVICE_LOST_60d829b4;
  else
    if Operation = CozyText_Overlay_State_RESIZE_459a44f6 then Result := CozyText_Overlay_State_OVERLAY_GRAPHICS_RESIZE_FAILED_8a4d88d6
    else Result := CozyText_Overlay_State_OVERLAY_GRAPHICS_dcc4911f + Operation + CozyText_Overlay_State_FAILED_f1b6a729;
  end;
  { No automatic device recreation: an error closes only our own authorized UI. }
end;
end.
