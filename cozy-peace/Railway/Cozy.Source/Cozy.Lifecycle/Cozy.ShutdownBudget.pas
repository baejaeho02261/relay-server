unit Cozy.ShutdownBudget;
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Lifecycle,
 System.SysUtils;
const OverlayShutdownTotalMs = 5000;
type
  { Accounting and admission deadlines, not a thread termination mechanism. }
  TShutdownBudget = record
    Started, Deadline, JoinDeadline, JoinElapsed, CloseElapsed: UInt64;
    JoinMissed, CloseMissed: Boolean;
    procedure BeginAt(NowTick: UInt64; TotalMs: Cardinal = 5000;
      CloseReserveMs: Cardinal = 1000);
    procedure ConstrainTo(DeadlineTick: UInt64);
    function Remaining(NowTick: UInt64): Cardinal;
    procedure JoinedAt(NowTick: UInt64);
    procedure ClosedAt(NowTick: UInt64);
  end;
implementation
procedure TShutdownBudget.BeginAt(NowTick: UInt64; TotalMs, CloseReserveMs: Cardinal);
begin
  if (TotalMs = 0) or (TotalMs > 120000) or (CloseReserveMs > TotalMs) or
     (NowTick > High(UInt64) - UInt64(TotalMs)) then
    raise EInvalidOpException.Create(CozyText_ShutdownBudget_SHUTDOWN_BUDGET_INVALID_7e7dfd77);
  Started := NowTick; Deadline := NowTick + TotalMs;
  JoinDeadline := Deadline - CloseReserveMs;
  JoinElapsed := 0; CloseElapsed := 0; JoinMissed := False; CloseMissed := False;
end;
procedure TShutdownBudget.ConstrainTo(DeadlineTick: UInt64);
var Reserve: UInt64;
begin
  if (DeadlineTick = 0) or (DeadlineTick >= Deadline) then Exit;
  if Deadline >= JoinDeadline then Reserve := Deadline-JoinDeadline else Reserve := 0;
  Deadline := DeadlineTick;
  if Deadline > Reserve then JoinDeadline := Deadline-Reserve else JoinDeadline := 0;
  if JoinDeadline < Started then JoinDeadline := Started;
end;
function TShutdownBudget.Remaining(NowTick: UInt64): Cardinal;
begin
  if (NowTick < Started) or (NowTick >= Deadline) then Exit(0);
  Result := Cardinal(Deadline - NowTick);
end;
procedure TShutdownBudget.JoinedAt(NowTick: UInt64);
begin
  JoinMissed := (NowTick < Started) or (NowTick >= JoinDeadline);
  if NowTick >= Started then JoinElapsed := NowTick - Started;
end;
procedure TShutdownBudget.ClosedAt(NowTick: UInt64);
begin
  CloseMissed := (NowTick < Started) or (NowTick >= Deadline);
  if (NowTick >= Started) and (NowTick - Started >= JoinElapsed) then
    CloseElapsed := NowTick - Started - JoinElapsed;
end;
end.
