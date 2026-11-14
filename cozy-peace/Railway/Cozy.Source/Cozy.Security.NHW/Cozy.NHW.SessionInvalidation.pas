unit Cozy.NHW.SessionInvalidation;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Cozy.NHW.SessionTrustLadder;

type
  TSessionInvalidationReason = (sirLocalTrustQuorum, sirServerRejected);
  TSessionInvalidationReasons = set of TSessionInvalidationReason;

  TSessionInvalidationLatch = class
  private
    FInvalidated: Boolean;
    FReasons: TSessionInvalidationReasons;
    FLocalConfirmations: Byte;
    FEpoch: UInt64;
    FTick: UInt64;
  public
    constructor Create;
    procedure Reset(Epoch: UInt64 = 0);
    procedure BeginEpoch(Epoch: UInt64);
    procedure ObserveLocal(Trust: TKernelSessionTrust; ResponseQuorum: Boolean;
      Tick: UInt64);
    procedure ObserveLocalCorrelated(Trust: TKernelSessionTrust;
      ResponseQuorum, CorrelationApproved: Boolean; Tick: UInt64);
    procedure ApplyServerVerdict(Epoch: UInt64; Accepted: Boolean; Tick: UInt64);
    property Invalidated: Boolean read FInvalidated;
    property Reasons: TSessionInvalidationReasons read FReasons;
    property Epoch: UInt64 read FEpoch;
    property Tick: UInt64 read FTick;
  end;

implementation

constructor TSessionInvalidationLatch.Create;
begin
  inherited Create;
  Reset;
end;

procedure TSessionInvalidationLatch.Reset(Epoch: UInt64);
begin
  FInvalidated := False;
  FReasons := [];
  FLocalConfirmations := 0;
  FEpoch := Epoch;
  FTick := 0;
end;

procedure TSessionInvalidationLatch.BeginEpoch(Epoch: UInt64);
begin
  if (Epoch <> 0) and (Epoch > FEpoch) then Reset(Epoch);
end;

procedure TSessionInvalidationLatch.ObserveLocal(Trust: TKernelSessionTrust;
  ResponseQuorum: Boolean; Tick: UInt64);
begin
  if FInvalidated then Exit;
  if (Trust = kstUntrusted) and ResponseQuorum then
  begin
    if FLocalConfirmations < 2 then Inc(FLocalConfirmations);
    if FLocalConfirmations >= 2 then
    begin
      FInvalidated := True;
      Include(FReasons, sirLocalTrustQuorum);
      FTick := Tick;
    end;
  end
  else
    FLocalConfirmations := 0;
end;

procedure TSessionInvalidationLatch.ObserveLocalCorrelated(
  Trust: TKernelSessionTrust; ResponseQuorum, CorrelationApproved: Boolean;
  Tick: UInt64);
begin
  if not CorrelationApproved then
  begin
    if not FInvalidated then FLocalConfirmations := 0;
    Exit;
  end;
  ObserveLocal(Trust, ResponseQuorum, Tick);
end;

procedure TSessionInvalidationLatch.ApplyServerVerdict(Epoch: UInt64;
  Accepted: Boolean; Tick: UInt64);
begin
  if Accepted or FInvalidated then Exit;
  if (FEpoch = 0) or (Epoch <> FEpoch) then Exit;
  FInvalidated := True;
  Include(FReasons, sirServerRejected);
  FTick := Tick;
end;

end.
