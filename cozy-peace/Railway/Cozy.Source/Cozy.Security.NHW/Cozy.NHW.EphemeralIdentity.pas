unit Cozy.NHW.EphemeralIdentity;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

const
  NHW_ALIAS_CAPACITY = 256;

type
  TPrivateActorSlot = record
    PID: Cardinal;
    Creation: UInt64;
    AliasId: UInt64;
    LastTick: UInt64;
  end;

  // v91. Aliases are random per process session and are never persisted.
  // A missing process creation time is UNKNOWN, not a stable identity.
  TSessionActorIdentity = class
  private
    FSlots: array[0..NHW_ALIAS_CAPACITY - 1] of TPrivateActorSlot;
    FLastTick: UInt64;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    function Observe(PID: Cardinal; Creation, Tick: UInt64): UInt64;
    function Existing(PID: Cardinal; Creation: UInt64): UInt64;
  end;

function NHWStrongRandom(Buffer: Pointer; Size: Cardinal): Boolean;

{$IFDEF NHW_NATIVE10Q_TESTS}
function TestEphemeralIdentity10Q(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

{$IFDEF NHW_NATIVE10Q_TESTS}
uses System.SysUtils;
{$ENDIF}

function BCryptGenRandom(hAlgorithm: THandle; Buffer: Pointer;
  BufferSize, Flags: Cardinal): LongInt; stdcall;
  external 'bcrypt.dll' name 'BCryptGenRandom';

function NHWStrongRandom(Buffer: Pointer; Size: Cardinal): Boolean;
begin
  Result := (Buffer <> nil) and (Size > 0) and
    (BCryptGenRandom(0, Buffer, Size, $00000002) = 0);
end;

constructor TSessionActorIdentity.Create;
begin
  inherited Create;
  Reset;
end;

destructor TSessionActorIdentity.Destroy;
begin
  Reset;
  inherited Destroy;
end;

procedure TSessionActorIdentity.Reset;
begin
  FillChar(FSlots, SizeOf(FSlots), 0);
  FLastTick := 0;
end;

function TSessionActorIdentity.Existing(PID: Cardinal;
  Creation: UInt64): UInt64;
var I: Integer;
begin
  Result := 0;
  if (PID <= 4) or (Creation = 0) then Exit;
  for I := Low(FSlots) to High(FSlots) do
    if (FSlots[I].PID = PID) and
       (FSlots[I].Creation = Creation) then
      Exit(FSlots[I].AliasId);
end;

function TSessionActorIdentity.Observe(PID: Cardinal;
  Creation, Tick: UInt64): UInt64;
var
  I, Slot: Integer;
  Candidate: UInt64;
  procedure SelectReplacementSlot(out Slot: Integer);
  var
    I: Integer;
    Oldest: UInt64;
  begin
    Slot := -1;
    Oldest := High(UInt64);
    for I := Low(FSlots) to High(FSlots) do
    begin
      if (FSlots[I].AliasId = 0) or
         ((Tick >= FSlots[I].LastTick) and
          (Tick - FSlots[I].LastTick > 120000)) then
      begin
        Slot := I;
        Break;
      end;
      if (Slot < 0) or (FSlots[I].LastTick < Oldest) then
      begin
        Oldest := FSlots[I].LastTick;
        Slot := I;
      end;
    end;
  end;

  function TryCreateUniqueAlias(out Candidate: UInt64): Boolean;
  var
    I, Tries: Integer;
  begin
    Result := False;
    Candidate := 0;
    for Tries := 0 to 3 do
    begin
      if not NHWStrongRandom(@Candidate, SizeOf(Candidate)) then Exit;
      if Candidate = 0 then Continue;
      for I := Low(FSlots) to High(FSlots) do
        if FSlots[I].AliasId = Candidate then
        begin
          Candidate := 0;
          Break;
        end;
      if Candidate <> 0 then Break;
    end;
    if Candidate = 0 then Exit;
    Result := True;
  end;

  procedure StoreActorIdentity;
  begin
    FSlots[Slot].PID := PID;
    FSlots[Slot].Creation := Creation;
    FSlots[Slot].AliasId := Candidate;
    FSlots[Slot].LastTick := Tick;
  end;

begin
  Result := 0;
  if (PID <= 4) or (Creation = 0) or (Tick = 0) then Exit;
  // An old event may resolve an already known actor, but may not refresh,
  // insert or evict entries in the current-session LRU.
  if Tick < FLastTick then Exit(Existing(PID, Creation));
  FLastTick := Tick;
  for I := Low(FSlots) to High(FSlots) do
    if (FSlots[I].PID = PID) and
       (FSlots[I].Creation = Creation) then
    begin
      if Tick > FSlots[I].LastTick then FSlots[I].LastTick := Tick;
      Exit(FSlots[I].AliasId);
    end;
  SelectReplacementSlot(Slot);
  if Slot < 0 then Exit;
  if not TryCreateUniqueAlias(Candidate) then Exit;
  StoreActorIdentity;
  Result := Candidate;
end;

{$IFDEF NHW_NATIVE10Q_TESTS}
{$I Cozy.NHW.Native10Q.EphemeralIdentity.inc}
{$ENDIF}

end.
