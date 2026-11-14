unit Cozy.NHW.PrivacyForensics;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses Winapi.Windows;

type
  TPrivateForensicEvent = record
    Tick: UInt64;
    ActorAlias: UInt64;
    RightsCategory: Byte;
    Corroborated: Boolean;
    HasCoverageGap: Boolean;
  end;

  // v99: no PID, file path, user name, machine ID, or remote endpoint in
  // the NEW privacy view; aliases disappear on restart.
  TPrivacyForensics = class
  private
    FEntries: array[0..63] of TPrivateForensicEvent;
    FNext, FCount: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Prune(Tick: UInt64);
    procedure Observe(ActorAlias, Tick: UInt64; RightsCategory: Byte;
      Corroborated, CoverageGap: Boolean);
    function Recent(Index: Integer; out Item: TPrivateForensicEvent): Boolean;
    property Count: Integer read FCount;
  end;

function NHWRightsCategory(Rights: Cardinal;
  IsThread: Boolean): Byte;

implementation

uses Cozy.NHW.Types, Cozy.NHW.NativeSafety;

function NHWRightsCategory(Rights: Cardinal;
  IsThread: Boolean): Byte;
begin
  Result := 0;
  if IsThread then
  begin
    if (Rights and (THREAD_SET_CONTEXT_RIGHT or
      THREAD_SUSPEND_RESUME_RIGHT)) <> 0 then Exit(3);
    if (Rights and THREAD_QUERY_INFORMATION_RIGHT) <> 0 then Exit(1);
  end
  else
  begin
    if (Rights and (ACCESS_VM_WRITE or ACCESS_VM_OPERATION or
      ACCESS_CREATE_THREAD)) <> 0 then Exit(3);
    if (Rights and ACCESS_VM_READ) <> 0 then Exit(2);
    if (Rights and PROCESS_QUERY_RIGHTS) <> 0 then Exit(1);
  end;
end;

constructor TPrivacyForensics.Create;
begin inherited Create; Reset; end;

destructor TPrivacyForensics.Destroy;
begin Reset; inherited Destroy; end;

procedure TPrivacyForensics.Reset;
begin
  FillChar(FEntries, SizeOf(FEntries), 0);
  FNext := 0;
  FCount := 0;
end;

procedure TPrivacyForensics.Prune(Tick: UInt64);
var Oldest, Newest: Integer;
begin
  if FCount > 0 then
  begin
    Newest := (FNext - 1 + Length(FEntries)) mod Length(FEntries);
    if Tick < FEntries[Newest].Tick then
    begin Reset; Exit; end;
  end;
  while FCount > 0 do
  begin
    Oldest := (FNext - FCount + Length(FEntries)) mod Length(FEntries);
    if not NHWExpired(FEntries[Oldest].Tick, Tick, 60000) then Break;
    FEntries[Oldest] := Default(TPrivateForensicEvent);
    Dec(FCount);
  end;
end;

procedure TPrivacyForensics.Observe(ActorAlias, Tick: UInt64;
  RightsCategory: Byte; Corroborated, CoverageGap: Boolean);
begin
  if ActorAlias = 0 then Exit;
  Prune(Tick);
  FEntries[FNext].Tick := Tick;
  FEntries[FNext].ActorAlias := ActorAlias;
  FEntries[FNext].RightsCategory := RightsCategory;
  FEntries[FNext].Corroborated := Corroborated;
  FEntries[FNext].HasCoverageGap := CoverageGap;
  FNext := (FNext + 1) mod Length(FEntries);
  if FCount < Length(FEntries) then Inc(FCount);
end;

function TPrivacyForensics.Recent(Index: Integer;
  out Item: TPrivateForensicEvent): Boolean;
var Pos: Integer;
begin
  Item := Default(TPrivateForensicEvent);
  Result := (Index >= 0) and (Index < FCount);
  if not Result then Exit;
  Pos := (FNext - 1 - Index + Length(FEntries)) mod Length(FEntries);
  Item := FEntries[Pos];
end;

end.
