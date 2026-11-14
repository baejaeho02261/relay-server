unit Cozy.NHW.RealtimeFusion;

{ Preserve the upstream Win64 compiler arithmetic and range settings for this unit. }
{$Q-}{$R-}

interface

uses
  Winapi.Windows,
  Cozy.NHW.FastEventRing;

type
  // v81: ETW is an observer only. Normal loads/starts are NOT alerts.
  TRealtimeFusion = class
  private
    FLastThread: UInt64;
    FLastImage: UInt64;
    FObservedCount: UInt64;
  public
    constructor Create;
    procedure Reset;
    procedure Observe(const Fast: TFastKernelSampleList;
      TargetPID: Cardinal; out Relevant: Boolean);
    function CorrelatedWithExternal(ExternalRights: Boolean;
      Tick: UInt64): Boolean;
    property ObservedCount: UInt64 read FObservedCount;
  end;

{$IFDEF NHW_NATIVE10M_TESTS}
function TestRealtimeFusion10M(out Failure: string; out Checks: Integer): Boolean;
{$ENDIF}

implementation

uses Cozy.NHW.ETWTypes{$IFDEF NHW_NATIVE10M_TESTS}, System.SysUtils{$ENDIF};

constructor TRealtimeFusion.Create;
begin inherited Create; Reset; end;

procedure TRealtimeFusion.Reset;
begin
  FLastThread := 0;
  FLastImage := 0;
  FObservedCount := 0;
end;

procedure TRealtimeFusion.Observe(const Fast: TFastKernelSampleList;
  TargetPID: Cardinal; out Relevant: Boolean);
var
  Item: TFastKernelSample;
begin
  Relevant := False;
  if (Fast = nil) or (TargetPID = 0) then Exit;
  for Item in Fast do
  begin
    if (Item.Event.PID <> TargetPID) and
       (Item.Event.ParentPID <> TargetPID) then Continue;
    if FObservedCount < High(UInt64) then Inc(FObservedCount);
    case Item.Event.Kind of
      keThreadStart, keThreadEnd:
        begin
          if Item.Event.Tick > FLastThread then FLastThread := Item.Event.Tick;
          Relevant := True;
        end;
      keImageLoad, keImageUnload:
        begin
          if Item.Event.Tick > FLastImage then FLastImage := Item.Event.Tick;
          Relevant := True;
        end;
      keProcessStart, keProcessEnd:
        Relevant := True;
    end;
  end;
end;

function TRealtimeFusion.CorrelatedWithExternal(ExternalRights: Boolean;
  Tick: UInt64): Boolean;
begin
  Result := ExternalRights and
    (((FLastThread <> 0) and (Tick >= FLastThread) and
      (Tick - FLastThread <= 2500)) or
     ((FLastImage <> 0) and (Tick >= FLastImage) and
      (Tick - FLastImage <= 2500)));
end;

{$IFDEF NHW_NATIVE10M_TESTS}
{$I Cozy.NHW.Native10M.RealtimeFusion.inc}
{$ENDIF}

end.
