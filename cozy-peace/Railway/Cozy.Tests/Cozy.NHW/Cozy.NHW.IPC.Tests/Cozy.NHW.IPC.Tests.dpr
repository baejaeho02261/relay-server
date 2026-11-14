program CozyNHW_IPC_Tests;

{$APPTYPE CONSOLE}
{$IFNDEF WIN64}
  {$MESSAGE FATAL 'Windows 64-bit only.'}
{$ENDIF}

uses
  System.SysUtils,
  System.Generics.Collections,
  Cozy.NHW.Types in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Types.pas',
  Cozy.NHW.Logging in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Logging.pas',
  Cozy.NHW.Native in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.Native.pas',
  Cozy.NHW.IPC in '..\..\..\Cozy.Source\Cozy.Security.NHW\Cozy.NHW.IPC.pas';

procedure Ensure(Condition: Boolean);
begin
  if not Condition then raise Exception.Create('IPC regression failure');
end;

function MakeObservation(PID: Cardinal; ObjectNo: NativeUInt;
  Kind: TIPCObjectKind; Rights: Cardinal): TIPCObservation;
begin
  Result := Default(TIPCObservation);
  Result.OwnerPID := PID;
  Result.ObjectIdentity := ObjectNo;
  Result.Kind := Kind;
  Result.GrantedAccess := Rights;
end;

var
  M: TIPCMonitor;
  O: TList<TIPCObservation>;
  D: TDetectionKinds;
  I: Integer;
begin
  M := TIPCMonitor.Create;
  O := TList<TIPCObservation>.Create;
  try
    O.Add(MakeObservation(4001, $100, ikEvent, $1));
    for I := 1 to 3 do
    begin
      D := [];
      M.Examine(O, True, UInt64(I)*500, D);
      Ensure(D = []);
    end;
    D := [];
    M.Examine(O, True, 2000, D);
    Ensure(D = []);

    O.Add(MakeObservation(4001, $200, ikMutex, $1));
    D := [];
    M.Examine(O, True, 2500, D);
    Ensure((dkMutex in D) and not (dkEvent in D) and
      not (dkIPC in D)); // baseline event must not count toward new-event IPC

    O.Add(MakeObservation(4001, $300, ikSection, $1));
    D := [];
    M.Examine(O, True, 3000, D);
    Ensure((dkSection in D) and (dkIPC in D));

    D := [];
    M.Examine(O, True, 3500, D);
    Ensure(D = []);

    O.Clear;
    D := [];
    M.Examine(O, False, 4000, D);
    Ensure(D = []); // invalid snapshot must not close tracked handles
    M.Examine(O, True, 4500, D);
    M.Examine(O, True, 5000, D);
    Ensure(D = []);

    O.Add(MakeObservation(4001, $100, ikEvent, $1));
    D := [];
    M.Examine(O, True, 5500, D);
    Ensure(dkEvent in D); // previously disappeared external access returned
    Ensure(not (dkIPC in D));
  finally
    O.Free;
    M.Free;
  end;
end.
