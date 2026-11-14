unit Cozy.SensitiveText;
{$IFDEF FPC}{$MODE DELPHI}{$ENDIF}
{$I ..\Cozy.Configuration\Cozy.Metadata.inc}
{$B-}
interface
uses
{ Cozy central text imports. }
  Cozy.Strings.Security,
 {$IFDEF FPC}SysUtils, SyncObjs{$ELSE}System.SysUtils, System.SyncObjs{$ENDIF}, Cozy.Api.Contracts;
type
  { App-owned UTF-16 only. Boundary strings/JSON and the user's clipboard are
    outside this allocation. This is lifetime control, not dump protection. }
  ICozySensitiveText = interface
    ['{5DBD01D2-5976-4A84-8FCA-96B524705F92}']
    function CopyText: UnicodeString;
    procedure Clear;
    function Count: Integer;
  end;
  TCozySensitiveText = class(TInterfacedObject, ICozySensitiveText)
  private
    FLock: TCriticalSection;
    FBuffer: TApiSensitiveBuffer;
    FLength, FMaximum: Integer;
  public
    constructor Create(Maximum: Integer);
    destructor Destroy; override;
    function CopyText: UnicodeString;
    procedure Assign(const Text: UnicodeString);
    procedure Append(Ch: WideChar);
    procedure AppendBuffer(Source: TCozySensitiveText);
    procedure Backspace;
    procedure Clear;
    function Count: Integer;
  end;
  { Record copies share one revocable allocation; Clear invalidates all aliases.
    Release only drops this handle, e.g. the caller relinquishing a session
    that the bootstrap client still owns for its close request. }
  TCozySecret = record
  private
    FOwner: ICozySensitiveText;
  public
    procedure Assign(const Text: UnicodeString; Maximum: Integer = 4096);
    function CopyText: UnicodeString;
    procedure Clear;
    procedure Release;
    function IsEmpty: Boolean;
  end;
procedure WipeBoundaryText(var Text: UnicodeString);
implementation
procedure WipeBoundaryText(var Text: UnicodeString);
begin
  if Text <> '' then
  begin
    UniqueString(Text);
    FillChar(PWideChar(Text)^, Length(Text) * SizeOf(WideChar), 0);
    Text := '';
  end;
end;
constructor TCozySensitiveText.Create(Maximum: Integer);
begin
  inherited Create;
  if (Maximum < 1) or (Maximum > 4096) then
    raise EArgumentOutOfRangeException.Create(CozyText_SensitiveText_SECRET_SIZE_INVALID_099110fc);
  FLock := TCriticalSection.Create;
  FMaximum := Maximum;
  FBuffer := TApiSensitiveBuffer.Create(NativeUInt(Maximum) * SizeOf(WideChar));
end;
destructor TCozySensitiveText.Destroy;
begin
  FBuffer.Free;
  FLock.Free;
  inherited;
end;
function TCozySensitiveText.CopyText: UnicodeString;
var Scope: TApiSensitiveScope;
begin
  Result := '';
  FLock.Acquire;
  try
    if FLength = 0 then Exit;
    Scope := FBuffer.OpenRead;
    try
      SetLength(Result, FLength);
      Move(Scope.Buffer.Read(0, NativeUInt(FLength) * SizeOf(WideChar))^,
        PWideChar(Result)^, FLength * SizeOf(WideChar));
    finally Scope.Free; end;
  finally FLock.Release; end;
end;
procedure TCozySensitiveText.Assign(const Text: UnicodeString);
var Scope: TApiSensitiveScope;
begin
  if Length(Text) > FMaximum then raise EArgumentOutOfRangeException.Create(CozyText_SensitiveText_SECRET_TOO_LONG_c3555c81);
  FLock.Acquire;
  try
    FBuffer.Clear; FLength := 0;
    if Text = '' then Exit;
    Scope := FBuffer.OpenWrite;
    try
      Move(PWideChar(Text)^, Scope.Buffer.Write(0, NativeUInt(Length(Text)) * SizeOf(WideChar))^,
        Length(Text) * SizeOf(WideChar));
      FLength := Length(Text);
    finally Scope.Free; end;
  finally FLock.Release; end;
end;
procedure TCozySensitiveText.Append(Ch: WideChar);
var Scope: TApiSensitiveScope;
begin
  FLock.Acquire;
  try
    if FLength >= FMaximum then raise EArgumentOutOfRangeException.Create(CozyText_SensitiveText_SECRET_TOO_LONG_c3555c81);
    Scope := FBuffer.OpenWrite;
    try
      PWideChar(Scope.Buffer.Write(NativeUInt(FLength) * SizeOf(WideChar), SizeOf(WideChar)))^ := Ch;
      Inc(FLength);
    finally Scope.Free; end;
  finally FLock.Release; end;
end;
procedure TCozySensitiveText.AppendBuffer(Source: TCozySensitiveText);
var ReadScope, WriteScope: TApiSensitiveScope; Amount: Integer;
begin
  if (Source = nil) or (Source = Self) then raise EArgumentException.Create(CozyText_SensitiveText_SECRET_SOURCE_INVALID_d1235b06);
  { Console owns both buffers on its input thread: no reverse lock order. }
  Source.FLock.Acquire;
  try
    FLock.Acquire;
    try
      Amount := Source.FLength;
      if Amount > FMaximum-FLength then raise EArgumentOutOfRangeException.Create(CozyText_SensitiveText_SECRET_TOO_LONG_c3555c81);
      if Amount = 0 then Exit;
      ReadScope := Source.FBuffer.OpenRead;
      try
        WriteScope := FBuffer.OpenWrite;
        try
          Move(ReadScope.Buffer.Read(0, NativeUInt(Amount)*SizeOf(WideChar))^,
            WriteScope.Buffer.Write(NativeUInt(FLength)*SizeOf(WideChar), NativeUInt(Amount)*SizeOf(WideChar))^,
            Amount*SizeOf(WideChar));
          Inc(FLength, Amount);
        finally WriteScope.Free; end;
      finally ReadScope.Free; end;
    finally FLock.Release; end;
  finally Source.FLock.Release; end;
end;
procedure TCozySensitiveText.Backspace;
var Scope: TApiSensitiveScope;
begin
  FLock.Acquire;
  try
    if FLength = 0 then Exit;
    Scope := FBuffer.OpenWrite;
    try
      Dec(FLength);
      PWideChar(Scope.Buffer.Write(NativeUInt(FLength)*SizeOf(WideChar), SizeOf(WideChar)))^ := #0;
    finally Scope.Free; end;
  finally FLock.Release; end;
end;
procedure TCozySensitiveText.Clear;
begin
  FLock.Acquire;
  try FBuffer.Clear; FLength := 0; finally FLock.Release; end;
end;
function TCozySensitiveText.Count: Integer;
begin
  FLock.Acquire;
  try Result := FLength; finally FLock.Release; end;
end;
procedure TCozySecret.Assign(const Text: UnicodeString; Maximum: Integer);
var NewOwner: ICozySensitiveText; Value: TCozySensitiveText;
begin
  Value := TCozySensitiveText.Create(Maximum);
  NewOwner := Value;
  Value.Assign(Text);
  Clear;
  FOwner := NewOwner;
end;
function TCozySecret.CopyText: UnicodeString;
begin
  if FOwner = nil then Result := '' else Result := FOwner.CopyText;
end;
procedure TCozySecret.Clear;
begin
  if FOwner <> nil then FOwner.Clear;
  FOwner := nil;
end;
procedure TCozySecret.Release;
begin FOwner := nil; end;
function TCozySecret.IsEmpty: Boolean;
begin Result := (FOwner = nil) or (FOwner.Count = 0); end;
end.
