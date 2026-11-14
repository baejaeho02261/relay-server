program Cozy_MetadataProbe;

{$APPTYPE CONSOLE}
{$IFNDEF RELEASE}
  {$MESSAGE FATAL 'Build Cozy.MetadataProbe with -DRELEASE.'}
{$ENDIF}
{$I ..\..\Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc}

uses
{ Cozy central text imports. }
  Cozy.Strings.Integrity in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Integrity.pas',
  Cozy.Strings.Platform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.Platform.pas',
  Cozy.Strings.TestsConfiguration in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsConfiguration.pas',
{$IF (Defined(GAME_NATIVE_ABI_TESTS))}
  Cozy.Strings.TestsPlatform in '..\..\Cozy.Source\Cozy.Configuration\Cozy.Strings.TestsPlatform.pas',
{$ENDIF}

  System.SysUtils, System.TypInfo, System.Rtti,
  Cozy.Api.Types in '..\..\Cozy.Source\Cozy.Platform\Cozy.Api.Types.pas';

type
  EMetadataProbe = class(Exception);
  TMetadataProbe = class
  private
    FValue: Integer;
  public
    constructor Create(Value: Integer);
    function ReadValue: Integer;
    property Value: Integer read FValue;
  end;

procedure Require(Condition: Boolean; const MessageText: string);
begin
  if not Condition then
    raise Exception.Create(MessageText);
end;

constructor TMetadataProbe.Create(Value: Integer);
begin
  inherited Create;
  FValue := Value;
end;

function TMetadataProbe.ReadValue: Integer;
begin
  Result := FValue;
end;

procedure CheckClassMetadata(var Context: TRttiContext; AClass: TClass);
var RttiType: TRttiType;
begin
  RttiType := Context.GetType(AClass);
  Require(RttiType <> nil, CozyText_MetadataProbe_Basic_class_type_information_must_remain_valid_13db9eed);
  Require(Length(RttiType.GetDeclaredMethods) = 0,
    CozyText_MetadataProbe_Unexpected_declared_method_RTTI_08851c8b + AClass.ClassName);
  Require(Length(RttiType.GetDeclaredFields) = 0,
    CozyText_MetadataProbe_Unexpected_declared_field_RTTI_3d958efd + AClass.ClassName);
  Require(Length(RttiType.GetDeclaredProperties) = 0,
    CozyText_MetadataProbe_Unexpected_declared_property_RTTI_dc241db8 + AClass.ClassName);
end;

procedure RunChecks;
var
  Context: TRttiContext;
  RttiType: TRttiType;
  Obj: TMetadataProbe;
  ApiError: EGameApi;
  Caught: Boolean;
begin
  Context := TRttiContext.Create;
  try
    CheckClassMetadata(Context, TMetadataProbe);
    CheckClassMetadata(Context, EGameApi);
    RttiType := Context.GetType(TypeInfo(TLicenseState));
    Require(RttiType <> nil, CozyText_MetadataProbe_The_explicitly_referenced_record_type_must_exist_ae0a76ea);
    Require(Length(RttiType.GetFields) = 0, CozyText_MetadataProbe_Unexpected_record_field_RTTI_52b911f7);
    Require(Length(RttiType.GetMethods) = 0, CozyText_MetadataProbe_Unexpected_record_method_RTTI_4511345a);
    Require(Length(RttiType.GetProperties) = 0, CozyText_MetadataProbe_Unexpected_record_property_RTTI_5aff0008);
    Obj := TMetadataProbe.Create(42);
    try
      Require(Obj.ReadValue = 42, CozyText_MetadataProbe_Direct_method_call_changed_dbeb7000);
      Require(Obj.Value = 42, CozyText_MetadataProbe_Direct_property_access_changed_b2e3bb2e);
      Require(Obj is TMetadataProbe, CozyText_MetadataProbe_Runtime_class_identity_changed_5209660a);
    finally
      Obj.Free;
    end;
    ApiError := EGameApi.Create(CozyText_MetadataProbe_PROBE_88cd2fb3, CozyText_MetadataProbe_Metadata_probe_d87d6b09, True);
    try
      Require((ApiError.Code = CozyText_MetadataProbe_PROBE_88cd2fb3) and ApiError.Retryable,
        CozyText_MetadataProbe_Existing_application_exception_properties_change_ae6cbccc);
    finally
      ApiError.Free;
    end;
    Caught := False;
    try
      raise EMetadataProbe.Create(CozyText_MetadataProbe_Expected_exception_274c79d5);
    except
      on E: EMetadataProbe do Caught := True;
    end;
    Require(Caught, CozyText_MetadataProbe_Exception_matching_changed_a3d5263b);
  finally
    Context.Free;
  end;
end;

begin
  try
    RunChecks;
    Writeln(CozyText_MetadataProbe_PASS_metadata_direct_calls_properties_class_iden_889b880e);
    ExitCode := 0;
  except
    on E: Exception do
    begin
      Writeln(CozyText_MetadataProbe_FAIL_d5bbda30, E.ClassName, CozyText_MetadataProbe_Text_bdc17a6c, E.Message);
      ExitCode := 1;
    end;
  end;
end.
