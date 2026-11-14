function TestHighResolutionClock10P(out Failure: string; out Checks: Integer): Boolean;
var
  V: UInt64;
  procedure Check(Value: Boolean; const Why: string);
  begin
    Inc(Checks);
    if not Value then raise Exception.Create(Why);
  end;
begin
  Result := False;
  Failure := '';
  Checks := 0;

  try
    try
      Check(NHWTryQpcConvertUS(0, 0, 1, V) and (V = 0), 'zero is valid');
      Check(not NHWTryQpcConvertUS(0, 1, 0, V) and (V = 0), 'zero frequency invalid');
      Check(not NHWTryQpcConvertUS(-1, 1, 1, V) and (V = 0), 'negative timestamp invalid');
      Check(not NHWTryQpcConvertUS(2, 1, 1, V) and (V = 0), 'reverse timestamp invalid');
      Check(not NHWTryQpcConvertUS(Low(Int64), High(Int64), 1, V), 'signed overflow input rejected');
      Check(not NHWTryQpcConvertUS(0, High(Int64), 1, V) and (V = 0), 'microsecond overflow rejected');
      Check(NHWQpcElapsedUS(2, 1) = High(UInt64), 'legacy invalid sentinel distinct from zero');
      Check(NHWTryQpcConvertUS(Int64(0), Int64(10), Int64(3), V) and (V = UInt64(3333333)), 'exact integer case 1');
      Check(NHWTryQpcConvertUS(Int64(100), Int64(100), Int64(10000000), V) and (V = UInt64(0)), 'exact integer case 2');
      Check(NHWTryQpcConvertUS(Int64(0), Int64(9223372036854775806), Int64(9223372036854775807), V) and (V = UInt64(999999)), 'exact integer case 3');
      Check(NHWTryQpcConvertUS(Int64(0), Int64(9223372036854775807), Int64(9223372036854775807), V) and (V = UInt64(1000000)), 'exact integer case 4');
      Check(NHWTryQpcConvertUS(Int64(0), Int64(999999999999999999), Int64(1000000000000000000), V) and (V = UInt64(999999)), 'exact integer case 5');
      Check(NHWTryQpcConvertUS(Int64(0), Int64(9223372036854775807), Int64(1000000), V) and (V = UInt64(9223372036854775807)), 'exact integer case 6');
      Check(NHWTryQpcConvertUS(Int64(9223372036854775806), Int64(9223372036854775807), Int64(1), V) and (V = UInt64(1000000)), 'exact integer case 7');
      Check(NHWTryQpcConvertUS(Int64(281963908108624578), Int64(3242415836618661368), Int64(3780721401748804213), V) and (V = UInt64(783038)), 'exact integer case 8');
      Check(NHWTryQpcConvertUS(Int64(171746857199686631), Int64(4901959727693537193), Int64(1510535676702914408), V) and (V = UInt64(3131480)), 'exact integer case 9');
      Check(NHWTryQpcConvertUS(Int64(2680066602773244444), Int64(3797313018998466809), Int64(3210423320213677224), V) and (V = UInt64(348005)), 'exact integer case 10');
      Check(NHWTryQpcConvertUS(Int64(7080190588981282031), Int64(7178433307173402898), Int64(8378382521261196564), V) and (V = UInt64(11725)), 'exact integer case 11');
      Check(NHWTryQpcConvertUS(Int64(9107772081686528724), Int64(9126547264283472406), Int64(6582952002167366940), V) and (V = UInt64(2852)), 'exact integer case 12');
      Check(NHWTryQpcConvertUS(Int64(7807904507346231343), Int64(8576944562469165520), Int64(8287024197193689461), V) and (V = UInt64(92800)), 'exact integer case 13');
      Check(NHWTryQpcConvertUS(Int64(3285082413480839070), Int64(8362609976775365992), Int64(4776614066389711261), V) and (V = UInt64(1062997)), 'exact integer case 14');
      Check(NHWTryQpcConvertUS(Int64(7698250630675590919), Int64(7704494294734387857), Int64(2932194680581931690), V) and (V = UInt64(2129)), 'exact integer case 15');
      Check(NHWTryQpcConvertUS(Int64(6694973541412835351), Int64(7344222235279277584), Int64(2279977147987725362), V) and (V = UInt64(284761)), 'exact integer case 16');
      Check(NHWTryQpcConvertUS(Int64(5467812676264339531), Int64(9178752749084238962), Int64(1623460158121902282), V) and (V = UInt64(2285821)), 'exact integer case 17');
      Check(NHWTryQpcConvertUS(Int64(2335724184530930692), Int64(5909273162119249230), Int64(158347353994622237), V) and (V = UInt64(22567784)), 'exact integer case 18');
      Check(NHWTryQpcConvertUS(Int64(2813697676040119307), Int64(8647808131606257832), Int64(1369283936839791898), V) and (V = UInt64(4260701)), 'exact integer case 19');
      Check(NHWTryQpcConvertUS(Int64(6688786383079791236), Int64(8122164336286101474), Int64(4784343711229650035), V) and (V = UInt64(299597)), 'exact integer case 20');
      Check(NHWTryQpcConvertUS(Int64(2802542446670533976), Int64(7893519457427456381), Int64(2531149197173362936), V) and (V = UInt64(2011330)), 'exact integer case 21');
      Check(NHWTryQpcConvertUS(Int64(2542068392357806985), Int64(3304232255200497253), Int64(2235486597439033542), V) and (V = UInt64(340938)), 'exact integer case 22');
      Check(NHWTryQpcConvertUS(Int64(4947926964312906772), Int64(7227383624533984899), Int64(1755912944567965183), V) and (V = UInt64(1298160)), 'exact integer case 23');
      Check(NHWTryQpcConvertUS(Int64(5474815150547550542), Int64(7135152563464088763), Int64(8192404316364682530), V) and (V = UInt64(202667)), 'exact integer case 24');
      Check(NHWTryQpcConvertUS(Int64(467628584822554543), Int64(1220031922637512718), Int64(7395021498495178089), V) and (V = UInt64(101744)), 'exact integer case 25');
      Check(NHWTryQpcConvertUS(Int64(7492389126995209042), Int64(8375923577681305677), Int64(3671504767182968698), V) and (V = UInt64(240646)), 'exact integer case 26');
      Check(NHWTryQpcConvertUS(Int64(3875520199172337999), Int64(9196636569128525596), Int64(1569630763054447698), V) and (V = UInt64(3390043)), 'exact integer case 27');
      Check(NHWTryQpcConvertUS(Int64(6050140046030360904), Int64(8017011163599083132), Int64(6699579061692672625), V) and (V = UInt64(293581)), 'exact integer case 28');
      Check(NHWTryQpcConvertUS(Int64(5458803781417188393), Int64(9000695133851827547), Int64(285437576369708455), V) and (V = UInt64(12408637)), 'exact integer case 29');
      Check(NHWTryQpcConvertUS(Int64(6735369607365039424), Int64(7791135796614225357), Int64(2613195018851228623), V) and (V = UInt64(404013)), 'exact integer case 30');
      Check(NHWTryQpcConvertUS(Int64(8247222220019377134), Int64(8512345453508386158), Int64(1438946279679689149), V) and (V = UInt64(184248)), 'exact integer case 31');
      Check(NHWTryQpcConvertUS(Int64(5011753471740842408), Int64(5463688409051857519), Int64(3405256817968207094), V) and (V = UInt64(132716)), 'exact integer case 32');
      Check(NHWTryQpcConvertUS(Int64(7515504803309918035), Int64(7938358048590779010), Int64(2312143925551933783), V) and (V = UInt64(182883)), 'exact integer case 33');
      Check(NHWTryQpcConvertUS(Int64(7000325245396807658), Int64(7183825415828338810), Int64(7712113555216100965), V) and (V = UInt64(23793)), 'exact integer case 34');
      Check(NHWTryQpcConvertUS(Int64(4234481128734488679), Int64(7816237968498847009), Int64(3329893192547231271), V) and (V = UInt64(1075637)), 'exact integer case 35');
      Check(NHWTryQpcConvertUS(Int64(2461468086274614162), Int64(3917072217539862266), Int64(1182218582153622404), V) and (V = UInt64(1231247)), 'exact integer case 36');
      Check(NHWTryQpcConvertUS(Int64(7305107555410525890), Int64(7680291872983081373), Int64(7815976265575304053), V) and (V = UInt64(48002)), 'exact integer case 37');

      Result := True;
    except
      on E: Exception do Failure := E.Message;
    end;
  finally
    // No owned resources.
  end;
end;
