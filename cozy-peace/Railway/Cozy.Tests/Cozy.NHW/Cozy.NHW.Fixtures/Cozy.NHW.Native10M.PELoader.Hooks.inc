var PE10MMode: Integer; PE10MImage: TPEImageSnapshot;
function CapturePEImage(out Snapshot: TPEImageSnapshot): Boolean;
begin
  if PE10MMode = 2 then raise Exception.Create('injected PE collection failure');
  Snapshot := PE10MImage; Result := PE10MMode = 0;
end;
