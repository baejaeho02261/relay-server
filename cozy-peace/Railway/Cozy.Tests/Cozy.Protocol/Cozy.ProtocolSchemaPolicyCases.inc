{ Public fixtures mirrored in Relay Server/tests/fixtures/protocol/peace.native-policy-contract-vectors.json.
  Evaluates the actual generated Pascal request parser; no authentication claim. }
type
  TPolicyWireCase = record
    Name, WireText: string;
    Accept: Boolean;
    MaximumBytes: Integer;
  end;
const
  PolicyWireCases: array[0..117] of TPolicyWireCase = (
    (Name: 'A-challenge-args0-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'A-challenge-args0-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':65535,"args":[]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'A-challenge-args3-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'A-challenge-args3-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':65535,"args":[-2147483648,0,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'A-challenge-args8-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,-1,0,1,2,3,7,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'A-challenge-args8-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':65535,"args":[-2147483648,-1,0,1,2,3,7,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'A-invoke-args0-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'A-invoke-args0-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":65' +
      '535,"args":[],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'A-invoke-args3-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'A-invoke-args3-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":65' +
      '535,"args":[-2147483648,0,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'A-invoke-args8-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,-1,0,1,2,3,7,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'A-invoke-args8-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":65' +
      '535,"args":[-2147483648,-1,0,1,2,3,7,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-challenge-args0-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-challenge-args0-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':65535,"args":[]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-challenge-args3-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-challenge-args3-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':65535,"args":[-2147483648,0,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-challenge-args8-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,-1,0,1,2,3,7,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-challenge-args8-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':65535,"args":[-2147483648,-1,0,1,2,3,7,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-invoke-args0-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-invoke-args0-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":65' +
      '535,"args":[],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-invoke-args3-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-invoke-args3-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":65' +
      '535,"args":[-2147483648,0,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-invoke-args8-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,-1,0,1,2,3,7,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'B-invoke-args8-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":65' +
      '535,"args":[-2147483648,-1,0,1,2,3,7,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-challenge-args0-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-challenge-args0-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':65535,"args":[]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-challenge-args3-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-challenge-args3-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':65535,"args":[-2147483648,0,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-challenge-args8-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,-1,0,1,2,3,7,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-challenge-args8-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':65535,"args":[-2147483648,-1,0,1,2,3,7,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-invoke-args0-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-invoke-args0-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":65' +
      '535,"args":[],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-invoke-args3-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-invoke-args3-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":65' +
      '535,"args":[-2147483648,0,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-invoke-args8-function2'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,-1,0,1,2,3,7,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'O-invoke-args8-function65535'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"O","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":65' +
      '535,"args":[-2147483648,-1,0,1,2,3,7,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'reject-functionId-36'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':0,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-functionId-37'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':1,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-functionId-38'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':65536,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-functionId-39'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2.5,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-functionId-40'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':"2","args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-functionId-41'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':null,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-functionId-42'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':true,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-args-43'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[0,0,0,0,0,0,0,0,0]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-args-44'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[2147483648]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-args-45'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483649]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-args-46'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[0.5]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-args-47'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":["1"]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-args-48'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[true]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-args-49'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[null]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-args-50'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":{}}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-args-51'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":null}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-stage-52'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"b","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-stage-53'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"AB","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionT' +
      'oken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId' +
      '":"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId' +
      '":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-stage-54'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTok' +
      'en":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":' +
      '"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":' +
      '2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-stage-55'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B\n","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","session' +
      'Token":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestI' +
      'd":"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionI' +
      'd":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-stage-56'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":null,"sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionT' +
      'oken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId' +
      '":"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId' +
      '":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-sessionId-57'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"aaaaaaaaaaaaaaaaaaaaaaaa","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-sessionId-58'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAA","sessionTok' +
      'en":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":' +
      '"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":' +
      '2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-sessionId-59'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA\n","session' +
      'Token":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestI' +
      'd":"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionI' +
      'd":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-machineId-60'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-machineId-61'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId' +
      '":"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId' +
      '":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-machineId-62'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r","requestI' +
      'd":"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionI' +
      'd":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-policyId-63'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-policyId-64'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":' +
      '2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-policyId-65'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n","functionI' +
      'd":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-requestId-66'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"aaaaaaa","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,2147' +
      '483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-requestId-67'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policyId":"ccccccccccccccccccccccccccccccccc' +
      'ccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-requestId-68'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"valid-id\n","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,2' +
      '147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-requestId-69'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"valid\u0000id","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,' +
      '0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-requestId-70'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"valid id","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,214' +
      '7483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-sessionToken-71'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111111-2222-3333-4444-555555' +
      '555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,2147483' +
      '647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-sessionToken-72'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss' +
      'ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss' +
      'ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss' +
      'sssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"' +
      ',"machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111111-2222-3333-4444-555555555555"' +
      ',"policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-sessionToken-73'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":7,"machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111111-2222-3333-4444-5555555' +
      '55555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,21474836' +
      '47]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-action-74'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"unknown","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToke' +
      'n":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"' +
      '11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2' +
      ',"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'reject-action-75'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":null,"stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"s' +
      'sssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111' +
      '111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"arg' +
      's":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'missing-action'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"sssssssssssssss' +
      'sssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111111-2222-3333-' +
      '4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-214748364' +
      '8,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'missing-stage'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"ssssss' +
      'ssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111111-2' +
      '222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-' +
      '2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'missing-sessionId'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionToken":"ssssssssssssssssssssssssssssssss"' +
      ',"machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111111-2222-3333-4444-555555555555"' +
      ',"policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'missing-sessionToken'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","machineId' +
      '":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111111-2222-3333-4444-555555555555","policyId"' +
      ':"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'missing-machineId'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","requestId":"11111111-2222-3333-4444-555555555555","policyId":"ccccccccccccccccccccccccccc' +
      'ccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'missing-requestId'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","policyId":' +
      '"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'missing-policyId'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'missing-functionId'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","args":[-214' +
      '7483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'missing-args'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'unknown-body-field'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647],"unexpected":true}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'invoke-reject-challengeId-86'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"challengeId":"","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAA=="}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'invoke-reject-challengeId-87'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"challengeId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'invoke-reject-challengeId-88'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"challengeId":2,"signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAA=="}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'invoke-reject-signature-89'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":""}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'invoke-reject-signature-90'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":"AAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'invoke-reject-signature-91'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"challengeId":"111111111111111111111111111111111111111111111111","signature":3}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'invoke-missing-challengeId'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' +
      '="}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'invoke-missing-signature'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"challengeId":"111111111111111111111111111111111111111111111111"}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'version-reject-94'; WireText: '{"operation":"policy","tlsPinVersion":0,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'version-reject-95'; WireText: '{"operation":"policy","tlsPinVersion":2,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'version-reject-96'; WireText: '{"operation":"policy","tlsPinVersion":"1","body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","session' +
      'Token":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestI' +
      'd":"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionI' +
      'd":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'version-reject-97'; WireText: '{"operation":"policy","tlsPinVersion":null,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessio' +
      'nToken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","request' +
      'Id":"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","function' +
      'Id":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'version-reject-98'; WireText: '{"operation":"policy","tlsPinVersion":true,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessio' +
      'nToken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","request' +
      'Id":"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","function' +
      'Id":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'unknown-operation'; WireText: '{"operation":"unknown","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionT' +
      'oken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId' +
      '":"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId' +
      '":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'unknown-envelope-field'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]},"unexpected":true}';
      Accept: False; MaximumBytes: -1),
    (Name: 'body-null'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":null}';
      Accept: False; MaximumBytes: -1),
    (Name: 'body-array'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":[]}';
      Accept: False; MaximumBytes: -1),
    (Name: 'missing-operation'; WireText: '{"tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"sssssssssssssss' +
      'sssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111111-2222-3333-' +
      '4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-214748364' +
      '8,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'missing-body'; WireText: '{"operation":"policy","tlsPinVersion":1}';
      Accept: False; MaximumBytes: -1),
    (Name: 'legacy-pin-version-omitted'; WireText: '{"operation":"policy","body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"ssssssssssss' +
      'ssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111111-2222-33' +
      '33-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-214748' +
      '3648,0,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'request-id-boundary-106'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"aaaaaaaa","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,214' +
      '7483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'request-id-boundary-107'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-","policyId":"cccccccccccccccccccccccccccccccccc' +
      'cccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'shape-only-token-boundary-108'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"s","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111111-2222-3333-4444-55555' +
      '5555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,214748' +
      '3647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'shape-only-token-boundary-109'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss' +
      'ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss' +
      'ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss' +
      'ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss",' +
      '"machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"11111111-2222-3333-4444-555555555555",' +
      '"policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'shape-only-invoke-minimum'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken' +
      '":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId":"1' +
      '1111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId":2,' +
      '"args":[-2147483648,0,2147483647],"challengeId":"x","signature":"x"}}';
      Accept: True; MaximumBytes: -1),
    (Name: 'byte-budget-exact'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: True; MaximumBytes: 428),
    (Name: 'byte-budget-one-short'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: 427),
    (Name: 'byte-budget-zero'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: 0),
    (Name: 'duplicate-body-field'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'duplicate-envelope-field'; WireText: '{"operation":"policy","operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAA' +
      'AAAAAAAAA","sessionToken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' +
      'BBBBBBBB","requestId":"11111111-2222-3333-4444-555555555555","policyId":"ccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' +
      'ccccccc","functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1),
    (Name: 'trailing-json'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","functionId"' +
      ':2,"args":[-2147483648,0,2147483647]}}{}';
      Accept: False; MaximumBytes: -1),
    (Name: 'prototype-field'; WireText: '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"B","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionTo' +
      'ken":"ssssssssssssssssssssssssssssssss","machineId":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","requestId"' +
      ':"11111111-2222-3333-4444-555555555555","policyId":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","__proto__":' +
      '{},"functionId":2,"args":[-2147483648,0,2147483647]}}';
      Accept: False; MaximumBytes: -1));
