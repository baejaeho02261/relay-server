{ Generated packet shapes only; these dummy keys never authorize execution. }
const
  ProtocolSchemaCases: array[0..39] of string = (
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"begin","requestId":"rrrrrrrr","launcherId":"AAAAAAAAAAAAAAAAAAAAAAAA","launcherSha512":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","launcherCrc64":"AAAAAAAAAAAAAAAA","aCodeSha512":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","aCodeCrc64":"AAAAAAAAAAAAAAAA","publicKey":"{}","deviceId":"AAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"keylessPolicy","version":1,"launcherId":"AAAAAAAAAAAAAAAAAAAAAAAA","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAA"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"keylessChallenge","version":1,"requestId":"rrrrrrrr","launcherId":"AAAAAAAAAAAAAAAAAAAAAAAA","launcherSha512":"aaaaaaaa' +
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","launcherCrc64":"AAAAAAAAAAAAAAAA","aCodeSha512":"aaaaaaaa' +
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","aCodeCrc64":"AAAAAAAAAAAAAAAA","publicKey":"{}","deviceId' +
    '":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","handoffVersion":3,"persistentPu' +
    'blicKey":"{}","persistentKeyId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","keyProvider":"SOFTWARE","epoch":0,"revision":0}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"keylessProve","version":1,"challengeId":"{}","appSignature":"{}","persistentSignature":"{}"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"keylessStatus","version":1,"challengeId":"{}","appSignature":"{}","persistentSignature":"{}"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"beginKeyless","version":1,"challengeId":"{}","appSignature":"{}","persistentSignature":"{}"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"chunk","flowId":"AAAAAAAAAAAAAAAAAAAAAAAA","downloadTicket":"{}","offset":0}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"finish","flowId":"AAAAAAAAAAAAAAAAAAAAAAAA","downloadTicket":"{}","sha512":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","crc64":"AAAAAAAAAAAAAAAA","aCodeSha512":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","aCodeCrc64":"AAAAAAAAAAAAAAAA","signature":"{}"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"claim","flowId":"AAAAAAAAAAAAAAAAAAAAAAAA","handoffToken":"{}","signature":"{}","binarySha512":"aaaaaaaaaaaaaaaaaaaaaaa' +
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","crc64":"AAAAAAAAAAAAAAAA","bCodeSha512":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bCodeCrc64":"AAAAAAAAAAAAAAAA"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"status","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"close","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"abort","flowId":"AAAAAAAAAAAAAAAAAAAAAAAA","downloadTicket":"{}"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"overlayChunk","overlayId":"AAAAAAAAAAAAAAAAAAAAAAAA","overlayTicket":"{}","offset":0}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"overlayFinish","overlayId":"AAAAAAAAAAAAAAAAAAAAAAAA","overlayTicket":"{}","signature":"{}"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"overlayClaim","overlayId":"AAAAAAAAAAAAAAAAAAAAAAAA","overlayTicket":"{}","signature":"{}","binarySha512":"aaaaaaaaaaaa' +
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","crc64":"AAAAAAAAAAAAAAAA","oCodeSha512":"aaaaaaaaaaaaaaaaaaaa' +
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","oCodeCrc64":"AAAAAAAAAAAAAAAA"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"overlayVerify","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","binarySha512":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",' +
    '"binaryCrc64":"AAAAAAAAAAAAAAAA","codeSha512":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","co' +
    'deCrc64":"AAAAAAAAAAAAAAAA"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"overlayProgress","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","sequence":1,"phase":"CLAIMED","elapsedMs":' +
    '0,"signature":"{}"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"overlayCommit","handoffVersion":1,"sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","overlayId":"AAAAAAAAAAAAA' +
    'AAAAAAAAAAA","signature":"{}"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"overlayClose","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"overlayAbort","handoffVersion":3,"parentSessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","parentSessionToken":"{}","signature":"{}' +
    '","overlayId":"AAAAAAAAAAAAAAAAAAAAAAAA"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"lifecycleChallenge","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","targetRole":"A","requestId"' +
    ':"rrrrrrrr"}}',
    '{"operation":"bootstrap","tlsPinVersion":1,"body":{"action":"lifecycleReport","permitId":"{}","requestId":"rrrrrrrr","eventsJson":"{}","signature":"{}"}}',
    '{"operation":"device","tlsPinVersion":1,"body":{"action":"policy","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}',
    '{"operation":"device","tlsPinVersion":1,"body":{"action":"challenge","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requestId":"rrrrrrrr","publicKey":"{}","keyProvider":"SOFTWARE"}}',
    '{"operation":"device","tlsPinVersion":1,"body":{"action":"complete","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","challengeId":"{}","appSignature":"{}","signature":"{}"}}',
    '{"operation":"device","tlsPinVersion":1,"body":{"action":"tpmActivate","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","challengeId":"{}","secret":"{}","signature":"{}","appSignature":"{}"}}',
    '{"operation":"security","tlsPinVersion":1,"body":{"action":"challenge","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","intent":"finish","binding":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
    'aaaaaaaaaaaaaaaaaa"}}',
    '{"operation":"security","tlsPinVersion":1,"body":{"action":"submit","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","intent":"finish","binding":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
    'aaaaaaaaaaaaaaa","challengeId":"{}","payload":"{}","signature":"{}"}}',
    '{"operation":"report","tlsPinVersion":1,"body":{"action":"challenge","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}"}}',
    '{"operation":"report","tlsPinVersion":1,"body":{"action":"submit","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","reportId":"{}","payload":"{}","signature":"{}"}}',
    '{"operation":"policy","tlsPinVersion":1,"body":{"action":"challenge","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requestId":"rrrrrrrr","policyId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","functionId":2,"args":[]}}',
    '{"operation":"policy","tlsPinVersion":1,"body":{"action":"invoke","stage":"A","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA","sessionToken":"{}","machineId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requestId":"rrrrrrrr","policyId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","functionId":2,"args":[],"challengeId":"{}"' +
    ',"signature":"{}"}}',
    '{"operation":"challenge","tlsPinVersion":1,"body":{"action":"redeem","requestId":"rrrrrrrr","deviceId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","publicKey' +
    '":"{}","payloadHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}',
    '{"operation":"execute","tlsPinVersion":1,"body":{"action":"redeem","requestId":"rrrrrrrr","deviceId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","publicKey":' +
    '"{}","challengeId":"{}","signature":"{}","payloadJSON":"{}"}}',
    '{"operation":"challenge","tlsPinVersion":1,"body":{"action":"verify","requestId":"rrrrrrrr","deviceId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","publicKey' +
    '":"{}","payloadHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}',
    '{"operation":"execute","tlsPinVersion":1,"body":{"action":"verify","requestId":"rrrrrrrr","deviceId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","publicKey":' +
    '"{}","challengeId":"{}","signature":"{}","payloadJSON":"{}"}}',
    '{"operation":"challenge","tlsPinVersion":1,"body":{"action":"release","requestId":"rrrrrrrr","deviceId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","publicKe' +
    'y":"{}","payloadHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}',
    '{"operation":"execute","tlsPinVersion":1,"body":{"action":"release","requestId":"rrrrrrrr","deviceId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","publicKey"' +
    ':"{}","challengeId":"{}","signature":"{}","payloadJSON":"{}"}}',
    '{"operation":"challenge","tlsPinVersion":1,"body":{"action":"overlay","requestId":"rrrrrrrr","deviceId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","publicKe' +
    'y":"{}","payloadHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}',
    '{"operation":"execute","tlsPinVersion":1,"body":{"action":"overlay","requestId":"rrrrrrrr","deviceId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","publicKey"' +
    ':"{}","challengeId":"{}","signature":"{}","payloadJSON":"{}"}}'
  );
