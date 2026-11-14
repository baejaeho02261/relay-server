{ Public known answers from tests/fixtures/integrity/peace.crc32c-collision-vectors.json.
  Independently checked with bit-at-a-time CRC32C and SHA-512. Never authorization. }
const
  CrcCollisionVectorName = CozyText_CrcCollisionVectors_COZY_CRC32C_COLLISION_V1_a1624cf8;
  CrcCollisionLeft: array[0..7] of Byte = ($48,$70,$59,$D7,$B6,$05,$E9,$FF);
  CrcCollisionRight: array[0..7] of Byte = ($48,$CC,$3C,$E6,$AB,$78,$9B,$5C);
  CrcCollisionSizes: array[0..1] of Integer = (8,4096);
  CrcCollisionCrc32c: array[0..1] of string = (
    CozyText_CrcCollisionVectors_FB92544B_d43e0d92,
    CozyText_CrcCollisionVectors_CA805F72_05c9b5ce);
  CrcCollisionLeftSha512: array[0..1] of string = (
    CozyText_CrcCollisionVectors_Digest_f5a17bcc,
    CozyText_CrcCollisionVectors_Digest_ea804d95);
  CrcCollisionRightSha512: array[0..1] of string = (
    CozyText_CrcCollisionVectors_Digest_3180ed20,
    CozyText_CrcCollisionVectors_Digest_4790feb0);
  CrcCollisionLeftCodeSha512: array[0..1] of string = (
    CozyText_CrcCollisionVectors_Digest_58349162,
    CozyText_CrcCollisionVectors_Digest_005ca559);
  CrcCollisionRightCodeSha512: array[0..1] of string = (
    CozyText_CrcCollisionVectors_Digest_15eecbbc,
    CozyText_CrcCollisionVectors_Digest_c8ffb13a);
  CrcCollisionLeftPageManifestSha512: array[0..1] of string = (
    CozyText_CrcCollisionVectors_Digest_4c7a1b8b,
    CozyText_CrcCollisionVectors_Digest_1a15ca86);
  CrcCollisionRightPageManifestSha512: array[0..1] of string = (
    CozyText_CrcCollisionVectors_Digest_0b3bd562,
    CozyText_CrcCollisionVectors_Digest_0fd5197b);
