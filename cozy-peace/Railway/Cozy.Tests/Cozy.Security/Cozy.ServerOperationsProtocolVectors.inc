{ Independent public V1 vectors. Legacy constants in the .dpr remain unchanged. }
type
  TOperationVector = record
    Stage: string;
    FunctionID: Word;
    ArgsVariant: Integer;
    ArgsSHA512, BindingSHA512, CanonicalSHA512: string;
  end;
  TOperationMutationVector = record
    BindingSHA512, CanonicalSHA512: string;
  end;
const
  OperationVectors: array[0..17] of TOperationVector = (
    (Stage: 'A'; FunctionID: 2; ArgsVariant: 0;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_c403d28a;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_b5a63650;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_793453d5),
    (Stage: 'A'; FunctionID: 65535; ArgsVariant: 0;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_c403d28a;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_5af92928;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_b107936a),
    (Stage: 'A'; FunctionID: 2; ArgsVariant: 1;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1701a560;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_2e18bf41;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_0495e863),
    (Stage: 'A'; FunctionID: 65535; ArgsVariant: 1;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1701a560;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_677a6dbe;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_c41a7592),
    (Stage: 'A'; FunctionID: 2; ArgsVariant: 2;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1c513308;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_2d9e1984;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_d4b47104),
    (Stage: 'A'; FunctionID: 65535; ArgsVariant: 2;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1c513308;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_4210230c;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_7724d04e),
    (Stage: 'B'; FunctionID: 2; ArgsVariant: 0;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_c403d28a;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_e88fb49a;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_26ad991a),
    (Stage: 'B'; FunctionID: 65535; ArgsVariant: 0;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_c403d28a;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_3925d5f6;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_e9dfe410),
    (Stage: 'B'; FunctionID: 2; ArgsVariant: 1;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1701a560;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_66608115;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_f8e30dbe),
    (Stage: 'B'; FunctionID: 65535; ArgsVariant: 1;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1701a560;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_5eb1acda;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_6221c10f),
    (Stage: 'B'; FunctionID: 2; ArgsVariant: 2;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1c513308;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_b62aae61;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_f70c849b),
    (Stage: 'B'; FunctionID: 65535; ArgsVariant: 2;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1c513308;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_5b425d96;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_6e8fa1fe),
    (Stage: 'O'; FunctionID: 2; ArgsVariant: 0;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_c403d28a;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_6c650b77;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_ef1519d1),
    (Stage: 'O'; FunctionID: 65535; ArgsVariant: 0;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_c403d28a;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_91df8975;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_0993b65d),
    (Stage: 'O'; FunctionID: 2; ArgsVariant: 1;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1701a560;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_d47becf5;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_13fed645),
    (Stage: 'O'; FunctionID: 65535; ArgsVariant: 1;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1701a560;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_b024dc73;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_228ef90c),
    (Stage: 'O'; FunctionID: 2; ArgsVariant: 2;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1c513308;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_c0a0d15c;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_3f2e5e00),
    (Stage: 'O'; FunctionID: 65535; ArgsVariant: 2;
      ArgsSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1c513308;
      BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_14155d78;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_658185f4));
  OperationMutations: array[0..13] of TOperationMutationVector = (
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_2e18bf41;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_0495e863),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_d47becf5;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_13fed645),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_b03c7979;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_d5818022),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_3fe8f9d9;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_35378a54),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_534692fb;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_635b6885),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_5b81c230;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_f0fa3a3d),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_5eb1acda;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_6221c10f),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_e88fb49a;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_26ad991a),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_66608115;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_426bf1e1),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_66608115;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_5613d352),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_66608115;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_92464686),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_66608115;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_0eacbf74),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_66608115;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_1fb8155a),
    (BindingSHA512: CozyText_ServerOperationsProtocolVectors_Digest_66608115;
      CanonicalSHA512: CozyText_ServerOperationsProtocolVectors_Digest_fff5acbf));
