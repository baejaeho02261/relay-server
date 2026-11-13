'use strict';
// Fixed wire identities from all 204 NHW v109 FP1 enumerators and audited Cozy outcomes.
// Metadata describes provenance/taxonomy, never grants authority or proves an attack.
// Semantic families are NOT independent acquisition roots. Unknown/unsupported/timeout
// observations must never count as confirmed attacks. No raw PID/path/user values.
function Freeze(row) { for (const value of Object.values(row)) if (Array.isArray(value)) { for(const item of value)if(item&&typeof item==='object'){if(Array.isArray(item.lines))Object.freeze(item.lines);Object.freeze(item);}Object.freeze(value); } return Object.freeze(row); }
// FP1 has 204 state identities, 197 standalone output states and 194 printed
// names. Internal evidence is never promoted to a standalone detection merely
// because it arrived in an authenticated batch. Warnings retain their original
// spelling without pretending that loss of coverage proves an attack.
const INTERNAL_EVIDENCE = new Set(['dkNamespace','dkDeviceMap','dkAllocation','dkCommit','dkMemoryRelease','dkAllocationBurst','dkReadGap']);
const WARING_OUTPUT = new Set(['dkETWLoss','dkCoverageGap','dkObservationUncertain','dkSensorPressure']);
function NHWMetadata(row) {
 const internal=INTERNAL_EVIDENCE.has(row.id),warning=row.signalClass==='UNKNOWN';
 const displayName=internal?row.label.replace(/ Detect$/,' Evidence'):WARING_OUTPUT.has(row.id)?'Waring Detect':row.label;
 if(row.id==='dkObservationUncertain')row.sourceUnits.push('Cozy.NHW.Handles','Cozy.NHW.Guard');
 return Freeze({...row,label:displayName,displayName,origin:'NHW',conditionLabel:WARING_OUTPUT.has(row.id)?row.label:'',standaloneOutput:!internal,
  observationClass:internal?'INTERNAL_EVIDENCE':warning?'COVERAGE_WARNING':'DETECTION',
  sessionStopPolicy:internal?'OBSERVE_ONLY':warning?'RECOVER_AND_REVALIDATE':'STOP_ON_NATIVE_DETECTED_OUTPUT',
  contextPolicy:require('./peace.security-context-policy').PolicyClass({...row,standaloneOutput:!internal})});
}
const COZY_NAMES={
 IMAGE_DIGEST_MISMATCH:'Image Digest Detect',CODE_HASH_MISMATCH:'Code Hash Detect',FILE_HASH_MISMATCH:'File Hash Detect',
 CODE_EXTENDED_HASH_MISMATCH:'Code Extended Hash Detect',FILE_EXTENDED_HASH_MISMATCH:'File Extended Hash Detect',
 KNOWN_MODULE_CODE_MISMATCH:'Known Module Code Detect',REQUIRED_MODULE_CODE_MISMATCH:'Required Module Code Detect',
 POINTER_GRAPH_MISMATCH:'API Pointer Graph Detect',RUNTIME_GRAPH_PROFILE_MISMATCH:'Runtime Object Graph Detect',
 CRC_ROLE_MISMATCH:'CRC Detect',FILE_DIGEST_MISMATCH:'File Digest Detect',CODE_DIGEST_MISMATCH:'Code Digest Detect',
 BOOTSTRAP_CODE_MISMATCH:'Bootstrap Code Detect',BOOTSTRAP_HASH_MISMATCH:'Bootstrap Hash Detect'
};
function CozyMetadata(row) {
 if(row.id==='SECURITY_CFG_BUILD_REQUIRED')row.sourceUnits.push('peace.desktop-mitigation-profiles');
 const name=COZY_NAMES[row.id]||row.id.split('_').map(word=>['API','CRC','TPM','NHW','CFG'].includes(word)?word:word[0]+word.slice(1).toLowerCase()).join(' ')+' Detect';
 return Freeze({...row,displayName:name,origin:'COZY',conditionLabel:'',observationClass:row.signalClass==='UNKNOWN'?'UNAVAILABLE_OR_INCOMPLETE':row.signalClass==='MISMATCH'?'INTEGRITY_MISMATCH':'POLICY_REJECTION',sessionStopPolicy:'SERVER_DECISION'});
}
const PEER_FINDINGS=['SECURITY_PEER_IMAGE_MISMATCH','SECURITY_PEER_IDENTITY_CHANGED','SECURITY_PEER_ENROLLMENT_REPLAY','SECURITY_HANDOFF_GRANT_REUSED'].map(id=>({id,label:id.replaceAll('_',' '),category:'FIRST_PARTY_BINDING',sourceUnits:['peace.nhw-peer-context'],responsePaths:['Trust','Driver','Integrity'],evidenceFamilies:['ARTIFACT_IDENTITY','SESSION_BINDING'],signalClass:'POLICY_REJECTION',sourceReferences:[{path:'services/security/peace.nhw-peer-context.js',lines:[]}]}));
const MITIGATION_FINDINGS=['SECURITY_MITIGATION_PROFILE_UNEXPECTED','SECURITY_MITIGATION_PROFILE_MISMATCH','SECURITY_STRICT_HANDLES_UNAVAILABLE','SECURITY_IMAGE_POLICY_UNAVAILABLE','SECURITY_CFG_UNAVAILABLE','SECURITY_DYNAMIC_POLICY_UNAVAILABLE'].map(id=>({
 id,label:id.replaceAll('_',' '),category:'MITIGATION_POLICY',sourceUnits:['peace.desktop-mitigation-profiles','peace.desktop-security-authority'],responsePaths:['Integrity'],evidenceFamilies:['MITIGATION_POLICY'],signalClass:id.endsWith('_UNAVAILABLE')?'UNKNOWN':'POLICY_REJECTION',sourceReferences:[{path:'services/security/peace.desktop-mitigation-profiles.js',lines:[82]}]
}));
const MITIGATION_RUNTIME_FINDINGS=['SECURITY_MITIGATION_PROFILE_RETIRED','SECURITY_MITIGATION_EVIDENCE_UNTRUSTED','SECURITY_MITIGATION_SIGNATURE_INVALID','SECURITY_MITIGATION_PROFILE_BINDING_REQUIRED','SECURITY_MITIGATION_ENVIRONMENT_REQUIRED','SECURITY_MITIGATION_ENVIRONMENT_UNVERIFIED','SECURITY_MITIGATION_PROFILE_AMBIGUOUS','SECURITY_MITIGATION_PROFILE_INVALID'].map(id=>({
 id,label:id.replaceAll('_',' '),category:'MITIGATION_POLICY',sourceUnits:['peace.desktop-mitigation-profiles','peace.desktop-security-authority'],responsePaths:['Integrity'],evidenceFamilies:['MITIGATION_POLICY'],signalClass:id==='SECURITY_MITIGATION_PROFILE_INVALID'?'UNKNOWN':'POLICY_REJECTION',sourceReferences:[{path:'services/security/peace.desktop-mitigation-profiles.js',lines:[]}]
}));
const NHW = Object.freeze([
 {
  "id": "dkProcess",
  "ordinal": 0,
  "label": "Process Detect",
  "category": "PROCESS_HANDLE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus"
  ],
  "producerUnits": [
   "Cozy.NHW.Engine"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_HANDLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     3357,
     3368,
     3589
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     67
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     94
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     64
    ]
   }
  ]
 },
 {
  "id": "dkThread",
  "ordinal": 1,
  "label": "Thread Detect",
  "category": "PROCESS_HANDLE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus"
  ],
  "producerUnits": [
   "Cozy.NHW.Engine"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_HANDLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     3356,
     3367,
     3589
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     67
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     94
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     64
    ]
   }
  ]
 },
 {
  "id": "dkOwnership",
  "ordinal": 2,
  "label": "Ownership Detect",
  "category": "PROCESS_HANDLE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Engine"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_HANDLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     3536,
     3589
    ]
   }
  ]
 },
 {
  "id": "dkEscalation",
  "ordinal": 3,
  "label": "Escalation Detect",
  "category": "PROCESS_HANDLE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus"
  ],
  "producerUnits": [
   "Cozy.NHW.Engine"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_HANDLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     3362,
     3590
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     67
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     95
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     64
    ]
   }
  ]
 },
 {
  "id": "dkReappearance",
  "ordinal": 4,
  "label": "Reappearance Detect",
  "category": "PROCESS_HANDLE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Engine"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_HANDLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     3360,
     3590
    ]
   }
  ]
 },
 {
  "id": "dkThreadBurst",
  "ordinal": 5,
  "label": "Thread Burst Detect",
  "category": "PROCESS_HANDLE",
  "sourceUnits": [
   "Cozy.NHW.Behavior",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Behavior"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_HANDLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Behavior.pas",
    "lines": [
     306
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     3590
    ]
   }
  ]
 },
 {
  "id": "dkHandleChurn",
  "ordinal": 6,
  "label": "Handle Churn Detect",
  "category": "PROCESS_HANDLE",
  "sourceUnits": [
   "Cozy.NHW.Behavior",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Behavior"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_HANDLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Behavior.pas",
    "lines": [
     325
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     3590
    ]
   }
  ]
 },
 {
  "id": "dkCrossAccess",
  "ordinal": 7,
  "label": "Cross Access Detect",
  "category": "PROCESS_HANDLE",
  "sourceUnits": [
   "Cozy.NHW.Behavior",
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Behavior"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_HANDLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Behavior.pas",
    "lines": [
     376
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     3591
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     68
    ]
   }
  ]
 },
 {
  "id": "dkAccessBurst",
  "ordinal": 8,
  "label": "Access Burst Detect",
  "category": "PROCESS_HANDLE",
  "sourceUnits": [
   "Cozy.NHW.Behavior",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Behavior"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_HANDLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Behavior.pas",
    "lines": [
     364
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     3591
    ]
   }
  ]
 },
 {
  "id": "dkThreadCreation",
  "ordinal": 9,
  "label": "Thread Creation Detect",
  "category": "PROCESS_LIFECYCLE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Lifecycle",
   "Cozy.NHW.SignalCorrelation"
  ],
  "producerUnits": [
   "Cozy.NHW.Lifecycle"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_LIFECYCLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Lifecycle.pas",
    "lines": [
     205
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     115
    ]
   }
  ]
 },
 {
  "id": "dkThreadExit",
  "ordinal": 10,
  "label": "Thread Exit Detect",
  "category": "PROCESS_LIFECYCLE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Lifecycle"
  ],
  "producerUnits": [
   "Cozy.NHW.Lifecycle"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_LIFECYCLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Lifecycle.pas",
    "lines": [
     206
    ]
   }
  ]
 },
 {
  "id": "dkThreadState",
  "ordinal": 11,
  "label": "Thread State Detect",
  "category": "PROCESS_LIFECYCLE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Lifecycle"
  ],
  "producerUnits": [
   "Cozy.NHW.Lifecycle"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_LIFECYCLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Lifecycle.pas",
    "lines": [
     207
    ]
   }
  ]
 },
 {
  "id": "dkHandleInherit",
  "ordinal": 12,
  "label": "Handle Inherit Detect",
  "category": "PROCESS_LIFECYCLE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Lifecycle"
  ],
  "producerUnits": [
   "Cozy.NHW.Lifecycle"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_LIFECYCLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Lifecycle.pas",
    "lines": [
     267
    ]
   }
  ]
 },
 {
  "id": "dkLifecycle",
  "ordinal": 13,
  "label": "Lifecycle Detect",
  "category": "PROCESS_LIFECYCLE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Lifecycle"
  ],
  "producerUnits": [
   "Cozy.NHW.Lifecycle"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PROCESS_LIFECYCLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Lifecycle.pas",
    "lines": [
     210
    ]
   }
  ]
 },
 {
  "id": "dkTokenObject",
  "ordinal": 14,
  "label": "Token Detect",
  "category": "TOKEN_SECURITY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Security"
  ],
  "producerUnits": [
   "Cozy.NHW.Security"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "TOKEN_SECURITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Security.pas",
    "lines": [
     243,
     249
    ]
   }
  ]
 },
 {
  "id": "dkTokenRights",
  "ordinal": 15,
  "label": "Token Rights Detect",
  "category": "TOKEN_SECURITY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Security"
  ],
  "producerUnits": [
   "Cozy.NHW.Security"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "TOKEN_SECURITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Security.pas",
    "lines": [
     245,
     251,
     256
    ]
   }
  ]
 },
 {
  "id": "dkTokenChange",
  "ordinal": 16,
  "label": "Token Change Detect",
  "category": "TOKEN_SECURITY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Security"
  ],
  "producerUnits": [
   "Cozy.NHW.Security"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "TOKEN_SECURITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Security.pas",
    "lines": [
     332
    ]
   }
  ]
 },
 {
  "id": "dkDacl",
  "ordinal": 17,
  "label": "DACL Detect",
  "category": "TOKEN_SECURITY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Security"
  ],
  "producerUnits": [
   "Cozy.NHW.Security"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "TOKEN_SECURITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Security.pas",
    "lines": [
     163
    ]
   }
  ]
 },
 {
  "id": "dkThreadToken",
  "ordinal": 18,
  "label": "Thread Token Detect",
  "category": "TOKEN_SECURITY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Security"
  ],
  "producerUnits": [
   "Cozy.NHW.Security"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "TOKEN_SECURITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Security.pas",
    "lines": [
     415
    ]
   }
  ]
 },
 {
  "id": "dkEvent",
  "ordinal": 19,
  "label": "Event Detect",
  "category": "IPC_JOB",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IPC",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.IPC"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "IPC_JOB"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IPC.pas",
    "lines": [
     67
    ]
   }
  ]
 },
 {
  "id": "dkMutex",
  "ordinal": 20,
  "label": "Mutex Detect",
  "category": "IPC_JOB",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IPC",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.IPC"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "IPC_JOB"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IPC.pas",
    "lines": [
     68
    ]
   }
  ]
 },
 {
  "id": "dkSemaphore",
  "ordinal": 21,
  "label": "Semaphore Detect",
  "category": "IPC_JOB",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IPC",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.IPC"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "IPC_JOB"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IPC.pas",
    "lines": [
     69
    ]
   }
  ]
 },
 {
  "id": "dkSection",
  "ordinal": 22,
  "label": "Section Detect",
  "category": "IPC_JOB",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IPC",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.IPC"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "IPC_JOB"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IPC.pas",
    "lines": [
     70
    ]
   }
  ]
 },
 {
  "id": "dkIPC",
  "ordinal": 23,
  "label": "IPC Detect",
  "category": "IPC_JOB",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IPC",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.IPC"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "IPC_JOB"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IPC.pas",
    "lines": [
     175
    ]
   }
  ]
 },
 {
  "id": "dkJob",
  "ordinal": 24,
  "label": "Job Detect",
  "category": "IPC_JOB",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.Job",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Job"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "IPC_JOB"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Job.pas",
    "lines": [
     86
    ]
   }
  ]
 },
 {
  "id": "dkFileSwap",
  "ordinal": 25,
  "label": "File Swap Detect",
  "category": "FILE_IDENTITY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.FileGuard",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SectionBackingIdentity"
  ],
  "producerUnits": [
   "Cozy.NHW.FileGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "FILE_IDENTITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FileGuard.pas",
    "lines": [
     110
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     106
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SectionBackingIdentity.pas",
    "lines": [
     437
    ]
   }
  ]
 },
 {
  "id": "dkFileRename",
  "ordinal": 26,
  "label": "File Rename Detect",
  "category": "FILE_IDENTITY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.FileGuard",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.FileGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "FILE_IDENTITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FileGuard.pas",
    "lines": [
     122,
     136
    ]
   }
  ]
 },
 {
  "id": "dkReparse",
  "ordinal": 27,
  "label": "Reparse Detect",
  "category": "FILE_IDENTITY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.FileGuard",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.FileGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "FILE_IDENTITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FileGuard.pas",
    "lines": [
     144
    ]
   }
  ]
 },
 {
  "id": "dkStream",
  "ordinal": 28,
  "label": "Stream Detect",
  "category": "FILE_IDENTITY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.FileGuard",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.FileGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "FILE_IDENTITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FileGuard.pas",
    "lines": [
     152
    ]
   }
  ]
 },
 {
  "id": "dkFileSecurity",
  "ordinal": 29,
  "label": "File Security Detect",
  "category": "FILE_IDENTITY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.FileGuard",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.FileGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "FILE_IDENTITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FileGuard.pas",
    "lines": [
     160
    ]
   }
  ]
 },
 {
  "id": "dkFileLink",
  "ordinal": 30,
  "label": "File Link Detect",
  "category": "FILE_IDENTITY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.FileGuard",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence"
  ],
  "producerUnits": [
   "Cozy.NHW.FileGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "FILE_IDENTITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FileGuard.pas",
    "lines": [
     170
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     106
    ]
   }
  ]
 },
 {
  "id": "dkRegistryValue",
  "ordinal": 31,
  "label": "Registry Value Detect",
  "category": "REGISTRY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Registry"
  ],
  "producerUnits": [
   "Cozy.NHW.Registry"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "REGISTRY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Registry.pas",
    "lines": [
     121
    ]
   }
  ]
 },
 {
  "id": "dkRegistryKey",
  "ordinal": 32,
  "label": "Registry Key Detect",
  "category": "REGISTRY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Registry"
  ],
  "producerUnits": [
   "Cozy.NHW.Registry"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "REGISTRY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Registry.pas",
    "lines": [
     129
    ]
   }
  ]
 },
 {
  "id": "dkRegistrySecurity",
  "ordinal": 33,
  "label": "Registry Security Detect",
  "category": "REGISTRY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Registry"
  ],
  "producerUnits": [
   "Cozy.NHW.Registry"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "REGISTRY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Registry.pas",
    "lines": [
     137
    ]
   }
  ]
 },
 {
  "id": "dkPolicy",
  "ordinal": 34,
  "label": "Policy Detect",
  "category": "REGISTRY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Registry"
  ],
  "producerUnits": [
   "Cozy.NHW.Registry"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "REGISTRY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Registry.pas",
    "lines": [
     296
    ]
   }
  ]
 },
 {
  "id": "dkRegistryBurst",
  "ordinal": 35,
  "label": "Registry Burst Detect",
  "category": "REGISTRY",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Registry"
  ],
  "producerUnits": [
   "Cozy.NHW.Registry"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "REGISTRY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Registry.pas",
    "lines": [
     407
    ]
   }
  ]
 },
 {
  "id": "dkThreadPriority",
  "ordinal": 36,
  "label": "Thread Priority Detect",
  "category": "SCHEDULING_MITIGATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Scheduler.Rules"
  ],
  "producerUnits": [
   "Cozy.NHW.Scheduler.Rules"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SCHEDULING_MITIGATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Scheduler.Rules.pas",
    "lines": [
     79
    ]
   }
  ]
 },
 {
  "id": "dkProcessPriority",
  "ordinal": 37,
  "label": "Priority Detect",
  "category": "SCHEDULING_MITIGATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Scheduler.Rules"
  ],
  "producerUnits": [
   "Cozy.NHW.Scheduler.Rules"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SCHEDULING_MITIGATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Scheduler.Rules.pas",
    "lines": [
     55
    ]
   }
  ]
 },
 {
  "id": "dkAffinity",
  "ordinal": 38,
  "label": "Affinity Detect",
  "category": "SCHEDULING_MITIGATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Scheduler.Rules"
  ],
  "producerUnits": [
   "Cozy.NHW.Scheduler.Rules"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SCHEDULING_MITIGATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Scheduler.Rules.pas",
    "lines": [
     58,
     85
    ]
   }
  ]
 },
 {
  "id": "dkCPUGroup",
  "ordinal": 39,
  "label": "CPU Group Detect",
  "category": "SCHEDULING_MITIGATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Scheduler.Rules"
  ],
  "producerUnits": [
   "Cozy.NHW.Scheduler.Rules"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SCHEDULING_MITIGATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Scheduler.Rules.pas",
    "lines": [
     61,
     83
    ]
   }
  ]
 },
 {
  "id": "dkScheduling",
  "ordinal": 40,
  "label": "Scheduling Detect",
  "category": "SCHEDULING_MITIGATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Scheduler.Rules"
  ],
  "producerUnits": [
   "Cozy.NHW.Scheduler.Rules"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SCHEDULING_MITIGATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Scheduler.Rules.pas",
    "lines": [
     64,
     89,
     93
    ]
   }
  ]
 },
 {
  "id": "dkMitigation",
  "ordinal": 41,
  "label": "Mitigation Detect",
  "category": "SCHEDULING_MITIGATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Scheduler.Rules"
  ],
  "producerUnits": [
   "Cozy.NHW.Scheduler.Rules"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SCHEDULING_MITIGATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Scheduler.Rules.pas",
    "lines": [
     69
    ]
   }
  ]
 },
 {
  "id": "dkNamespace",
  "ordinal": 42,
  "label": "Namespace Detect",
  "category": "NAMESPACE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Namespace"
  ],
  "producerUnits": [
   "Cozy.NHW.Namespace"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NAMESPACE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Namespace.pas",
    "lines": [
     88,
     114
    ]
   }
  ]
 },
 {
  "id": "dkObjectType",
  "ordinal": 43,
  "label": "Object Type Detect",
  "category": "NAMESPACE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Namespace"
  ],
  "producerUnits": [
   "Cozy.NHW.Namespace"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NAMESPACE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Namespace.pas",
    "lines": [
     98
    ]
   }
  ]
 },
 {
  "id": "dkSymbolicLink",
  "ordinal": 44,
  "label": "Symbolic Link Detect",
  "category": "NAMESPACE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Namespace"
  ],
  "producerUnits": [
   "Cozy.NHW.Namespace"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NAMESPACE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Namespace.pas",
    "lines": [
     106
    ]
   }
  ]
 },
 {
  "id": "dkDeviceMap",
  "ordinal": 45,
  "label": "Device Map Detect",
  "category": "NAMESPACE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Namespace"
  ],
  "producerUnits": [
   "Cozy.NHW.Namespace"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NAMESPACE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Namespace.pas",
    "lines": [
     90,
     100,
     107,
     116
    ]
   }
  ]
 },
 {
  "id": "dkObjectSecurity",
  "ordinal": 46,
  "label": "Object Security Detect",
  "category": "NAMESPACE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Namespace"
  ],
  "producerUnits": [
   "Cozy.NHW.Namespace"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NAMESPACE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Namespace.pas",
    "lines": [
     222
    ]
   }
  ]
 },
 {
  "id": "dkNamespaceBurst",
  "ordinal": 47,
  "label": "Namespace Burst Detect",
  "category": "NAMESPACE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.Namespace"
  ],
  "producerUnits": [
   "Cozy.NHW.Namespace"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NAMESPACE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Namespace.pas",
    "lines": [
     312
    ]
   }
  ]
 },
 {
  "id": "dkTransientThread",
  "ordinal": 48,
  "label": "Transient Thread Detect",
  "category": "ETW_LIFECYCLE",
  "sourceUnits": [
   "Cozy.NHW.ETWFusion",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ETWFusion"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ETW_LIFECYCLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETWFusion.pas",
    "lines": [
     153
    ]
   }
  ]
 },
 {
  "id": "dkProcessLifetime",
  "ordinal": 49,
  "label": "Process Lifetime Detect",
  "category": "ETW_LIFECYCLE",
  "sourceUnits": [
   "Cozy.NHW.ETWFusion",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ETWFusion"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ETW_LIFECYCLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETWFusion.pas",
    "lines": [
     185
    ]
   }
  ]
 },
 {
  "id": "dkKernelFileIO",
  "ordinal": 50,
  "label": "File I/O Detect",
  "category": "ETW_LIFECYCLE",
  "sourceUnits": [
   "Cozy.NHW.ETWFusion",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ETWFusion"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ETW_LIFECYCLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETWFusion.pas",
    "lines": [
     256
    ]
   }
  ]
 },
 {
  "id": "dkKernelRegistry",
  "ordinal": 51,
  "label": "Registry Activity Detect",
  "category": "ETW_LIFECYCLE",
  "sourceUnits": [
   "Cozy.NHW.ETWFusion",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ETWFusion"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ETW_LIFECYCLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETWFusion.pas",
    "lines": [
     267
    ]
   }
  ]
 },
 {
  "id": "dkEventFusion",
  "ordinal": 52,
  "label": "Event Fusion Detect",
  "category": "ETW_LIFECYCLE",
  "sourceUnits": [
   "Cozy.NHW.ETWFusion",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ETWFusion"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ETW_LIFECYCLE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETWFusion.pas",
    "lines": [
     202
    ]
   }
  ]
 },
 {
  "id": "dkTraceGap",
  "ordinal": 53,
  "label": "Trace Gap Detect",
  "category": "ETW_LIFECYCLE",
  "sourceUnits": [
   "Cozy.NHW.ETWFusion",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ETWFusion"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ETW_LIFECYCLE"
  ],
  "signalClass": "UNKNOWN",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETWFusion.pas",
    "lines": [
     215
    ]
   }
  ]
 },
 {
  "id": "dkThreadStart",
  "ordinal": 54,
  "label": "Thread Start Detect",
  "category": "THREAD_ORIGIN",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ThreadOrigin"
  ],
  "producerUnits": [
   "Cozy.NHW.ThreadOrigin"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "THREAD_ORIGIN"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadOrigin.pas",
    "lines": [
     286
    ]
   }
  ]
 },
 {
  "id": "dkPrivateThread",
  "ordinal": 55,
  "label": "Private Thread Detect",
  "category": "THREAD_ORIGIN",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.ETWImageFusion",
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExecutableLifecycle",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.InjectionEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ModuleOriginVerification",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus",
   "Cozy.NHW.SignalCorrelation",
   "Cozy.NHW.TLSCallbackIntegrity",
   "Cozy.NHW.ThreadOrigin",
   "Cozy.NHW.ThreadStackProvenance"
  ],
  "producerUnits": [
   "Cozy.NHW.ThreadOrigin"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "THREAD_ORIGIN"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": true,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     73
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETWImageFusion.pas",
    "lines": [
     100
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1710,
     1980,
     2648,
     2702,
     2719
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExecutableLifecycle.pas",
    "lines": [
     338
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     75
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.InjectionEvidence.pas",
    "lines": [
     100
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ModuleOriginVerification.pas",
    "lines": [
     446
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     97
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     67
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     114
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.TLSCallbackIntegrity.pas",
    "lines": [
     306
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadOrigin.pas",
    "lines": [
     288
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadStackProvenance.pas",
    "lines": [
     203
    ]
   }
  ]
 },
 {
  "id": "dkRemoteThread",
  "ordinal": 56,
  "label": "Remote Thread Detect",
  "category": "THREAD_ORIGIN",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.ETWImageFusion",
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.InjectionEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ModuleOriginVerification",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus",
   "Cozy.NHW.SignalCorrelation",
   "Cozy.NHW.ThreadOrigin"
  ],
  "producerUnits": [
   "Cozy.NHW.ThreadOrigin"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "THREAD_ORIGIN"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": true,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     73
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETWImageFusion.pas",
    "lines": [
     100
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1710,
     1980,
     2648,
     2701,
     2719
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     75
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.InjectionEvidence.pas",
    "lines": [
     100
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ModuleOriginVerification.pas",
    "lines": [
     446
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     97
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     67
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     114
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadOrigin.pas",
    "lines": [
     292
    ]
   }
  ]
 },
 {
  "id": "dkThreadRegion",
  "ordinal": 57,
  "label": "Thread Region Detect",
  "category": "THREAD_ORIGIN",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SignalCorrelation",
   "Cozy.NHW.ThreadOrigin"
  ],
  "producerUnits": [
   "Cozy.NHW.ThreadOrigin"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "THREAD_ORIGIN"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     114
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadOrigin.pas",
    "lines": [
     296
    ]
   }
  ]
 },
 {
  "id": "dkThreadSpawn",
  "ordinal": 58,
  "label": "Thread Spawn Detect",
  "category": "THREAD_ORIGIN",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SignalCorrelation",
   "Cozy.NHW.ThreadOrigin"
  ],
  "producerUnits": [
   "Cozy.NHW.ThreadOrigin"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "THREAD_ORIGIN"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     75
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     77
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     99
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     115
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadOrigin.pas",
    "lines": [
     318
    ]
   }
  ]
 },
 {
  "id": "dkStackBounds",
  "ordinal": 59,
  "label": "Stack Bounds Detect",
  "category": "STACK",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.StackGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.StackGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "STACK"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.StackGuard.pas",
    "lines": [
     279
    ]
   }
  ]
 },
 {
  "id": "dkStackGuard",
  "ordinal": 60,
  "label": "Stack Guard Detect",
  "category": "STACK",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.StackGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.StackGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "STACK"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.StackGuard.pas",
    "lines": [
     280
    ]
   }
  ]
 },
 {
  "id": "dkStackExecute",
  "ordinal": 61,
  "label": "Stack Execute Detect",
  "category": "STACK",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.StackGuard",
   "Cozy.NHW.ThreadStackProvenance"
  ],
  "producerUnits": [
   "Cozy.NHW.StackGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "STACK"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.StackGuard.pas",
    "lines": [
     281
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadStackProvenance.pas",
    "lines": [
     203
    ]
   }
  ]
 },
 {
  "id": "dkStackAllocation",
  "ordinal": 62,
  "label": "Stack Allocation Detect",
  "category": "STACK",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.StackGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.StackGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "STACK"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.StackGuard.pas",
    "lines": [
     282
    ]
   }
  ]
 },
 {
  "id": "dkStackGrowth",
  "ordinal": 63,
  "label": "Stack Growth Detect",
  "category": "STACK",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.StackGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.StackGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "STACK"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.StackGuard.pas",
    "lines": [
     283
    ]
   }
  ]
 },
 {
  "id": "dkStackCorrelation",
  "ordinal": 64,
  "label": "Stack Correlation Detect",
  "category": "STACK",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.StackGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.StackGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "STACK"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.StackGuard.pas",
    "lines": [
     287
    ]
   }
  ]
 },
 {
  "id": "dkAllocation",
  "ordinal": 65,
  "label": "Allocation Detect",
  "category": "MEMORY_ALLOCATION",
  "sourceUnits": [
   "Cozy.NHW.AllocationGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.AllocationGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_ALLOCATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AllocationGuard.pas",
    "lines": [
     347,
     369
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1309,
     1336
    ]
   }
  ]
 },
 {
  "id": "dkCommit",
  "ordinal": 66,
  "label": "Commit Detect",
  "category": "MEMORY_ALLOCATION",
  "sourceUnits": [
   "Cozy.NHW.AllocationGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.AllocationGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_ALLOCATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AllocationGuard.pas",
    "lines": [
     370
    ]
   }
  ]
 },
 {
  "id": "dkExecuteProtect",
  "ordinal": 67,
  "label": "Execute Protect Detect",
  "category": "MEMORY_ALLOCATION",
  "sourceUnits": [
   "Cozy.NHW.AllocationGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SignalCorrelation"
  ],
  "producerUnits": [
   "Cozy.NHW.AllocationGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_ALLOCATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AllocationGuard.pas",
    "lines": [
     371
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     116
    ]
   }
  ]
 },
 {
  "id": "dkRWX",
  "ordinal": 68,
  "label": "RWX Detect",
  "category": "MEMORY_ALLOCATION",
  "sourceUnits": [
   "Cozy.NHW.AllocationGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SignalCorrelation"
  ],
  "producerUnits": [
   "Cozy.NHW.AllocationGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_ALLOCATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AllocationGuard.pas",
    "lines": [
     348,
     372
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     116
    ]
   }
  ]
 },
 {
  "id": "dkMemoryRelease",
  "ordinal": 69,
  "label": "Memory Release Detect",
  "category": "MEMORY_ALLOCATION",
  "sourceUnits": [
   "Cozy.NHW.AllocationGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SensorConsensus"
  ],
  "producerUnits": [
   "Cozy.NHW.AllocationGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_ALLOCATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AllocationGuard.pas",
    "lines": [
     373,
     417
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     72
    ]
   }
  ]
 },
 {
  "id": "dkAllocationBurst",
  "ordinal": 70,
  "label": "Allocation Burst Detect",
  "category": "MEMORY_ALLOCATION",
  "sourceUnits": [
   "Cozy.NHW.AllocationGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.AllocationGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_ALLOCATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AllocationGuard.pas",
    "lines": [
     292
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1310,
     1336
    ]
   }
  ]
 },
 {
  "id": "dkMappedView",
  "ordinal": 71,
  "label": "Mapped View Detect",
  "category": "MEMORY_MAPPING",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SectionCorrelation"
  ],
  "producerUnits": [],
  "productionEmission": "FP1_BASELINE_ONLY_NO_DIRECT_EMITTER",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_MAPPING"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SectionCorrelation.pas",
    "lines": [
     186
    ]
   }
  ]
 },
 {
  "id": "dkCOW",
  "ordinal": 72,
  "label": "COW Detect",
  "category": "MEMORY_MAPPING",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.MappingGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.MappingGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_MAPPING"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.MappingGuard.pas",
    "lines": [
     429
    ]
   }
  ]
 },
 {
  "id": "dkPageSharing",
  "ordinal": 73,
  "label": "Page Sharing Detect",
  "category": "MEMORY_MAPPING",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.MappingGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.MappingGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_MAPPING"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.MappingGuard.pas",
    "lines": [
     430
    ]
   }
  ]
 },
 {
  "id": "dkMappingBacking",
  "ordinal": 74,
  "label": "Mapping Backing Detect",
  "category": "MEMORY_MAPPING",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.MappingGuard",
   "Cozy.NHW.SectionCorrelation"
  ],
  "producerUnits": [
   "Cozy.NHW.MappingGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_MAPPING"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.MappingGuard.pas",
    "lines": [
     431
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SectionCorrelation.pas",
    "lines": [
     186
    ]
   }
  ]
 },
 {
  "id": "dkExecutableMapping",
  "ordinal": 75,
  "label": "Executable Mapping Detect",
  "category": "MEMORY_MAPPING",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.MappingGuard",
   "Cozy.NHW.SectionCorrelation"
  ],
  "producerUnits": [
   "Cozy.NHW.MappingGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_MAPPING"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.MappingGuard.pas",
    "lines": [
     432
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SectionCorrelation.pas",
    "lines": [
     187
    ]
   }
  ]
 },
 {
  "id": "dkMappingBurst",
  "ordinal": 76,
  "label": "Mapping Burst Detect",
  "category": "MEMORY_MAPPING",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.MappingGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.MappingGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_MAPPING"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.MappingGuard.pas",
    "lines": [
     342
    ]
   }
  ]
 },
 {
  "id": "dkProtectTransition",
  "ordinal": 77,
  "label": "Protect Transition Detect",
  "category": "MEMORY_PROTECTION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ProtectionGuard",
   "Cozy.NHW.SignalCorrelation"
  ],
  "producerUnits": [
   "Cozy.NHW.ProtectionGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_PROTECTION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ProtectionGuard.pas",
    "lines": [
     350
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     116
    ]
   }
  ]
 },
 {
  "id": "dkProtectionCycle",
  "ordinal": 78,
  "label": "Protection Cycle Detect",
  "category": "MEMORY_PROTECTION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ProtectionGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.ProtectionGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_PROTECTION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ProtectionGuard.pas",
    "lines": [
     370
    ]
   }
  ]
 },
 {
  "id": "dkImageProtection",
  "ordinal": 79,
  "label": "Image Protection Detect",
  "category": "MEMORY_PROTECTION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ProtectionGuard",
   "Cozy.NHW.SignalCorrelation"
  ],
  "producerUnits": [
   "Cozy.NHW.ProtectionGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_PROTECTION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ProtectionGuard.pas",
    "lines": [
     351
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     117
    ]
   }
  ]
 },
 {
  "id": "dkGuardTransition",
  "ordinal": 80,
  "label": "Guard Transition Detect",
  "category": "MEMORY_PROTECTION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ProtectionGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.ProtectionGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_PROTECTION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ProtectionGuard.pas",
    "lines": [
     352
    ]
   }
  ]
 },
 {
  "id": "dkNoAccess",
  "ordinal": 81,
  "label": "NoAccess Detect",
  "category": "MEMORY_PROTECTION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ProtectionGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.ProtectionGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_PROTECTION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ProtectionGuard.pas",
    "lines": [
     353
    ]
   }
  ]
 },
 {
  "id": "dkProtectBurst",
  "ordinal": 82,
  "label": "Protect Burst Detect",
  "category": "MEMORY_PROTECTION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ProtectionGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.ProtectionGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_PROTECTION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ProtectionGuard.pas",
    "lines": [
     282
    ]
   }
  ]
 },
 {
  "id": "dkReadAccess",
  "ordinal": 83,
  "label": "Read Access Detect",
  "category": "MEMORY_READ",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ReadAccess"
  ],
  "producerUnits": [
   "Cozy.NHW.ReadAccess"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_READ"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ReadAccess.pas",
    "lines": [
     189
    ]
   }
  ]
 },
 {
  "id": "dkCanaryAccess",
  "ordinal": 84,
  "label": "Canary Access Detect",
  "category": "MEMORY_READ",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ReadAccess"
  ],
  "producerUnits": [
   "Cozy.NHW.ReadAccess"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_READ"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ReadAccess.pas",
    "lines": [
     265
    ]
   }
  ]
 },
 {
  "id": "dkReadCorrelation",
  "ordinal": 85,
  "label": "Read Correlation Detect",
  "category": "MEMORY_READ",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ReadAccess"
  ],
  "producerUnits": [
   "Cozy.NHW.ReadAccess"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_READ"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ReadAccess.pas",
    "lines": [
     273
    ]
   }
  ]
 },
 {
  "id": "dkReadPattern",
  "ordinal": 86,
  "label": "Read Pattern Detect",
  "category": "MEMORY_READ",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ReadAccess"
  ],
  "producerUnits": [
   "Cozy.NHW.ReadAccess"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_READ"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ReadAccess.pas",
    "lines": [
     170
    ]
   }
  ]
 },
 {
  "id": "dkReadGap",
  "ordinal": 87,
  "label": "Read Gap Detect",
  "category": "MEMORY_READ",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ReadAccess"
  ],
  "producerUnits": [
   "Cozy.NHW.ReadAccess"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_READ"
  ],
  "signalClass": "UNKNOWN",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ReadAccess.pas",
    "lines": [
     332
    ]
   }
  ]
 },
 {
  "id": "dkWriteWatch",
  "ordinal": 88,
  "label": "Write Watch Detect",
  "category": "MEMORY_WRITE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.WriteWatch"
  ],
  "producerUnits": [
   "Cozy.NHW.WriteWatch"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_WRITE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.WriteWatch.pas",
    "lines": [
     337
    ]
   }
  ]
 },
 {
  "id": "dkWriteBurst",
  "ordinal": 89,
  "label": "Write Burst Detect",
  "category": "MEMORY_WRITE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.WriteWatch"
  ],
  "producerUnits": [
   "Cozy.NHW.WriteWatch"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_WRITE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.WriteWatch.pas",
    "lines": [
     287
    ]
   }
  ]
 },
 {
  "id": "dkRepeatedWrite",
  "ordinal": 90,
  "label": "Repeated Write Detect",
  "category": "MEMORY_WRITE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.WriteWatch"
  ],
  "producerUnits": [
   "Cozy.NHW.WriteWatch"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_WRITE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.WriteWatch.pas",
    "lines": [
     312
    ]
   }
  ]
 },
 {
  "id": "dkWriteCorrelation",
  "ordinal": 91,
  "label": "Write Correlation Detect",
  "category": "MEMORY_WRITE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.WriteWatch"
  ],
  "producerUnits": [
   "Cozy.NHW.WriteWatch"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_WRITE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.WriteWatch.pas",
    "lines": [
     328
    ]
   }
  ]
 },
 {
  "id": "dkWriteIntegrity",
  "ordinal": 92,
  "label": "Write Integrity Detect",
  "category": "MEMORY_WRITE",
  "sourceUnits": [
   "Cozy.NHW.APCStyleEvidence",
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.InjectionEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus",
   "Cozy.NHW.SignalCorrelation",
   "Cozy.NHW.ThreadTimeline",
   "Cozy.NHW.WriteWatch"
  ],
  "producerUnits": [
   "Cozy.NHW.WriteWatch"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEMORY_WRITE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": true,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.APCStyleEvidence.pas",
    "lines": [
     42
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     65
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1981,
     2702,
     2720
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     71
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.InjectionEvidence.pas",
    "lines": [
     106
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     103
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     70
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     117
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadTimeline.pas",
    "lines": [
     313
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.WriteWatch.pas",
    "lines": [
     412
    ]
   }
  ]
 },
 {
  "id": "dkDeadlock",
  "ordinal": 93,
  "label": "Deadlock Detect",
  "category": "WAIT_CHAIN",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.WaitChain"
  ],
  "producerUnits": [
   "Cozy.NHW.WaitChain"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "WAIT_CHAIN"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.WaitChain.pas",
    "lines": [
     318
    ]
   }
  ]
 },
 {
  "id": "dkThreadWait",
  "ordinal": 94,
  "label": "Thread Wait Detect",
  "category": "WAIT_CHAIN",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.WaitChain"
  ],
  "producerUnits": [
   "Cozy.NHW.WaitChain"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "WAIT_CHAIN"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.WaitChain.pas",
    "lines": [
     326
    ]
   }
  ]
 },
 {
  "id": "dkExternalWait",
  "ordinal": 95,
  "label": "External Wait Detect",
  "category": "WAIT_CHAIN",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.WaitChain"
  ],
  "producerUnits": [
   "Cozy.NHW.WaitChain"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "WAIT_CHAIN"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.WaitChain.pas",
    "lines": [
     328
    ]
   }
  ]
 },
 {
  "id": "dkCriticalSection",
  "ordinal": 96,
  "label": "Critical Section Detect",
  "category": "WAIT_CHAIN",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.WaitChain"
  ],
  "producerUnits": [
   "Cozy.NHW.WaitChain"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "WAIT_CHAIN"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.WaitChain.pas",
    "lines": [
     331
    ]
   }
  ]
 },
 {
  "id": "dkContention",
  "ordinal": 97,
  "label": "Contention Detect",
  "category": "WAIT_CHAIN",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.WaitChain"
  ],
  "producerUnits": [
   "Cozy.NHW.WaitChain"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "WAIT_CHAIN"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.WaitChain.pas",
    "lines": [
     353
    ]
   }
  ]
 },
 {
  "id": "dkWaitBurst",
  "ordinal": 98,
  "label": "Wait Burst Detect",
  "category": "WAIT_CHAIN",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.WaitChain"
  ],
  "producerUnits": [
   "Cozy.NHW.WaitChain"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "WAIT_CHAIN"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.WaitChain.pas",
    "lines": [
     377
    ]
   }
  ]
 },
 {
  "id": "dkCaptureClient",
  "ordinal": 99,
  "label": "Capture Client Detect",
  "category": "CAPTURE",
  "sourceUnits": [
   "Cozy.NHW.Capture",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Capture"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "CAPTURE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Capture.pas",
    "lines": [
     156
    ]
   }
  ]
 },
 {
  "id": "dkCaptureLibrary",
  "ordinal": 100,
  "label": "Capture Library Detect",
  "category": "CAPTURE",
  "sourceUnits": [
   "Cozy.NHW.Capture",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Capture"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "CAPTURE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Capture.pas",
    "lines": [
     157
    ]
   }
  ]
 },
 {
  "id": "dkCaptureDriver",
  "ordinal": 101,
  "label": "Capture Driver Detect",
  "category": "CAPTURE",
  "sourceUnits": [
   "Cozy.NHW.Capture",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Capture"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "CAPTURE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Capture.pas",
    "lines": [
     158
    ]
   }
  ]
 },
 {
  "id": "dkCaptureProxy",
  "ordinal": 102,
  "label": "Packet Proxy Detect",
  "category": "CAPTURE",
  "sourceUnits": [
   "Cozy.NHW.Capture",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Capture"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "CAPTURE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Capture.pas",
    "lines": [
     159
    ]
   }
  ]
 },
 {
  "id": "dkCaptureCorrelation",
  "ordinal": 103,
  "label": "Capture Correlation Detect",
  "category": "CAPTURE",
  "sourceUnits": [
   "Cozy.NHW.Capture",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Capture"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "CAPTURE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Capture.pas",
    "lines": [
     160
    ]
   }
  ]
 },
 {
  "id": "dkNetworkFilter",
  "ordinal": 104,
  "label": "Network Filter Detect",
  "category": "NETWORK_FILTER",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.NetworkGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.NetworkGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_FILTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.NetworkGuard.pas",
    "lines": [
     127
    ]
   }
  ]
 },
 {
  "id": "dkWFPCallout",
  "ordinal": 105,
  "label": "WFP Callout Detect",
  "category": "NETWORK_FILTER",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.NetworkGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.NetworkGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_FILTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.NetworkGuard.pas",
    "lines": [
     132
    ]
   }
  ]
 },
 {
  "id": "dkWFPProvider",
  "ordinal": 106,
  "label": "WFP Provider Detect",
  "category": "NETWORK_FILTER",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.NetworkGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.NetworkGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_FILTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.NetworkGuard.pas",
    "lines": [
     137
    ]
   }
  ]
 },
 {
  "id": "dkRouteChange",
  "ordinal": 107,
  "label": "Route Change Detect",
  "category": "NETWORK_FILTER",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.NetworkGuard",
   "Cozy.NHW.PathGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.NetworkGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_FILTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.NetworkGuard.pas",
    "lines": [
     147
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PathGuard.pas",
    "lines": [
     95
    ]
   }
  ]
 },
 {
  "id": "dkProxyChange",
  "ordinal": 108,
  "label": "Proxy Change Detect",
  "category": "NETWORK_FILTER",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.NetworkGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.NetworkGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_FILTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.NetworkGuard.pas",
    "lines": [
     152
    ]
   }
  ]
 },
 {
  "id": "dkNetworkCorrelation",
  "ordinal": 109,
  "label": "Network Correlation Detect",
  "category": "NETWORK_FILTER",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.NetworkGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.NetworkGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_FILTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.NetworkGuard.pas",
    "lines": [
     111
    ]
   }
  ]
 },
 {
  "id": "dkDNSServer",
  "ordinal": 110,
  "label": "DNS Server Detect",
  "category": "NETWORK_PATH",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PathGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.PathGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_PATH"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PathGuard.pas",
    "lines": [
     113
    ]
   }
  ]
 },
 {
  "id": "dkDNSPolicy",
  "ordinal": 111,
  "label": "DNS Policy Detect",
  "category": "NETWORK_PATH",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PathGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.PathGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_PATH"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PathGuard.pas",
    "lines": [
     124
    ]
   }
  ]
 },
 {
  "id": "dkWinsockProvider",
  "ordinal": 112,
  "label": "Winsock Provider Detect",
  "category": "NETWORK_PATH",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PathGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.PathGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_PATH"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PathGuard.pas",
    "lines": [
     129
    ]
   }
  ]
 },
 {
  "id": "dkInterfaceChange",
  "ordinal": 113,
  "label": "Interface Detect",
  "category": "NETWORK_PATH",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PathGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.PathGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_PATH"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PathGuard.pas",
    "lines": [
     118
    ]
   }
  ]
 },
 {
  "id": "dkPathCorrelation",
  "ordinal": 114,
  "label": "Path Correlation Detect",
  "category": "NETWORK_PATH",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PathRules"
  ],
  "producerUnits": [
   "Cozy.NHW.PathRules"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_PATH"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PathRules.pas",
    "lines": [
     110
    ]
   }
  ]
 },
 {
  "id": "dkNetworkIntegrity",
  "ordinal": 115,
  "label": "Network Integrity Detect",
  "category": "NETWORK_PATH",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PathRules"
  ],
  "producerUnits": [
   "Cozy.NHW.PathRules"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "NETWORK_PATH"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PathRules.pas",
    "lines": [
     137
    ]
   }
  ]
 },
 {
  "id": "dkIAT",
  "ordinal": 116,
  "label": "IAT Detect",
  "category": "SELF_POINTER",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ImportRedirection",
   "Cozy.NHW.IndirectTargets",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SelfGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.SelfGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SELF_POINTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ImportRedirection.pas",
    "lines": [
     316
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IndirectTargets.pas",
    "lines": [
     180
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SelfGuard.pas",
    "lines": [
     316
    ]
   }
  ]
 },
 {
  "id": "dkFunctionPointer",
  "ordinal": 117,
  "label": "Function Pointer Detect",
  "category": "SELF_POINTER",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IndirectTargets",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SelfGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.SelfGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SELF_POINTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IndirectTargets.pas",
    "lines": [
     180
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SelfGuard.pas",
    "lines": [
     324
    ]
   }
  ]
 },
 {
  "id": "dkCallback",
  "ordinal": 118,
  "label": "Callback Detect",
  "category": "SELF_POINTER",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IndirectTargets",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SelfGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.SelfGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SELF_POINTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IndirectTargets.pas",
    "lines": [
     180
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SelfGuard.pas",
    "lines": [
     341
    ]
   }
  ]
 },
 {
  "id": "dkProcessParameter",
  "ordinal": 119,
  "label": "Process Parameter Detect",
  "category": "SELF_POINTER",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SelfGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.SelfGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SELF_POINTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SelfGuard.pas",
    "lines": [
     348
    ]
   }
  ]
 },
 {
  "id": "dkThreadProvenance",
  "ordinal": 120,
  "label": "Thread Origin Detect",
  "category": "SELF_POINTER",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SelfGuard",
   "Cozy.NHW.SensorConsensus"
  ],
  "producerUnits": [
   "Cozy.NHW.SelfGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SELF_POINTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     74
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     77
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     99
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SelfGuard.pas",
    "lines": [
     240
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     68
    ]
   }
  ]
 },
 {
  "id": "dkBoundary",
  "ordinal": 121,
  "label": "Boundary Detect",
  "category": "SELF_POINTER",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SelfGuard"
  ],
  "producerUnits": [
   "Cozy.NHW.SelfGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SELF_POINTER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SelfGuard.pas",
    "lines": [
     365
    ]
   }
  ]
 },
 {
  "id": "dkTLSPointer",
  "ordinal": 122,
  "label": "TLS Pointer Detect",
  "category": "HEAP_TLS",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.HeapTLS",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.TLSCallbackIntegrity"
  ],
  "producerUnits": [
   "Cozy.NHW.HeapTLS"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "HEAP_TLS"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.HeapTLS.pas",
    "lines": [
     293
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.TLSCallbackIntegrity.pas",
    "lines": [
     305
    ]
   }
  ]
 },
 {
  "id": "dkFLSCallback",
  "ordinal": 123,
  "label": "FLS Callback Detect",
  "category": "HEAP_TLS",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.HeapTLS",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.HeapTLS"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "HEAP_TLS"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.HeapTLS.pas",
    "lines": [
     313
    ]
   }
  ]
 },
 {
  "id": "dkHeapState",
  "ordinal": 124,
  "label": "Heap State Detect",
  "category": "HEAP_TLS",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.HeapTLS",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.HeapTLS"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "HEAP_TLS"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.HeapTLS.pas",
    "lines": [
     237
    ]
   }
  ]
 },
 {
  "id": "dkHeapIntegrity",
  "ordinal": 125,
  "label": "Heap Integrity Detect",
  "category": "HEAP_TLS",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.HeapTLS",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.HeapTLS"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "HEAP_TLS"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.HeapTLS.pas",
    "lines": [
     336
    ]
   }
  ]
 },
 {
  "id": "dkHeapCorrelation",
  "ordinal": 126,
  "label": "Heap Correlation Detect",
  "category": "HEAP_TLS",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.HeapTLS",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.HeapTLS"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "HEAP_TLS"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.HeapTLS.pas",
    "lines": [
     394
    ]
   }
  ]
 },
 {
  "id": "dkUnwind",
  "ordinal": 127,
  "label": "Unwind Detect",
  "category": "EXCEPTION_UNWIND",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExceptionGuard",
   "Cozy.NHW.ExplainableEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.UnwindConsistency"
  ],
  "producerUnits": [
   "Cozy.NHW.ExceptionGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXCEPTION_UNWIND"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExceptionGuard.pas",
    "lines": [
     219,
     231
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExplainableEvidence.pas",
    "lines": [
     61
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.UnwindConsistency.pas",
    "lines": [
     109
    ]
   }
  ]
 },
 {
  "id": "dkFunctionTable",
  "ordinal": 128,
  "label": "Function Table Detect",
  "category": "EXCEPTION_UNWIND",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExceptionGuard",
   "Cozy.NHW.ExplainableEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.UnwindConsistency"
  ],
  "producerUnits": [
   "Cozy.NHW.ExceptionGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXCEPTION_UNWIND"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExceptionGuard.pas",
    "lines": [
     213,
     234
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExplainableEvidence.pas",
    "lines": [
     61
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.UnwindConsistency.pas",
    "lines": [
     109
    ]
   }
  ]
 },
 {
  "id": "dkExceptionRange",
  "ordinal": 129,
  "label": "Exception Range Detect",
  "category": "EXCEPTION_UNWIND",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExceptionGuard",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.UnwindConsistency"
  ],
  "producerUnits": [
   "Cozy.NHW.ExceptionGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXCEPTION_UNWIND"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExceptionGuard.pas",
    "lines": [
     215,
     228
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.UnwindConsistency.pas",
    "lines": [
     110
    ]
   }
  ]
 },
 {
  "id": "dkExceptionCallback",
  "ordinal": 130,
  "label": "Exception Callback Detect",
  "category": "EXCEPTION_UNWIND",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExceptionGuard",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ExceptionGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXCEPTION_UNWIND"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExceptionGuard.pas",
    "lines": [
     242
    ]
   }
  ]
 },
 {
  "id": "dkExceptionCorrelation",
  "ordinal": 131,
  "label": "Exception Correlation Detect",
  "category": "EXCEPTION_UNWIND",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExceptionGuard",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ExceptionGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXCEPTION_UNWIND"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExceptionGuard.pas",
    "lines": [
     289
    ]
   }
  ]
 },
 {
  "id": "dkCompletionPort",
  "ordinal": 132,
  "label": "Completion Port Detect",
  "category": "ASYNC",
  "sourceUnits": [
   "Cozy.NHW.AsyncGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.AsyncGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ASYNC"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AsyncGuard.pas",
    "lines": [
     484,
     496
    ]
   }
  ]
 },
 {
  "id": "dkCompletionKey",
  "ordinal": 133,
  "label": "Completion Key Detect",
  "category": "ASYNC",
  "sourceUnits": [
   "Cozy.NHW.AsyncGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.AsyncGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ASYNC"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AsyncGuard.pas",
    "lines": [
     490
    ]
   }
  ]
 },
 {
  "id": "dkAsyncCallback",
  "ordinal": 134,
  "label": "Async Callback Detect",
  "category": "ASYNC",
  "sourceUnits": [
   "Cozy.NHW.AsyncGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.AsyncGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ASYNC"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AsyncGuard.pas",
    "lines": [
     397,
     417
    ]
   }
  ]
 },
 {
  "id": "dkThreadpool",
  "ordinal": 135,
  "label": "Threadpool Detect",
  "category": "ASYNC",
  "sourceUnits": [
   "Cozy.NHW.AsyncGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.AsyncGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ASYNC"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AsyncGuard.pas",
    "lines": [
     438
    ]
   }
  ]
 },
 {
  "id": "dkAsyncBurst",
  "ordinal": 136,
  "label": "Async Burst Detect",
  "category": "ASYNC",
  "sourceUnits": [
   "Cozy.NHW.AsyncGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.AsyncGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ASYNC"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AsyncGuard.pas",
    "lines": [
     461
    ]
   }
  ]
 },
 {
  "id": "dkAsyncCorrelation",
  "ordinal": 137,
  "label": "Async Correlation Detect",
  "category": "ASYNC",
  "sourceUnits": [
   "Cozy.NHW.AsyncGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.AsyncGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "ASYNC"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.AsyncGuard.pas",
    "lines": [
     535
    ]
   }
  ]
 },
 {
  "id": "dkPEHeader",
  "ordinal": 138,
  "label": "PE Header Detect",
  "category": "PE_IMAGE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PELoader"
  ],
  "producerUnits": [
   "Cozy.NHW.PELoader"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_IMAGE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PELoader.pas",
    "lines": [
     123
    ]
   }
  ]
 },
 {
  "id": "dkSectionMapping",
  "ordinal": 139,
  "label": "Section Mapping Detect",
  "category": "PE_IMAGE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PELoader"
  ],
  "producerUnits": [
   "Cozy.NHW.PELoader"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_IMAGE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PELoader.pas",
    "lines": [
     125
    ]
   }
  ]
 },
 {
  "id": "dkRelocation",
  "ordinal": 140,
  "label": "Relocation Detect",
  "category": "PE_IMAGE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PELoader"
  ],
  "producerUnits": [
   "Cozy.NHW.PELoader"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_IMAGE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PELoader.pas",
    "lines": [
     127
    ]
   }
  ]
 },
 {
  "id": "dkTLSDirectory",
  "ordinal": 141,
  "label": "TLS Directory Detect",
  "category": "PE_IMAGE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PELoader",
   "Cozy.NHW.TLSCallbackIntegrity"
  ],
  "producerUnits": [
   "Cozy.NHW.PELoader"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_IMAGE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PELoader.pas",
    "lines": [
     129
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.TLSCallbackIntegrity.pas",
    "lines": [
     305
    ]
   }
  ]
 },
 {
  "id": "dkLoadConfig",
  "ordinal": 142,
  "label": "Load Config Detect",
  "category": "PE_IMAGE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PELoader"
  ],
  "producerUnits": [
   "Cozy.NHW.PELoader"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_IMAGE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PELoader.pas",
    "lines": [
     131
    ]
   }
  ]
 },
 {
  "id": "dkDirectoryBounds",
  "ordinal": 143,
  "label": "Directory Bounds Detect",
  "category": "PE_IMAGE",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PELoader"
  ],
  "producerUnits": [
   "Cozy.NHW.PELoader"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_IMAGE"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PELoader.pas",
    "lines": [
     133
    ]
   }
  ]
 },
 {
  "id": "dkExportTable",
  "ordinal": 144,
  "label": "Export Table Detect",
  "category": "PE_EXPORT",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExportGuard",
   "Cozy.NHW.ImportRedirection",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ExportGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_EXPORT"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExportGuard.pas",
    "lines": [
     112
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ImportRedirection.pas",
    "lines": [
     316
    ]
   }
  ]
 },
 {
  "id": "dkExportForwarder",
  "ordinal": 145,
  "label": "Export Forwarder Detect",
  "category": "PE_EXPORT",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExportGuard",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ExportGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_EXPORT"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExportGuard.pas",
    "lines": [
     113
    ]
   }
  ]
 },
 {
  "id": "dkAPISet",
  "ordinal": 146,
  "label": "API Set Detect",
  "category": "PE_EXPORT",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExportGuard",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ExportGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_EXPORT"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExportGuard.pas",
    "lines": [
     114
    ]
   }
  ]
 },
 {
  "id": "dkDelayImport",
  "ordinal": 147,
  "label": "Delay Import Detect",
  "category": "PE_EXPORT",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExportGuard",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ExportGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_EXPORT"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExportGuard.pas",
    "lines": [
     115
    ]
   }
  ]
 },
 {
  "id": "dkExportTarget",
  "ordinal": 148,
  "label": "Export Target Detect",
  "category": "PE_EXPORT",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExportGuard",
   "Cozy.NHW.ImportRedirection",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ExportGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_EXPORT"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExportGuard.pas",
    "lines": [
     116
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ImportRedirection.pas",
    "lines": [
     316
    ]
   }
  ]
 },
 {
  "id": "dkResolution",
  "ordinal": 149,
  "label": "Resolution Detect",
  "category": "PE_EXPORT",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExportGuard",
   "Cozy.NHW.ImportRedirection",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ExportGuard"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "PE_EXPORT"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExportGuard.pas",
    "lines": [
     118
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ImportRedirection.pas",
    "lines": [
     317
    ]
   }
  ]
 },
 {
  "id": "dkMultiSignal",
  "ordinal": 150,
  "label": "Multi-Signal Detect",
  "category": "EXECUTION_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SignalCorrelation"
  ],
  "producerUnits": [
   "Cozy.NHW.SignalCorrelation"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXECUTION_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     140
    ]
   }
  ]
 },
 {
  "id": "dkPECodeIntegrity",
  "ordinal": 151,
  "label": "PE Code Integrity Detect",
  "category": "EXECUTION_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.APCStyleEvidence",
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExecutableLifecycle",
   "Cozy.NHW.ImageCOWIntegrity",
   "Cozy.NHW.ImportRedirection",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.InjectionEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.PECodeIntegrity",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SectionBackingIdentity",
   "Cozy.NHW.SensorConsensus",
   "Cozy.NHW.SignalCorrelation",
   "Cozy.NHW.TLSCallbackIntegrity",
   "Cozy.NHW.ThreadTimeline",
   "Cozy.NHW.UnwindConsistency"
  ],
  "producerUnits": [
   "Cozy.NHW.PECodeIntegrity"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXECUTION_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": true,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.APCStyleEvidence.pas",
    "lines": [
     42
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     64
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1711,
     1981,
     2651,
     2703,
     2721
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExecutableLifecycle.pas",
    "lines": [
     339
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ImageCOWIntegrity.pas",
    "lines": [
     328
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ImportRedirection.pas",
    "lines": [
     317
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     70
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.InjectionEvidence.pas",
    "lines": [
     105
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.PECodeIntegrity.pas",
    "lines": [
     233
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     101
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SectionBackingIdentity.pas",
    "lines": [
     437
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     70
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     117
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.TLSCallbackIntegrity.pas",
    "lines": [
     306
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadTimeline.pas",
    "lines": [
     311
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.UnwindConsistency.pas",
    "lines": [
     110
    ]
   }
  ]
 },
 {
  "id": "dkPrivateExecRegion",
  "ordinal": 152,
  "label": "Private Executable Region Detect",
  "category": "EXECUTION_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.APCStyleEvidence",
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.InjectionEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RegionClassifier",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus",
   "Cozy.NHW.SignalCorrelation",
   "Cozy.NHW.ThreadTimeline"
  ],
  "producerUnits": [
   "Cozy.NHW.RegionClassifier"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXECUTION_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.APCStyleEvidence.pas",
    "lines": [
     43
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     65
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1712,
     2651
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     71
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.InjectionEvidence.pas",
    "lines": [
     105
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RegionClassifier.pas",
    "lines": [
     269
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     103
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     71
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SignalCorrelation.pas",
    "lines": [
     118
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadTimeline.pas",
    "lines": [
     312
    ]
   }
  ]
 },
 {
  "id": "dkETWImageFusion",
  "ordinal": 153,
  "label": "ETW Image Correlation Detect",
  "category": "EXECUTION_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.ETWImageFusion",
   "Cozy.NHW.Engine",
   "Cozy.NHW.InjectionEvidence",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ETWImageFusion"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXECUTION_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETWImageFusion.pas",
    "lines": [
     112
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1712
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.InjectionEvidence.pas",
    "lines": [
     106
    ]
   }
  ]
 },
 {
  "id": "dkInjectionEvidence",
  "ordinal": 154,
  "label": "Injection Evidence Detect",
  "category": "EXECUTION_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.InjectionEvidence",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.InjectionEvidence"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXECUTION_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": true,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1982,
     2701,
     2719
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.InjectionEvidence.pas",
    "lines": [
     117
    ]
   }
  ]
 },
 {
  "id": "dkExecutionProvenance",
  "ordinal": 155,
  "label": "Execution Provenance Detect",
  "category": "EXECUTION_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExecutableLifecycle",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ModuleOriginVerification",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus",
   "Cozy.NHW.ThreadExecutionProvenance",
   "Cozy.NHW.ThreadStackProvenance"
  ],
  "producerUnits": [
   "Cozy.NHW.ThreadExecutionProvenance"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXECUTION_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     74
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1711,
     2649
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExecutableLifecycle.pas",
    "lines": [
     338
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     76
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ModuleOriginVerification.pas",
    "lines": [
     446
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     98
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     68
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadExecutionProvenance.pas",
    "lines": [
     254
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadStackProvenance.pas",
    "lines": [
     202
    ]
   }
  ]
 },
 {
  "id": "dkImageCOWIntegrity",
  "ordinal": 156,
  "label": "Image COW Detect",
  "category": "EXECUTION_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.APCStyleEvidence",
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExecutableLifecycle",
   "Cozy.NHW.ImageCOWIntegrity",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SectionBackingIdentity",
   "Cozy.NHW.SectionCorrelation",
   "Cozy.NHW.SensorConsensus",
   "Cozy.NHW.ThreadTimeline",
   "Cozy.NHW.UnwindConsistency"
  ],
  "producerUnits": [
   "Cozy.NHW.ImageCOWIntegrity"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXECUTION_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": true,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.APCStyleEvidence.pas",
    "lines": [
     43
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     64
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1981,
     2652,
     2703,
     2721
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExecutableLifecycle.pas",
    "lines": [
     339
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ImageCOWIntegrity.pas",
    "lines": [
     352
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     70
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     101
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SectionBackingIdentity.pas",
    "lines": [
     438
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SectionCorrelation.pas",
    "lines": [
     187
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     71
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadTimeline.pas",
    "lines": [
     311
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.UnwindConsistency.pas",
    "lines": [
     110
    ]
   }
  ]
 },
 {
  "id": "dkTemporalHandleGraph",
  "ordinal": 157,
  "label": "Temporal Handle Graph Detect",
  "category": "EXECUTION_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus",
   "Cozy.NHW.TemporalHandleGraph"
  ],
  "producerUnits": [
   "Cozy.NHW.TemporalHandleGraph"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXECUTION_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     68
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     95
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     65
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.TemporalHandleGraph.pas",
    "lines": [
     162
    ]
   }
  ]
 },
 {
  "id": "dkModuleOrigin",
  "ordinal": 158,
  "label": "Module Origin Detect",
  "category": "EXECUTION_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ModuleOriginVerification",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SectionBackingIdentity",
   "Cozy.NHW.SensorConsensus"
  ],
  "producerUnits": [
   "Cozy.NHW.ModuleOriginVerification"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EXECUTION_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1982,
     2652
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     79
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ModuleOriginVerification.pas",
    "lines": [
     423
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     105
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SectionBackingIdentity.pas",
    "lines": [
     437
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     74
    ]
   }
  ]
 },
 {
  "id": "dkETWLoss",
  "ordinal": 159,
  "label": "ETW Loss / Coverage Warning",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.ETWLossHealth",
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ETWLossHealth"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "UNKNOWN",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ETWLossHealth.pas",
    "lines": [
     181
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1123
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     84
    ]
   }
  ]
 },
 {
  "id": "dkImportRedirect",
  "ordinal": 160,
  "label": "Import Redirect Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExplainableEvidence",
   "Cozy.NHW.FalsePositiveControl",
   "Cozy.NHW.ImportRedirection",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.IndirectTargets",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.ThreadTimeline"
  ],
  "producerUnits": [
   "Cozy.NHW.ImportRedirection"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": true,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     66
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1983,
     2702,
     2720
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExplainableEvidence.pas",
    "lines": [
     63
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FalsePositiveControl.pas",
    "lines": [
     44
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ImportRedirection.pas",
    "lines": [
     358
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     72
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IndirectTargets.pas",
    "lines": [
     181
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     103
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadTimeline.pas",
    "lines": [
     313
    ]
   }
  ]
 },
 {
  "id": "dkTLSCallbackIntegrity",
  "ordinal": 161,
  "label": "TLS Callback Integrity Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExplainableEvidence",
   "Cozy.NHW.FalsePositiveControl",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.IndirectTargets",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.TLSCallbackIntegrity"
  ],
  "producerUnits": [
   "Cozy.NHW.TLSCallbackIntegrity"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": true,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     66
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     1982,
     2703,
     2720
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExplainableEvidence.pas",
    "lines": [
     64
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FalsePositiveControl.pas",
    "lines": [
     44
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     72
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IndirectTargets.pas",
    "lines": [
     181
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     102
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.TLSCallbackIntegrity.pas",
    "lines": [
     347
    ]
   }
  ]
 },
 {
  "id": "dkUnwindStructural",
  "ordinal": 162,
  "label": "Unwind Structural Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExplainableEvidence",
   "Cozy.NHW.FalsePositiveControl",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.UnwindConsistency"
  ],
  "producerUnits": [
   "Cozy.NHW.UnwindConsistency"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     67
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExplainableEvidence.pas",
    "lines": [
     61
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FalsePositiveControl.pas",
    "lines": [
     45
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.UnwindConsistency.pas",
    "lines": [
     173
    ]
   }
  ]
 },
 {
  "id": "dkExecutableLifecycle",
  "ordinal": 163,
  "label": "Executable Lifecycle Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.APCStyleEvidence",
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExecutableLifecycle",
   "Cozy.NHW.ExplainableEvidence",
   "Cozy.NHW.FalsePositiveControl",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus",
   "Cozy.NHW.ThreadStackProvenance",
   "Cozy.NHW.ThreadTimeline"
  ],
  "producerUnits": [
   "Cozy.NHW.ExecutableLifecycle"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.APCStyleEvidence.pas",
    "lines": [
     43
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     65
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExecutableLifecycle.pas",
    "lines": [
     270
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExplainableEvidence.pas",
    "lines": [
     65
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FalsePositiveControl.pas",
    "lines": [
     45
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     71
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     102
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     72
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadStackProvenance.pas",
    "lines": [
     203
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadTimeline.pas",
    "lines": [
     312
    ]
   }
  ]
 },
 {
  "id": "dkSectionBacking",
  "ordinal": 164,
  "label": "Section Backing Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExplainableEvidence",
   "Cozy.NHW.FalsePositiveControl",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SectionBackingIdentity",
   "Cozy.NHW.SectionCorrelation",
   "Cozy.NHW.SensorConsensus"
  ],
  "producerUnits": [
   "Cozy.NHW.SectionBackingIdentity"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     67
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExplainableEvidence.pas",
    "lines": [
     66
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FalsePositiveControl.pas",
    "lines": [
     45
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     79
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     105
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SectionBackingIdentity.pas",
    "lines": [
     391
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SectionCorrelation.pas",
    "lines": [
     186
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     75
    ]
   }
  ]
 },
 {
  "id": "dkThreadStackOrigin",
  "ordinal": 165,
  "label": "Thread Stack Origin Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExplainableEvidence",
   "Cozy.NHW.FalsePositiveControl",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.ThreadStackProvenance"
  ],
  "producerUnits": [
   "Cozy.NHW.ThreadStackProvenance"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExplainableEvidence.pas",
    "lines": [
     67
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FalsePositiveControl.pas",
    "lines": [
     46
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     98
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadStackProvenance.pas",
    "lines": [
     222
    ]
   }
  ]
 },
 {
  "id": "dkCoverageGap",
  "ordinal": 166,
  "label": "Coverage Gap Warning",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.CoverageWindow",
   "Cozy.NHW.Engine",
   "Cozy.NHW.ExplainableEvidence",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.CoverageWindow"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "UNKNOWN",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CoverageWindow.pas",
    "lines": [
     135
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ExplainableEvidence.pas",
    "lines": [
     68
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     84
    ]
   }
  ]
 },
 {
  "id": "dkProcessSnapshot",
  "ordinal": 167,
  "label": "Process Snapshot Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ProcessSnapshot"
  ],
  "producerUnits": [
   "Cozy.NHW.ProcessSnapshot"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ProcessSnapshot.pas",
    "lines": [
     296
    ]
   }
  ]
 },
 {
  "id": "dkLoaderCrossView",
  "ordinal": 168,
  "label": "Loader Cross-View Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.LoaderCrossView",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus"
  ],
  "producerUnits": [
   "Cozy.NHW.LoaderCrossView"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     80
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.LoaderCrossView.pas",
    "lines": [
     364
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     107
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     74
    ]
   }
  ]
 },
 {
  "id": "dkFileAttestation",
  "ordinal": 169,
  "label": "File Attestation Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.FileAttestation",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence",
   "Cozy.NHW.SensorConsensus"
  ],
  "producerUnits": [
   "Cozy.NHW.FileAttestation"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.FileAttestation.pas",
    "lines": [
     188
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     80
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     106
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     75
    ]
   }
  ]
 },
 {
  "id": "dkControlFlow",
  "ordinal": 170,
  "label": "Control Flow Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.APCStyleEvidence",
   "Cozy.NHW.ControlFlowAttestation",
   "Cozy.NHW.Engine",
   "Cozy.NHW.IndirectTargets",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.ControlFlowAttestation"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.APCStyleEvidence.pas",
    "lines": [
     44
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ControlFlowAttestation.pas",
    "lines": [
     153
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IndirectTargets.pas",
    "lines": [
     181
    ]
   }
  ]
 },
 {
  "id": "dkSnapshotETW",
  "ordinal": 171,
  "label": "Snapshot ETW Mismatch Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SnapshotETWReconcile"
  ],
  "producerUnits": [
   "Cozy.NHW.SnapshotETWReconcile"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SnapshotETWReconcile.pas",
    "lines": [
     247
    ]
   }
  ]
 },
 {
  "id": "dkObserverMismatch",
  "ordinal": 172,
  "label": "Observer Mismatch Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.DualObserver",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.DualObserver"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.DualObserver.pas",
    "lines": [
     299
    ]
   }
  ]
 },
 {
  "id": "dkEvidenceIntegrity",
  "ordinal": 173,
  "label": "Evidence Integrity Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.Engine"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     2624
    ]
   }
  ]
 },
 {
  "id": "dkRiskConfidence",
  "ordinal": 174,
  "label": "Risk Correlation Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.RiskConfidence"
  ],
  "producerUnits": [
   "Cozy.NHW.RiskConfidence"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.RiskConfidence.pas",
    "lines": [
     132
    ]
   }
  ]
 },
 {
  "id": "dkCausalSequence",
  "ordinal": 175,
  "label": "Causal Sequence Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.CausalGraph"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     155
    ]
   }
  ]
 },
 {
  "id": "dkCodeProvenance",
  "ordinal": 176,
  "label": "Code Provenance Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.APCStyleEvidence",
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.CodeProvenanceGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ThreadTimeline"
  ],
  "producerUnits": [
   "Cozy.NHW.CodeProvenanceGraph"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.APCStyleEvidence.pas",
    "lines": [
     44
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     68
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CodeProvenanceGraph.pas",
    "lines": [
     190
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     72
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadTimeline.pas",
    "lines": [
     313
    ]
   }
  ]
 },
 {
  "id": "dkSectionCorrelation",
  "ordinal": 177,
  "label": "Section Correlation Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SectionCorrelation"
  ],
  "producerUnits": [
   "Cozy.NHW.SectionCorrelation"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     68
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     81
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SectionCorrelation.pas",
    "lines": [
     258
    ]
   }
  ]
 },
 {
  "id": "dkIndirectTarget",
  "ordinal": 178,
  "label": "Indirect Target Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.IndirectTargets",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.IndirectTargets"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     73
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IndirectTargets.pas",
    "lines": [
     166
    ]
   }
  ]
 },
 {
  "id": "dkThreadTimeline",
  "ordinal": 179,
  "label": "Thread Timeline Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.CausalGraph",
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.SensorConsensus",
   "Cozy.NHW.ThreadTimeline"
  ],
  "producerUnits": [
   "Cozy.NHW.ThreadTimeline"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CausalGraph.pas",
    "lines": [
     75
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     76
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorConsensus.pas",
    "lines": [
     68
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ThreadTimeline.pas",
    "lines": [
     288
    ]
   }
  ]
 },
 {
  "id": "dkObservationUncertain",
  "ordinal": 180,
  "label": "Observation Uncertain",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ObservationTrust",
   "Cozy.NHW.SensorRecovery",
   "Cozy.NHW.SensorTamperHealth"
  ],
  "producerUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.ObservationTrust",
   "Cozy.NHW.SensorRecovery",
   "Cozy.NHW.SensorTamperHealth"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "UNKNOWN",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     2690,
     2872
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     85
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ObservationTrust.pas",
    "lines": [
     125
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorRecovery.pas",
    "lines": [
     136
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SensorTamperHealth.pas",
    "lines": [
     175
    ]
   }
  ]
 },
 {
  "id": "dkSensorPressure",
  "ordinal": 181,
  "label": "Sensor Pressure Warning",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ResourceController"
  ],
  "producerUnits": [
   "Cozy.NHW.ResourceController"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "UNKNOWN",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     85
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResourceController.pas",
    "lines": [
     129
    ]
   }
  ]
 },
 {
  "id": "dkIncidentReconstruction",
  "ordinal": 182,
  "label": "Incident Correlation Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.IncidentReconstruction",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.IncidentReconstruction"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.IncidentReconstruction.pas",
    "lines": [
     181
    ]
   }
  ]
 },
 {
  "id": "dkHandleSharingEvidence",
  "ordinal": 183,
  "label": "Handle Sharing Evidence Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.HandleSharingEvidence",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.HandleSharingEvidence"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.HandleSharingEvidence.pas",
    "lines": [
     323
    ]
   }
  ]
 },
 {
  "id": "dkAPCStyleEvidence",
  "ordinal": 184,
  "label": "APC-Style Evidence Detect",
  "category": "EVIDENCE_CORRELATION",
  "sourceUnits": [
   "Cozy.NHW.APCStyleEvidence",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust"
  ],
  "producerUnits": [
   "Cozy.NHW.APCStyleEvidence"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "EVIDENCE_CORRELATION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.APCStyleEvidence.pas",
    "lines": [
     110
    ]
   }
  ]
 },
 {
  "id": "dkBootTrust",
  "ordinal": 185,
  "label": "Boot Trust Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.BootTrust",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Trust",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.BootTrust"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_BOOT"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.BootTrust.pas",
    "lines": [
     102
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     58,
     85
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Trust.pas",
    "lines": [
     60
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     88
    ]
   }
  ]
 },
 {
  "id": "dkVBSHVCI",
  "ordinal": 186,
  "label": "VBS HVCI Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Trust",
   "Cozy.NHW.SessionTrustLadder",
   "Cozy.NHW.VBSHVCI"
  ],
  "producerUnits": [
   "Cozy.NHW.VBSHVCI"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_BOOT"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     58,
     85
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Trust.pas",
    "lines": [
     60
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     88
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.VBSHVCI.pas",
    "lines": [
     105
    ]
   }
  ]
 },
 {
  "id": "dkVulnerableDriver",
  "ordinal": 187,
  "label": "Vulnerable Driver Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.ClientGuard",
   "Cozy.NHW.CodeIntegrityEventCorrelation",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelMappingEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Driver",
   "Cozy.NHW.ResponseTransport",
   "Cozy.NHW.SessionTrustLadder",
   "Cozy.NHW.VulnerableDriver"
  ],
  "producerUnits": [
   "Cozy.NHW.VulnerableDriver"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_DRIVER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": true,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ClientGuard.pas",
    "lines": [
     88,
     115,
     143
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CodeIntegrityEventCorrelation.pas",
    "lines": [
     79
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     426
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelMappingEvidence.pas",
    "lines": [
     86
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     61,
     76
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.pas",
    "lines": [
     494
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Driver.pas",
    "lines": [
     60
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponseTransport.pas",
    "lines": [
     281
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     91
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.VulnerableDriver.pas",
    "lines": [
     213
    ]
   }
  ]
 },
 {
  "id": "dkDriverIdentity",
  "ordinal": 188,
  "label": "Driver Identity Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.CodeIntegrityEventCorrelation",
   "Cozy.NHW.DriverIdentity",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelMappingEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Driver",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.DriverIdentity"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_VIEW"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CodeIntegrityEventCorrelation.pas",
    "lines": [
     79
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.DriverIdentity.pas",
    "lines": [
     168
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelMappingEvidence.pas",
    "lines": [
     88
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     64,
     83
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Driver.pas",
    "lines": [
     60
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     94
    ]
   }
  ]
 },
 {
  "id": "dkDriverCrossView",
  "ordinal": 189,
  "label": "Driver Cross-View Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.CodeIntegrityEventCorrelation",
   "Cozy.NHW.DriverCrossView",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelMappingEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Driver",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.DriverCrossView"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_VIEW"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CodeIntegrityEventCorrelation.pas",
    "lines": [
     79
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.DriverCrossView.pas",
    "lines": [
     141
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelMappingEvidence.pas",
    "lines": [
     88
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     64,
     83
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.pas",
    "lines": [
     495
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Driver.pas",
    "lines": [
     60
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     94
    ]
   }
  ]
 },
 {
  "id": "dkKernelTrustDowngrade",
  "ordinal": 190,
  "label": "Kernel Trust Downgrade Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.CodeIntegrityEventCorrelation",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelMappingEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.KernelTrustDowngrade",
   "Cozy.NHW.ResponsePath.Trust",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.KernelTrustDowngrade"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_INTEGRITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CodeIntegrityEventCorrelation.pas",
    "lines": [
     80
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelMappingEvidence.pas",
    "lines": [
     90
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     67,
     77
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.pas",
    "lines": [
     431,
     534
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrustDowngrade.pas",
    "lines": [
     124
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Trust.pas",
    "lines": [
     60
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     97
    ]
   }
  ]
 },
 {
  "id": "dkCodeIntegrityPolicy",
  "ordinal": 191,
  "label": "Code Integrity Policy Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.ClientGuard",
   "Cozy.NHW.CodeIntegrityEventCorrelation",
   "Cozy.NHW.CodeIntegrityPolicy",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelMappingEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Integrity",
   "Cozy.NHW.ResponseTransport",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.CodeIntegrityPolicy"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_INTEGRITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": true,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ClientGuard.pas",
    "lines": [
     90,
     117,
     145
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CodeIntegrityEventCorrelation.pas",
    "lines": [
     80
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CodeIntegrityPolicy.pas",
    "lines": [
     247
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     428
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelMappingEvidence.pas",
    "lines": [
     91
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     67,
     89
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Integrity.pas",
    "lines": [
     60
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponseTransport.pas",
    "lines": [
     283
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     97
    ]
   }
  ]
 },
 {
  "id": "dkDriverTimelineKernel",
  "ordinal": 192,
  "label": "Driver Timeline Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.ClientGuard",
   "Cozy.NHW.CodeIntegrityEventCorrelation",
   "Cozy.NHW.DriverTimeline",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelMappingEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Driver",
   "Cozy.NHW.ResponseTransport",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.DriverTimeline"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_DRIVER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": true,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ClientGuard.pas",
    "lines": [
     88,
     115,
     143
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CodeIntegrityEventCorrelation.pas",
    "lines": [
     80
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.DriverTimeline.pas",
    "lines": [
     128
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     427
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelMappingEvidence.pas",
    "lines": [
     87
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     61,
     88
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Driver.pas",
    "lines": [
     61
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponseTransport.pas",
    "lines": [
     282
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     91
    ]
   }
  ]
 },
 {
  "id": "dkSystemViewDisagreement",
  "ordinal": 193,
  "label": "System View Disagreement Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.CodeIntegrityEventCorrelation",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelMappingEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Driver",
   "Cozy.NHW.SessionTrustLadder",
   "Cozy.NHW.SystemViewDisagreement"
  ],
  "producerUnits": [
   "Cozy.NHW.SystemViewDisagreement"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_VIEW"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CodeIntegrityEventCorrelation.pas",
    "lines": [
     81
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelMappingEvidence.pas",
    "lines": [
     89
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     65,
     84
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.pas",
    "lines": [
     496,
     536
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Driver.pas",
    "lines": [
     61
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     95
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SystemViewDisagreement.pas",
    "lines": [
     195
    ]
   }
  ]
 },
 {
  "id": "dkKernelMappingEvidence",
  "ordinal": 194,
  "label": "Kernel Mapping Evidence Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.ClientGuard",
   "Cozy.NHW.CodeIntegrityEventCorrelation",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelMappingEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Driver",
   "Cozy.NHW.ResponseTransport",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.KernelMappingEvidence"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_MAPPING"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": true,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ClientGuard.pas",
    "lines": [
     88,
     115,
     143
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CodeIntegrityEventCorrelation.pas",
    "lines": [
     81
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     427
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelMappingEvidence.pas",
    "lines": [
     125
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     70,
     75
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.pas",
    "lines": [
     521,
     535
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Driver.pas",
    "lines": [
     62
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponseTransport.pas",
    "lines": [
     282
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     101
    ]
   }
  ]
 },
 {
  "id": "dkBootAttestationContinuity",
  "ordinal": 195,
  "label": "Boot Attestation Continuity Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.BootAttestationContinuity",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Trust",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.BootAttestationContinuity"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_BOOT"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.BootAttestationContinuity.pas",
    "lines": [
     116
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     58,
     85
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Trust.pas",
    "lines": [
     61
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     88
    ]
   }
  ]
 },
 {
  "id": "dkCodeIntegrityEventCorrelation",
  "ordinal": 196,
  "label": "Code Integrity Event Correlation Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.CodeIntegrityEventCorrelation",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelMappingEvidence",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Integrity",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.CodeIntegrityEventCorrelation"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_INTEGRITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.CodeIntegrityEventCorrelation.pas",
    "lines": [
     144
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelMappingEvidence.pas",
    "lines": [
     92
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     68,
     78
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.pas",
    "lines": [
     537
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Integrity.pas",
    "lines": [
     60
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     98
    ]
   }
  ]
 },
 {
  "id": "dkKernelTelemetryGap",
  "ordinal": 197,
  "label": "Kernel Telemetry Gap Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.ClientGuard",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTelemetryGap",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Integrity",
   "Cozy.NHW.ResponseTransport",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.KernelTelemetryGap"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_TELEMETRY"
  ],
  "signalClass": "UNKNOWN",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": true,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ClientGuard.pas",
    "lines": [
     87,
     114,
     142
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     426
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTelemetryGap.pas",
    "lines": [
     144
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     72,
     81
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Integrity.pas",
    "lines": [
     61
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponseTransport.pas",
    "lines": [
     281
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     102
    ]
   }
  ]
 },
 {
  "id": "dkSessionTrustUntrusted",
  "ordinal": 198,
  "label": "Session Trust Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.ResponsePath.Integrity",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.SessionTrustLadder"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_SESSION"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Integrity.pas",
    "lines": [
     61
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     178
    ]
   }
  ]
 },
 {
  "id": "dkDriverLoadProvenance",
  "ordinal": 199,
  "label": "Driver Load Provenance Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.ClientGuard",
   "Cozy.NHW.DriverLoadProvenance",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Driver",
   "Cozy.NHW.ResponseTransport",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.DriverLoadProvenance"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_DRIVER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": true,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ClientGuard.pas",
    "lines": [
     89,
     116,
     144
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.DriverLoadProvenance.pas",
    "lines": [
     118
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     428
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     62,
     88
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Driver.pas",
    "lines": [
     62
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponseTransport.pas",
    "lines": [
     283
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     92
    ]
   }
  ]
 },
 {
  "id": "dkDriverSignerAttestation",
  "ordinal": 200,
  "label": "Driver Signer Attestation Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.ClientGuard",
   "Cozy.NHW.DriverSignerAttestation",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Driver",
   "Cozy.NHW.ResponsePath.Integrity",
   "Cozy.NHW.ResponseTransport",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.DriverSignerAttestation"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_INTEGRITY"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": true,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ClientGuard.pas",
    "lines": [
     89,
     116,
     144
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.DriverSignerAttestation.pas",
    "lines": [
     141
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     427
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     68,
     79
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Driver.pas",
    "lines": [
     63
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Integrity.pas",
    "lines": [
     62
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponseTransport.pas",
    "lines": [
     282
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     98
    ]
   }
  ]
 },
 {
  "id": "dkDriverServiceTimeline",
  "ordinal": 201,
  "label": "Driver Service Timeline Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.ClientGuard",
   "Cozy.NHW.DriverServiceTimeline",
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Driver",
   "Cozy.NHW.ResponseTransport",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.DriverServiceTimeline"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_DRIVER"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": true,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ClientGuard.pas",
    "lines": [
     90,
     117,
     145
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.DriverServiceTimeline.pas",
    "lines": [
     165
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.Engine.pas",
    "lines": [
     428
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     62,
     80
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Driver.pas",
    "lines": [
     63
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponseTransport.pas",
    "lines": [
     283
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     92
    ]
   }
  ]
 },
 {
  "id": "dkHypervisorVBSCrossView",
  "ordinal": 202,
  "label": "Hypervisor VBS Cross-View Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.HypervisorVBSCrossView",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Trust",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.HypervisorVBSCrossView"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_BOOT"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.HypervisorVBSCrossView.pas",
    "lines": [
     112
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     59,
     86
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Trust.pas",
    "lines": [
     61
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     89
    ]
   }
  ]
 },
 {
  "id": "dkKernelDMAIOMMUTrust",
  "ordinal": 203,
  "label": "Kernel DMA IOMMU Trust Detect",
  "category": "KERNEL_TRUST",
  "sourceUnits": [
   "Cozy.NHW.Engine",
   "Cozy.NHW.KernelDMAIOMMUTrust",
   "Cozy.NHW.KernelTrust",
   "Cozy.NHW.KernelTrust.CorrelationPolicy",
   "Cozy.NHW.ResponsePath.Integrity",
   "Cozy.NHW.ResponsePath.Trust",
   "Cozy.NHW.SessionTrustLadder"
  ],
  "producerUnits": [
   "Cozy.NHW.KernelDMAIOMMUTrust"
  ],
  "productionEmission": "SOURCE_EMITTER_PRESENT",
  "responsePaths": [
   "Trust",
   "Driver",
   "Integrity"
  ],
  "evidenceFamilies": [
   "KERNEL_BOOT"
  ],
  "signalClass": "CORROBORATION_REQUIRED",
  "strongExecutionCandidate": false,
  "localOnlyKernelPolicy": false,
  "sourceReferences": [
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelDMAIOMMUTrust.pas",
    "lines": [
     91
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.KernelTrust.CorrelationPolicy.pas",
    "lines": [
     59,
     86
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Integrity.pas",
    "lines": [
     62
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.ResponsePath.Trust.pas",
    "lines": [
     62
    ]
   },
   {
    "path": "Cozy.Source/Cozy.Security.NHW/Cozy.NHW.SessionTrustLadder.pas",
    "lines": [
     99
    ]
   }
  ]
 }
].map(NHWMetadata));
const COZY = Object.freeze([
 {
  "id": "IMAGE_DIGEST_MISMATCH",
  "label": "IMAGE DIGEST MISMATCH",
  "category": "IMAGE_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "IMAGE_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     295
    ]
   }
  ]
 },
 {
  "id": "CODE_HASH_MISMATCH",
  "label": "CODE HASH MISMATCH",
  "category": "IMAGE_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "IMAGE_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     274
    ]
   }
  ]
 },
 {
  "id": "FILE_HASH_MISMATCH",
  "label": "FILE HASH MISMATCH",
  "category": "IMAGE_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "IMAGE_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     274
    ]
   }
  ]
 },
 {
  "id": "CODE_EXTENDED_HASH_MISMATCH",
  "label": "CODE EXTENDED HASH MISMATCH",
  "category": "IMAGE_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "IMAGE_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     274
    ]
   }
  ]
 },
 {
  "id": "FILE_EXTENDED_HASH_MISMATCH",
  "label": "FILE EXTENDED HASH MISMATCH",
  "category": "IMAGE_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "IMAGE_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     274
    ]
   }
  ]
 },
 {
  "id": "KNOWN_MODULE_CODE_MISMATCH",
  "label": "KNOWN MODULE CODE MISMATCH",
  "category": "IMAGE_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "IMAGE_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     193,
     283
    ]
   }
  ]
 },
 {
  "id": "REQUIRED_MODULE_CODE_MISMATCH",
  "label": "REQUIRED MODULE CODE MISMATCH",
  "category": "IMAGE_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "IMAGE_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     369
    ]
   }
  ]
 },
 {
  "id": "POINTER_GRAPH_MISMATCH",
  "label": "POINTER GRAPH MISMATCH",
  "category": "IMAGE_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "IMAGE_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.pointer-graph-contract.js",
    "lines": [
     65
    ]
   }
  ]
 },
 {
  "id": "RUNTIME_GRAPH_PROFILE_MISMATCH",
  "label": "RUNTIME GRAPH PROFILE MISMATCH",
  "category": "IMAGE_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "IMAGE_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.owned-runtime-graph-contract.js",
    "lines": [
     46
    ]
   }
  ]
 },
 {
  "id": "CRC_ROLE_MISMATCH",
  "label": "CRC ROLE MISMATCH",
  "category": "CRC_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "CRC_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/runtime/peace.desktop-crc-policy.js",
    "lines": [
     27
    ]
   }
  ]
 },
 {
  "id": "NOT_MEASURED",
  "label": "NOT MEASURED",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     96
    ]
   },
   {
    "path": "services/integrity/peace.measurement-status.js",
    "lines": [
     2
    ]
   }
  ]
 },
 {
  "id": "READ_ERROR",
  "label": "READ ERROR",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     90,
     97,
     274,
     366,
     369
    ]
   },
   {
    "path": "services/integrity/peace.measurement-status.js",
    "lines": [
     2,
     7,
     8
    ]
   },
   {
    "path": "services/runtime/peace.desktop-crc-policy.js",
    "lines": [
     13
    ]
   }
  ]
 },
 {
  "id": "FILE_CHANGED",
  "label": "FILE CHANGED",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     90,
     366,
     369
    ]
   },
   {
    "path": "services/integrity/peace.measurement-status.js",
    "lines": [
     2
    ]
   },
   {
    "path": "services/runtime/peace.desktop-crc-policy.js",
    "lines": [
     13
    ]
   }
  ]
 },
 {
  "id": "COVERAGE_INSUFFICIENT",
  "label": "COVERAGE INSUFFICIENT",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     90,
     366,
     369
    ]
   },
   {
    "path": "services/integrity/peace.measurement-status.js",
    "lines": [
     2
    ]
   },
   {
    "path": "services/runtime/peace.desktop-crc-policy.js",
    "lines": [
     13
    ]
   }
  ]
 },
 {
  "id": "CANCELLED",
  "label": "CANCELLED",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     90,
     366,
     369
    ]
   },
   {
    "path": "services/integrity/peace.measurement-status.js",
    "lines": [
     2
    ]
   },
   {
    "path": "services/runtime/peace.desktop-crc-policy.js",
    "lines": [
     13
    ]
   }
  ]
 },
 {
  "id": "DEADLINE_EXCEEDED",
  "label": "DEADLINE EXCEEDED",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     90,
     366,
     369
    ]
   },
   {
    "path": "services/integrity/peace.measurement-status.js",
    "lines": [
     2
    ]
   },
   {
    "path": "services/runtime/peace.desktop-crc-policy.js",
    "lines": [
     13
    ]
   }
  ]
 },
 {
  "id": "MEASUREMENT_FAILED",
  "label": "MEASUREMENT FAILED",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     274
    ]
   }
  ]
 },
 {
  "id": "MEASUREMENT_UNAVAILABLE",
  "label": "MEASUREMENT UNAVAILABLE",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.measurement-status.js",
    "lines": [
     8
    ]
   }
  ]
 },
 {
  "id": "HASH_VERSION_MISMATCH",
  "label": "HASH VERSION MISMATCH",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     293
    ]
   }
  ]
 },
 {
  "id": "CRC_BASELINE_UNAVAILABLE",
  "label": "CRC BASELINE UNAVAILABLE",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     131
    ]
   },
   {
    "path": "services/runtime/peace.desktop-crc-policy.js",
    "lines": [
     23
    ]
   }
  ]
 },
 {
  "id": "CRC_MEASUREMENT_INVALID",
  "label": "CRC MEASUREMENT INVALID",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/runtime/peace.desktop-crc-policy.js",
    "lines": [
     24
    ]
   }
  ]
 },
 {
  "id": "CRC_COVERAGE_INCOMPLETE",
  "label": "CRC COVERAGE INCOMPLETE",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     274
    ]
   },
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     132,
     298
    ]
   }
  ]
 },
 {
  "id": "API_STORAGE_NOT_SEALED",
  "label": "API STORAGE NOT SEALED",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     299
    ]
   }
  ]
 },
 {
  "id": "DYNAMIC_CODE_POLICY_UNAVAILABLE",
  "label": "DYNAMIC CODE POLICY UNAVAILABLE",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     301
    ]
   }
  ]
 },
 {
  "id": "CFG_UNAVAILABLE",
  "label": "CFG UNAVAILABLE",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     302
    ]
   }
  ]
 },
 {
  "id": "BUILD_CONTRACT_REQUIRED",
  "label": "BUILD CONTRACT REQUIRED",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-operations.js",
    "lines": [
     112
    ]
   }
  ]
 },
 {
  "id": "EVIDENCE_VERSION_MISMATCH",
  "label": "EVIDENCE VERSION MISMATCH",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-operations.js",
    "lines": [
     113
    ]
   }
  ]
 },
 {
  "id": "API_SLOT_COUNT_MISMATCH",
  "label": "API SLOT COUNT MISMATCH",
  "category": "MEASUREMENT_HEALTH",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "MEASUREMENT_HEALTH"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-operations.js",
    "lines": [
     114
    ]
   }
  ]
 },
 {
  "id": "POINTER_GRAPH_BUILD_CONTRACT_REQUIRED",
  "label": "POINTER GRAPH BUILD CONTRACT REQUIRED",
  "category": "GRAPH_MEASUREMENT",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "GRAPH_MEASUREMENT"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.pointer-graph-contract.js",
    "lines": [
     62
    ]
   }
  ]
 },
 {
  "id": "POINTER_GRAPH_INCOMPLETE",
  "label": "POINTER GRAPH INCOMPLETE",
  "category": "GRAPH_MEASUREMENT",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "GRAPH_MEASUREMENT"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.pointer-graph-contract.js",
    "lines": [
     63
    ]
   },
   {
    "path": "services/integrity/peace.measurement-plan-contract.js",
    "lines": [
     49
    ]
   }
  ]
 },
 {
  "id": "POINTER_GRAPH_REQUIRED",
  "label": "POINTER GRAPH REQUIRED",
  "category": "GRAPH_MEASUREMENT",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "GRAPH_MEASUREMENT"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.measurement-plan-contract.js",
    "lines": [
     50
    ]
   }
  ]
 },
 {
  "id": "RUNTIME_GRAPH_BUILD_COMPONENT_REQUIRED",
  "label": "RUNTIME GRAPH BUILD COMPONENT REQUIRED",
  "category": "GRAPH_MEASUREMENT",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "GRAPH_MEASUREMENT"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.owned-runtime-graph-contract.js",
    "lines": [
     44
    ]
   }
  ]
 },
 {
  "id": "RUNTIME_GRAPH_INCOMPLETE",
  "label": "RUNTIME GRAPH INCOMPLETE",
  "category": "GRAPH_MEASUREMENT",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "GRAPH_MEASUREMENT"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.owned-runtime-graph-contract.js",
    "lines": [
     45
    ]
   }
  ]
 },
 {
  "id": "RUNTIME_GRAPH_REQUIRED",
  "label": "RUNTIME GRAPH REQUIRED",
  "category": "GRAPH_MEASUREMENT",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "GRAPH_MEASUREMENT"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.owned-runtime-graph-contract.js",
    "lines": [
     9
    ]
   },
   {
    "path": "services/integrity/peace.measurement-plan-contract.js",
    "lines": [
     45
    ]
   }
  ]
 },
 {
  "id": "INTEGRITY_SNAPSHOT_CONFLICT",
  "label": "INTEGRITY SNAPSHOT CONFLICT",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     353
    ]
   }
  ]
 },
 {
  "id": "INTEGRITY_SNAPSHOT_POLICY_CHANGED",
  "label": "INTEGRITY SNAPSHOT POLICY CHANGED",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     354,
     381
    ]
   }
  ]
 },
 {
  "id": "INTEGRITY_SNAPSHOT_DUPLICATE_MODULE",
  "label": "INTEGRITY SNAPSHOT DUPLICATE MODULE",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     358
    ]
   }
  ]
 },
 {
  "id": "INTEGRITY_SNAPSHOT_LIMIT",
  "label": "INTEGRITY SNAPSHOT LIMIT",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     202,
     350,
     361
    ]
   }
  ]
 },
 {
  "id": "INTEGRITY_SNAPSHOT_REQUIRED",
  "label": "INTEGRITY SNAPSHOT REQUIRED",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     381
    ]
   }
  ]
 },
 {
  "id": "INTEGRITY_SNAPSHOT_STALE",
  "label": "INTEGRITY SNAPSHOT STALE",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     381
    ]
   }
  ]
 },
 {
  "id": "INTEGRITY_MEASUREMENT_PLAN_REQUIRED",
  "label": "INTEGRITY MEASUREMENT PLAN REQUIRED",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     381
    ]
   }
  ]
 },
 {
  "id": "MEASUREMENT_PLAN_INCOMPLETE",
  "label": "MEASUREMENT PLAN INCOMPLETE",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     366
    ]
   }
  ]
 },
 {
  "id": "MEASUREMENT_GENERATION_INCOMPLETE",
  "label": "MEASUREMENT GENERATION INCOMPLETE",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     366
    ]
   }
  ]
 },
 {
  "id": "MEASUREMENT_EXPORT_INCOMPLETE",
  "label": "MEASUREMENT EXPORT INCOMPLETE",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     366
    ]
   }
  ]
 },
 {
  "id": "INCOMPLETE_SNAPSHOT",
  "label": "INCOMPLETE SNAPSHOT",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     218,
     367
    ]
   }
  ]
 },
 {
  "id": "INVALID_SNAPSHOT_COUNTS",
  "label": "INVALID SNAPSHOT COUNTS",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     368
    ]
   }
  ]
 },
 {
  "id": "REQUIRED_MODULE_MISSING",
  "label": "REQUIRED MODULE MISSING",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     369
    ]
   }
  ]
 },
 {
  "id": "REQUIRED_MODULE_READ_FAILED",
  "label": "REQUIRED MODULE READ FAILED",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     369
    ]
   }
  ]
 },
 {
  "id": "REQUIRED_MODULE_UNVERIFIED",
  "label": "REQUIRED MODULE UNVERIFIED",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     369
    ]
   }
  ]
 },
 {
  "id": "REQUIRED_MODULE_EXTENDED_UNVERIFIED",
  "label": "REQUIRED MODULE EXTENDED UNVERIFIED",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     369
    ]
   }
  ]
 },
 {
  "id": "SNAPSHOT_TIMEOUT",
  "label": "SNAPSHOT TIMEOUT",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     218
    ]
   }
  ]
 },
 {
  "id": "MEASUREMENT_GENERATION_UNSUPPORTED",
  "label": "MEASUREMENT GENERATION UNSUPPORTED",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     365
    ]
   }
  ]
 },
 {
  "id": "MEASUREMENT_GENERATION_TRACKING_FAILED",
  "label": "MEASUREMENT GENERATION TRACKING FAILED",
  "category": "SNAPSHOT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "SNAPSHOT_POLICY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/integrity/peace.desktop-integrity-reports.js",
    "lines": [
     365
    ]
   }
  ]
 },
 {
  "id": "SECURITY_FRESH_OBSERVATION_REQUIRED",
  "label": "SECURITY FRESH OBSERVATION REQUIRED",
  "category": "SESSION_AUTHORITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Trust",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SESSION_AUTHORITY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     413,
     425
    ]
   }
  ]
 },
 {
  "id": "SECURITY_MEASUREMENT_INCOMPLETE",
  "label": "SECURITY MEASUREMENT INCOMPLETE",
  "category": "SESSION_AUTHORITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Trust",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SESSION_AUTHORITY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     414
    ]
   }
  ]
 },
 {
  "id": "SECURITY_OBSERVATION_INDETERMINATE",
  "label": "SECURITY OBSERVATION INDETERMINATE",
  "category": "SESSION_AUTHORITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Trust",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SESSION_AUTHORITY"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     416
    ]
   }
  ]
 },
 {
  "id": "SECURITY_SESSION_STOP",
  "label": "SECURITY SESSION STOP",
  "category": "SESSION_AUTHORITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Trust",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SESSION_AUTHORITY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     366
    ]
   }
  ]
 },
 {
  "id": "SECURITY_OBSERVATION_MISMATCH",
  "label": "SECURITY OBSERVATION MISMATCH",
  "category": "SESSION_AUTHORITY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-integrity-reports"
  ],
  "responsePaths": [
   "Trust",
   "Integrity"
  ],
  "evidenceFamilies": [
   "SESSION_AUTHORITY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     415
    ]
   }
  ]
 },
 {
  "id": "SECURITY_RELEASE_MISSING",
  "label": "SECURITY RELEASE MISSING",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-security-operations"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     120
    ]
   },
   {
    "path": "services/security/peace.desktop-security-operations.js",
    "lines": [
     96,
     132,
     150
    ]
   }
  ]
 },
 {
  "id": "SECURITY_RELEASE_REVOKED",
  "label": "SECURITY RELEASE REVOKED",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-security-operations"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     121
    ]
   }
  ]
 },
 {
  "id": "SECURITY_RELEASE_COMPONENT",
  "label": "SECURITY RELEASE COMPONENT",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-security-operations"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     122
    ]
   }
  ]
 },
 {
  "id": "SECURITY_RELEASE_VERSION",
  "label": "SECURITY RELEASE VERSION",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-security-operations"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     123
    ]
   }
  ]
 },
 {
  "id": "SECURITY_RELEASE_SIGNATURE",
  "label": "SECURITY RELEASE SIGNATURE",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-security-operations"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     124
    ]
   }
  ]
 },
 {
  "id": "SECURITY_CLIENT_UPGRADE_REQUIRED",
  "label": "SECURITY CLIENT UPGRADE REQUIRED",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-security-operations"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     125
    ]
   },
   {
    "path": "services/security/peace.desktop-security-operations.js",
    "lines": [
     133,
     152
    ]
   }
  ]
 },
 {
  "id": "SECURITY_CFG_BUILD_REQUIRED",
  "label": "SECURITY CFG BUILD REQUIRED",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-security-operations"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-authority.js",
    "lines": [
     126
    ]
   },
   {
    "path": "services/security/peace.desktop-security-operations.js",
    "lines": [
     151
    ]
   }
  ]
 },
 {
  "id": "SECURITY_SIGNER_REVOKED",
  "label": "SECURITY SIGNER REVOKED",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-security-operations"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-operations.js",
    "lines": [
     97
    ]
   }
  ]
 },
 {
  "id": "SECURITY_BUILD_CONTRACT_REQUIRED",
  "label": "SECURITY BUILD CONTRACT REQUIRED",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.desktop-security-authority",
   "peace.desktop-security-operations"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.desktop-security-operations.js",
    "lines": [
     98
    ]
   }
  ]
 },
 {
  "id": "COZY_SERVER_POLICY_NOT_BOUND",
  "label": "COZY SERVER POLICY NOT BOUND",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.server-policy-registry"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.server-policy-registry.js",
    "lines": [
     101
    ]
   }
  ]
 },
 {
  "id": "COZY_SERVER_POLICY_RECORD_MISSING",
  "label": "COZY SERVER POLICY RECORD MISSING",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.server-policy-registry"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.server-policy-registry.js",
    "lines": [
     102
    ]
   }
  ]
 },
 {
  "id": "COZY_SERVER_POLICY_RECORD_MISMATCH",
  "label": "COZY SERVER POLICY RECORD MISMATCH",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.server-policy-registry"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.server-policy-registry.js",
    "lines": [
     105
    ]
   }
  ]
 },
 {
  "id": "COZY_SERVER_POLICY_RECEIPT_REQUIRED",
  "label": "COZY SERVER POLICY RECEIPT REQUIRED",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.server-policy-registry"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.server-policy-registry.js",
    "lines": [
     107
    ]
   }
  ]
 },
 {
  "id": "COZY_SERVER_POLICY_RECORD_INVALID",
  "label": "COZY SERVER POLICY RECORD INVALID",
  "category": "ARTIFACT_POLICY",
  "sourceUnits": [
   "peace.server-policy-registry"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "ARTIFACT_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.server-policy-registry.js",
    "lines": [
     109
    ]
   }
  ]
 },
 {
  "id": "DESKTOP_REVOKED",
  "label": "DESKTOP REVOKED",
  "category": "LICENSE_POLICY",
  "sourceUnits": [
   "peace.desktop-licenses"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "LICENSE_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/licensing/peace.desktop-licenses.js",
    "lines": [
     11,
     177,
     253
    ]
   }
  ]
 },
 {
  "id": "DESKTOP_EXPIRED",
  "label": "DESKTOP EXPIRED",
  "category": "LICENSE_POLICY",
  "sourceUnits": [
   "peace.desktop-licenses"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "LICENSE_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/licensing/peace.desktop-licenses.js",
    "lines": [
     11,
     177,
     253
    ]
   }
  ]
 },
 {
  "id": "DESKTOP_KEY_USED",
  "label": "DESKTOP KEY USED",
  "category": "LICENSE_POLICY",
  "sourceUnits": [
   "peace.desktop-licenses"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "LICENSE_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/licensing/peace.desktop-licenses.js",
    "lines": [
     11,
     126,
     253
    ]
   }
  ]
 },
 {
  "id": "BOOTSTRAP_LICENSE_MISMATCH",
  "label": "BOOTSTRAP LICENSE MISMATCH",
  "category": "LICENSE_POLICY",
  "sourceUnits": [
   "peace.desktop-licenses"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "LICENSE_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/licensing/peace.desktop-licenses.js",
    "lines": [
     179,
     234,
     251,
     252,
     264
    ]
   }
  ]
 },
 {
  "id": "DESKTOP_ACTIVATION_INVALID",
  "label": "DESKTOP ACTIVATION INVALID",
  "category": "LICENSE_POLICY",
  "sourceUnits": [
   "peace.desktop-licenses",
   "peace.desktop-overlay"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "LICENSE_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/licensing/peace.desktop-licenses.js",
    "lines": [
     11,
     173,
     177,
     178,
     233
    ]
   },
   {
    "path": "services/overlay/peace.desktop-overlay.js",
    "lines": [
     33
    ]
   }
  ]
 },
 {
  "id": "DESKTOP_REQUEST_REUSED",
  "label": "DESKTOP REQUEST REUSED",
  "category": "LICENSE_POLICY",
  "sourceUnits": [
   "peace.desktop-licenses"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "LICENSE_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/licensing/peace.desktop-licenses.js",
    "lines": [
     11,
     54,
     123,
     125,
     140,
     232,
     238
    ]
   }
  ]
 },
 {
  "id": "DESKTOP_PROOF_INVALID",
  "label": "DESKTOP PROOF INVALID",
  "category": "LICENSE_POLICY",
  "sourceUnits": [
   "peace.desktop-licenses"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "LICENSE_POLICY"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/licensing/peace.desktop-licenses.js",
    "lines": [
     11,
     148,
     149,
     150,
     151,
     152,
     153,
     218,
     219,
     220,
     221
    ]
   }
  ]
 },
 {
  "id": "DEVICE_IDENTITY_REVOKED",
  "label": "DEVICE IDENTITY REVOKED",
  "category": "DEVICE_ATTESTATION",
  "sourceUnits": [
   "peace.desktop-device-identity"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "DEVICE_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/devices/peace.desktop-device-identity.js",
    "lines": [
     86
    ]
   }
  ]
 },
 {
  "id": "DEVICE_PERSISTENT_PROOF_REQUIRED",
  "label": "DEVICE PERSISTENT PROOF REQUIRED",
  "category": "DEVICE_ATTESTATION",
  "sourceUnits": [
   "peace.desktop-device-identity"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "DEVICE_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/devices/peace.desktop-device-identity.js",
    "lines": [
     86
    ]
   }
  ]
 },
 {
  "id": "DEVICE_TPM_REQUIRED",
  "label": "DEVICE TPM REQUIRED",
  "category": "DEVICE_ATTESTATION",
  "sourceUnits": [
   "peace.desktop-device-identity"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "DEVICE_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/devices/peace.desktop-device-identity.js",
    "lines": [
     59,
     64,
     69,
     83,
     86,
     105
    ]
   }
  ]
 },
 {
  "id": "DEVICE_REQUEST_REUSED",
  "label": "DEVICE REQUEST REUSED",
  "category": "DEVICE_ATTESTATION",
  "sourceUnits": [
   "peace.desktop-device-identity"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "DEVICE_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/devices/peace.desktop-device-identity.js",
    "lines": [
     70,
     78,
     83,
     108
    ]
   }
  ]
 },
 {
  "id": "DEVICE_CHALLENGE_EXPIRED",
  "label": "DEVICE CHALLENGE EXPIRED",
  "category": "DEVICE_ATTESTATION",
  "sourceUnits": [
   "peace.desktop-device-identity"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "DEVICE_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/devices/peace.desktop-device-identity.js",
    "lines": [
     74,
     75,
     78,
     82,
     83,
     85,
     105
    ]
   }
  ]
 },
 {
  "id": "DEVICE_TPM_ACTIVATION_INVALID",
  "label": "DEVICE TPM ACTIVATION INVALID",
  "category": "DEVICE_ATTESTATION",
  "sourceUnits": [
   "peace.desktop-device-identity"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "DEVICE_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/devices/peace.desktop-device-identity.js",
    "lines": [
     85
    ]
   }
  ]
 },
 {
  "id": "DEVICE_PROOF_INVALID",
  "label": "DEVICE PROOF INVALID",
  "category": "DEVICE_ATTESTATION",
  "sourceUnits": [
   "peace.desktop-device-identity"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "DEVICE_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/devices/peace.desktop-device-identity.js",
    "lines": [
     75,
     85
    ]
   }
  ]
 },
 {
  "id": "DEVICE_SESSION_CHANGED",
  "label": "DEVICE SESSION CHANGED",
  "category": "DEVICE_ATTESTATION",
  "sourceUnits": [
   "peace.desktop-device-identity"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "DEVICE_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/devices/peace.desktop-device-identity.js",
    "lines": [
     28,
     82,
     105
    ]
   }
  ]
 },
 {
  "id": "BOOTSTRAP_MACHINE_BINDING_MISMATCH",
  "label": "BOOTSTRAP MACHINE BINDING MISMATCH",
  "category": "SESSION_BINDING",
  "sourceUnits": [
   "peace.desktop-bootstrap"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "SESSION_BINDING"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/bootstrap/peace.desktop-bootstrap.js",
    "lines": [
     286
    ]
   }
  ]
 },
 {
  "id": "FILE_DIGEST_MISMATCH",
  "label": "FILE DIGEST MISMATCH",
  "category": "ARTIFACT_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-bootstrap"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "ARTIFACT_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/bootstrap/peace.desktop-bootstrap.js",
    "lines": [
     296,
     298
    ]
   }
  ]
 },
 {
  "id": "CODE_DIGEST_MISMATCH",
  "label": "CODE DIGEST MISMATCH",
  "category": "ARTIFACT_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-bootstrap",
   "peace.desktop-overlay"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "ARTIFACT_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/bootstrap/peace.desktop-bootstrap.js",
    "lines": [
     307,
     309,
     310
    ]
   },
   {
    "path": "services/overlay/peace.desktop-overlay.js",
    "lines": [
     87
    ]
   }
  ]
 },
 {
  "id": "BOOTSTRAP_CODE_MISMATCH",
  "label": "BOOTSTRAP CODE MISMATCH",
  "category": "ARTIFACT_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-bootstrap"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "ARTIFACT_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/bootstrap/peace.desktop-bootstrap.js",
    "lines": [
     14,
     311
    ]
   }
  ]
 },
 {
  "id": "BOOTSTRAP_HASH_MISMATCH",
  "label": "BOOTSTRAP HASH MISMATCH",
  "category": "ARTIFACT_INTEGRITY",
  "sourceUnits": [
   "peace.desktop-bootstrap"
  ],
  "responsePaths": [
   "Integrity"
  ],
  "evidenceFamilies": [
   "ARTIFACT_INTEGRITY"
  ],
  "signalClass": "MISMATCH",
  "sourceReferences": [
   {
    "path": "services/bootstrap/peace.desktop-bootstrap.js",
    "lines": [
     14,
     286,
     299
    ]
   }
  ]
 },
 {
  "id": "SECURITY_NHW_QUOTE_INVALID",
  "label": "SECURITY NHW QUOTE INVALID",
  "category": "TPM_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-tpm-quote",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "TPM_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-tpm-quote.js",
    "lines": [
     15
    ]
   }
  ]
 },
 {
  "id": "SECURITY_NHW_QUOTE_TYPE",
  "label": "SECURITY NHW QUOTE TYPE",
  "category": "TPM_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-tpm-quote",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "TPM_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-tpm-quote.js",
    "lines": [
     39
    ]
   }
  ]
 },
 {
  "id": "SECURITY_NHW_QUOTE_SIGNER",
  "label": "SECURITY NHW QUOTE SIGNER",
  "category": "TPM_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-tpm-quote",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "TPM_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-tpm-quote.js",
    "lines": [
     40
    ]
   }
  ]
 },
 {
  "id": "SECURITY_NHW_QUOTE_BINDING",
  "label": "SECURITY NHW QUOTE BINDING",
  "category": "TPM_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-tpm-quote",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "TPM_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-tpm-quote.js",
    "lines": [
     41
    ]
   }
  ]
 },
 {
  "id": "SECURITY_NHW_QUOTE_CLOCK",
  "label": "SECURITY NHW QUOTE CLOCK",
  "category": "TPM_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-tpm-quote",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "TPM_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-tpm-quote.js",
    "lines": [
     46
    ]
   }
  ]
 },
 {
  "id": "SECURITY_NHW_QUOTE_SELECTION",
  "label": "SECURITY NHW QUOTE SELECTION",
  "category": "TPM_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-tpm-quote",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "TPM_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-tpm-quote.js",
    "lines": [
     49
    ]
   }
  ]
 },
 {
  "id": "SECURITY_NHW_QUOTE_PCR_DIGEST",
  "label": "SECURITY NHW QUOTE PCR DIGEST",
  "category": "TPM_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-tpm-quote",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "TPM_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-tpm-quote.js",
    "lines": [
     52
    ]
   }
  ]
 },
 {
  "id": "SECURITY_NHW_QUOTE_ALGORITHM",
  "label": "SECURITY NHW QUOTE ALGORITHM",
  "category": "TPM_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-tpm-quote",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "TPM_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-tpm-quote.js",
    "lines": [
     54
    ]
   }
  ]
 },
 {
  "id": "SECURITY_NHW_QUOTE_SIGNATURE",
  "label": "SECURITY NHW QUOTE SIGNATURE",
  "category": "TPM_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-tpm-quote",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "TPM_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-tpm-quote.js",
    "lines": [
     59
    ]
   }
  ]
 },
 {
  "id": "SECURITY_NHW_QUOTE_UNENROLLED",
  "label": "SECURITY NHW QUOTE UNENROLLED",
  "category": "TPM_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-tpm-quote",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "TPM_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-tpm-quote.js",
    "lines": [
     96
    ]
   }
  ]
 },
 {
  "id": "SECURITY_NHW_EVIDENCE_INVALID",
  "label": "SECURITY NHW EVIDENCE INVALID",
  "category": "NHW_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-attestation",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "NHW_ATTESTATION"
  ],
  "signalClass": "POLICY_REJECTION",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-attestation.js",
    "lines": [
     16
    ]
   }
  ]
 },
 {
  "id": "TPM_CLOCK_UNSAFE",
  "label": "TPM CLOCK UNSAFE",
  "category": "TPM_ATTESTATION",
  "sourceUnits": [
   "peace.nhw-tpm-quote",
   "peace.desktop-security-authority"
  ],
  "responsePaths": [
   "Trust"
  ],
  "evidenceFamilies": [
   "TPM_ATTESTATION"
  ],
  "signalClass": "UNKNOWN",
  "sourceReferences": [
   {
    "path": "services/security/peace.nhw-tpm-quote.js",
    "lines": [
     63
    ]
   }
  ]
 }
].concat(MITIGATION_FINDINGS,MITIGATION_RUNTIME_FINDINGS,PEER_FINDINGS).map(CozyMetadata));
const byId = new Map([...NHW, ...COZY].map(row => [row.id, row]));
function Get(id) { return typeof id === 'string' ? byId.get(id) || null : null; }
function ResolveNHWOrdinal(ordinal) { return Number.isInteger(ordinal) && ordinal >= 0 && ordinal < NHW.length ? NHW[ordinal] : null; }
const Counts = Object.freeze({nhw: NHW.length, cozy: COZY.length,nhwStandalone:NHW.filter(row=>row.standaloneOutput).length,nhwOutputNames:new Set(NHW.filter(row=>row.standaloneOutput).map(row=>row.displayName)).size,nhwInternalEvidence:INTERNAL_EVIDENCE.size});
module.exports = {NHW, COZY, Get, Find:Get, ResolveNHWOrdinal, Counts, nhwDetections:NHW, cozyDetections:COZY};
