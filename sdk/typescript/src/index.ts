export { VAOLClient, type VAOLClientOptions } from "./client.js";
export { DecisionRecordBuilder } from "./record.js";
export { instrumentOpenAI, type InstrumentOptions } from "./wrapper.js";
export {
  verifyDSSEEd25519,
  verifyInclusionProof,
  type VerifyResult,
  type VerifyCheck,
} from "./verifier.js";
export type {
  DecisionRecord,
  Identity,
  Model,
  Parameters,
  PromptContext,
  PolicyContext,
  RAGContext,
  Output,
  Trace,
  Integrity,
  InclusionProof,
  Receipt,
  DSSEEnvelope,
  DSSESignature,
  VerificationResult,
  VerificationProfile,
  CheckResult,
} from "./types.js";
