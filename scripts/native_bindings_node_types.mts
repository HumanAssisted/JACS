import { JacsAgent, JacsSimpleAgent, type VerifyStandaloneResult } from '@hai.ai/jacs';
import { JacsClient } from '@hai.ai/jacs/client';
import {
  canonicalizeJson, encodeUtf8, buildSignedDocumentSignatureInputV2,
  buildDocumentChecksumInputV1, buildHaiSignatureInputDigestPreimageV1,
  buildHumanApprovalDocumentSignatureInputDigestPreimageV1,
} from '@hai.ai/jacs/signing-input';

const native = new JacsAgent();
const identity: Promise<string> = native.ephemeral('pq2025');
const client = JacsClient.ephemeralSync('pq2025');
const signed = client.signMessageSync({ installedTypes: true });
const verified: boolean = client.verifySync(signed.raw).valid;
const simple = JacsSimpleAgent.ephemeral('pq2025');
const raw: string = simple.signMessage('{}');
const proof: string | undefined = JacsSimpleAgent.verifyHumanApprovedDocument?.('{}', '{}', '{}', '{}');

function bindingStatus(result: VerifyStandaloneResult): 'unavailable' | 'locally_enrolled' {
  return result.identityBindingStatus;
}
const text: string = canonicalizeJson({ a: 1 });
const bytes: Uint8Array[] = [
  encodeUtf8(text), buildSignedDocumentSignatureInputV2({}),
  buildDocumentChecksumInputV1({}), buildHaiSignatureInputDigestPreimageV1({}),
  buildHumanApprovalDocumentSignatureInputDigestPreimageV1({}),
];
void [identity, verified, raw, proof, bindingStatus, bytes];
