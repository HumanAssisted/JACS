function portableSignedDocument(content, options = {}) {
  const signature = {
    agentID: options.agentId || 'agent-abc',
    agentVersion: options.agentVersion || 'agent-version-1',
    date: options.timestamp || '2026-07-10T00:00:00Z',
    publicKeyHash: options.publicKeyHash || 'public-key-hash-1',
    signature: options.signature || 'signed-document-bytes',
    signatureContentVersion: 'jacs-signature-v2',
    ...(options.signatureFields || {}),
  };
  return {
    jacsId: options.documentId || 'doc-123',
    jacsVersion: options.documentVersion || 'document-version-1',
    content,
    jacsSignature: signature,
    ...(options.documentFields || {}),
  };
}

function signedResult(content, options = {}) {
  const document = portableSignedDocument(content, options);
  return {
    raw: JSON.stringify(document),
    documentId: document.jacsId,
    agentId: document.jacsSignature.agentID || document.jacsSignature.agentId,
    timestamp: document.jacsSignature.date,
  };
}

module.exports = {
  portableSignedDocument,
  signedResult,
};
