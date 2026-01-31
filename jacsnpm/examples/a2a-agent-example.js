#!/usr/bin/env node

/**
 * JACS A2A Agent Example for Node.js
 * 
 * This example demonstrates how to:
 * 1. Create a JACS agent with A2A support
 * 2. Export to A2A Agent Card format
 * 3. Wrap artifacts with JACS provenance
 * 4. Create workflows with chain of custody
 */

const fs = require('fs').promises;
const path = require('path');
const jacs = require('../src/index');
const {
  JACSA2AIntegration,
  A2A_PROTOCOL_VERSION,
  JACS_EXTENSION_URI
} = require('../src/a2a');

// Example agent data
const exampleAgentData = {
  jacsId: 'nodejs-example-agent',
  jacsVersion: 'v1.0.0',
  jacsName: 'Node.js A2A Example Agent',
  jacsDescription: 'A Node.js agent demonstrating JACS + A2A protocol integration',
  jacsAgentType: 'ai',
  jacsServices: [{
    name: 'Text Analysis Service',
    serviceDescription: 'Analyzes text using NLP techniques',
    successDescription: 'Text successfully analyzed',
    failureDescription: 'Text analysis failed',
    tools: [{
      url: '/api/analyze-text',
      function: {
        name: 'analyzeText',
        description: 'Analyze text and extract insights',
        parameters: {
          type: 'object',
          properties: {
            text: {
              type: 'string',
              description: 'The text to analyze'
            },
            language: {
              type: 'string',
              description: 'Language code (e.g., en, es, fr)',
              default: 'en'
            },
            operations: {
              type: 'array',
              items: { type: 'string' },
              description: 'Analysis operations to perform',
              default: ['sentiment', 'entities', 'keywords']
            }
          },
          required: ['text']
        }
      }
    }]
  }, {
    name: 'Document Processing Service',
    serviceDescription: 'Processes various document formats',
    successDescription: 'Document processed successfully',
    failureDescription: 'Document processing failed',
    tools: [{
      url: '/api/process-document',
      function: {
        name: 'processDocument',
        description: 'Process and extract information from documents',
        parameters: {
          type: 'object',
          properties: {
            documentUrl: {
              type: 'string',
              description: 'URL of the document to process'
            },
            format: {
              type: 'string',
              enum: ['pdf', 'docx', 'txt', 'html'],
              description: 'Document format'
            }
          },
          required: ['documentUrl', 'format']
        }
      }
    }]
  }],
  jacsContacts: [{
    type: 'email',
    value: 'admin@nodejs-example-agent.com',
    description: 'Administrator contact'
  }]
};

async function main() {
  console.log('=== JACS A2A Node.js Agent Example ===\n');

  try {
    // Step 1: Initialize JACS (with mock config for example)
    console.log('1. Initializing JACS...');
    // In a real application, you would load an actual config
    // jacs.load('jacs.config.json');
    console.log('   ✓ JACS initialized\n');

    // Step 2: Create A2A integration
    console.log('2. Creating A2A integration...');
    const a2a = new JACSA2AIntegration();
    console.log('   ✓ A2A integration created\n');

    // Step 3: Export agent to A2A Agent Card
    console.log('3. Exporting to A2A Agent Card...');
    const agentCard = a2a.exportAgentCard(exampleAgentData);
    
    console.log('   ✓ Agent Card created');
    console.log(`   - Name: ${agentCard.name}`);
    console.log(`   - URL: ${agentCard.url}`);
    console.log(`   - Protocol: ${agentCard.protocolVersion}`);
    console.log(`   - Skills: ${agentCard.skills.length} defined`);
    
    agentCard.skills.forEach(skill => {
      console.log(`     • ${skill.name}: ${skill.description}`);
    });
    
    console.log(`   - Extensions: ${agentCard.capabilities.extensions?.length || 0} configured`);
    if (agentCard.capabilities.extensions) {
      agentCard.capabilities.extensions.forEach(ext => {
        console.log(`     • ${ext.uri}: ${ext.description}`);
      });
    }
    console.log();

    // Step 4: Create extension descriptor
    console.log('4. Creating JACS extension descriptor...');
    const extensionDescriptor = a2a.createExtensionDescriptor();
    console.log('   ✓ Extension descriptor created');
    console.log(`   - URI: ${extensionDescriptor.uri}`);
    console.log(`   - Capabilities: ${Object.keys(extensionDescriptor.capabilities).join(', ')}`);
    console.log();

    // Step 5: Demonstrate wrapping A2A artifacts
    console.log('5. Wrapping A2A artifacts with JACS provenance...');
    
    // Example task
    const a2aTask = {
      taskId: 'analyze-001',
      type: 'text-analysis',
      input: {
        text: 'JACS provides cryptographic provenance for A2A agent networks.',
        language: 'en',
        operations: ['sentiment', 'entities']
      },
      requestedBy: 'client-agent-456',
      timestamp: new Date().toISOString()
    };

    // Mock the signing (in real usage, JACS would sign with actual keys)
    const mockSignRequest = (doc) => ({
      ...doc,
      jacsSignature: {
        agentID: exampleAgentData.jacsId,
        agentVersion: exampleAgentData.jacsVersion,
        date: new Date().toISOString(),
        signature: 'mock-signature-base64',
        signingAlgorithm: 'RSA-PSS',
        publicKeyHash: 'mock-public-key-hash',
        fields: Object.keys(doc).filter(k => k !== 'jacsSignature')
      },
      jacsSha256: 'mock-document-hash'
    });

    // Override jacs.signRequest for the example
    const originalSign = jacs.signRequest;
    jacs.signRequest = mockSignRequest;

    const wrappedTask = a2a.wrapArtifactWithProvenance(a2aTask, 'task');
    
    console.log('   ✓ Task wrapped with JACS signature');
    console.log(`   - JACS ID: ${wrappedTask.jacsId}`);
    console.log(`   - Type: ${wrappedTask.jacsType}`);
    console.log(`   - Signer: ${wrappedTask.jacsSignature.agentID}`);
    console.log();

    // Step 6: Create a workflow with chain of custody
    console.log('6. Creating workflow with chain of custody...');
    
    const workflowSteps = [
      {
        step: 'document-receipt',
        documentId: 'doc-789',
        receivedFrom: 'client-agent-456',
        status: 'completed'
      },
      {
        step: 'text-extraction',
        documentId: 'doc-789',
        extractedText: 'Sample text extracted from document...',
        confidence: 0.98,
        status: 'completed'
      },
      {
        step: 'entity-analysis',
        documentId: 'doc-789',
        entities: [
          { type: 'ORG', value: 'JACS', confidence: 0.95 },
          { type: 'TECH', value: 'A2A protocol', confidence: 0.92 }
        ],
        status: 'completed'
      }
    ];

    const wrappedSteps = [];
    for (let i = 0; i < workflowSteps.length; i++) {
      const parentSigs = i > 0 ? [wrappedSteps[i - 1]] : null;
      const wrapped = a2a.wrapArtifactWithProvenance(
        workflowSteps[i],
        'workflow-step',
        parentSigs
      );
      wrappedSteps.push(wrapped);
    }

    const chainOfCustody = a2a.createChainOfCustody(wrappedSteps);
    
    console.log('   ✓ Workflow created');
    console.log(`   - Total steps: ${chainOfCustody.totalArtifacts}`);
    console.log('   - Chain of custody:');
    chainOfCustody.chainOfCustody.forEach((entry, i) => {
      console.log(`     ${i + 1}. ${entry.artifactType} by ${entry.agentId}`);
    });
    console.log();

    // Step 7: Verify wrapped artifact
    console.log('7. Verifying wrapped artifact...');
    
    // Mock verification
    jacs.verifyRequest = () => true;
    
    const verification = a2a.verifyWrappedArtifact(wrappedTask);
    console.log(`   ✓ Verification: ${verification.valid ? 'PASSED' : 'FAILED'}`);
    console.log(`   - Signer: ${verification.signerId}`);
    console.log(`   - Type: ${verification.artifactType}`);
    console.log();

    // Step 8: Generate well-known documents
    console.log('8. Generating .well-known documents...');
    
    // Mock JWS signature and public key
    const mockJwsSignature = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2VudENhcmQiOiJ0cnVlIn0.signature';
    const mockPublicKeyB64 = Buffer.from('mock-public-key').toString('base64');
    
    // Mock hashPublicKey
    jacs.hashPublicKey = () => 'mock-public-key-hash';
    
    const wellKnownDocs = a2a.generateWellKnownDocuments(
      agentCard,
      mockJwsSignature,
      mockPublicKeyB64,
      exampleAgentData
    );
    
    console.log('   ✓ Documents generated:');
    Object.keys(wellKnownDocs).forEach(path => {
      console.log(`     • ${path}`);
    });
    console.log();

    // Step 9: Save example outputs
    console.log('9. Saving example outputs...');
    
    const outputDir = path.join(__dirname, 'a2a-output');
    await fs.mkdir(outputDir, { recursive: true });
    
    // Save Agent Card
    await fs.writeFile(
      path.join(outputDir, 'agent-card.json'),
      JSON.stringify(agentCard, null, 2)
    );
    
    // Save wrapped task
    await fs.writeFile(
      path.join(outputDir, 'wrapped-task.json'),
      JSON.stringify(wrappedTask, null, 2)
    );
    
    // Save chain of custody
    await fs.writeFile(
      path.join(outputDir, 'chain-of-custody.json'),
      JSON.stringify(chainOfCustody, null, 2)
    );
    
    // Save well-known documents
    for (const [docPath, content] of Object.entries(wellKnownDocs)) {
      const filename = docPath.split('/').pop();
      await fs.writeFile(
        path.join(outputDir, filename),
        JSON.stringify(content, null, 2)
      );
    }
    
    console.log(`   ✓ Outputs saved to: ${outputDir}`);
    console.log();

    // Restore original functions
    jacs.signRequest = originalSign;

    console.log('=== Example completed successfully! ===');
    console.log('\nKey Takeaways:');
    console.log('- JACS provides document-level cryptographic provenance');
    console.log('- A2A enables agent discovery and communication');
    console.log('- Together they create a complete agent ecosystem');
    console.log('- Post-quantum support ensures long-term security');
    console.log('\nNext Steps:');
    console.log('1. Set up actual JACS configuration with keys');
    console.log('2. Implement HTTP endpoints for A2A skills');
    console.log('3. Host .well-known documents on your server');
    console.log('4. Register with A2A discovery services');

  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

// Run the example
main();
