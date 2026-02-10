#!/usr/bin/env tsx
/**
 * Basic LangChain.js Agent with JACS Integration
 *
 * This example demonstrates how to create a LangChain.js agent that uses
 * the JACS simple API directly for cryptographic signing and verification.
 *
 * Prerequisites:
 *   1. Install dependencies: npm install
 *   2. Set up a JACS agent: npx jacs init && npx jacs create
 *   3. Set your LLM API key: export ANTHROPIC_API_KEY=your-key
 *
 * Usage:
 *   npx tsx basic-agent.ts
 */

import { ChatAnthropic } from "@langchain/anthropic";
import { ChatOpenAI } from "@langchain/openai";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { tool } from "@langchain/core/tools";
import { z } from "zod";
import * as jacs from "../../simple.js";

// Configuration
const CONFIG_PATH = process.env.JACS_CONFIG || "./jacs.config.json";

// Check for API keys
if (!process.env.ANTHROPIC_API_KEY && !process.env.OPENAI_API_KEY) {
  console.error("Error: Please set ANTHROPIC_API_KEY or OPENAI_API_KEY");
  console.error("  export ANTHROPIC_API_KEY=your-key-here");
  process.exit(1);
}

/**
 * Initialize JACS and create tools that wrap the JACS simple API.
 */
async function initializeJACSTools() {
  // Load the JACS agent
  console.log(`Loading JACS agent from: ${CONFIG_PATH}`);
  const agentInfo = await jacs.load(CONFIG_PATH);
  console.log(`Agent loaded: ${agentInfo.agentId}`);

  // Verify agent integrity
  const selfCheck = await jacs.verifySelf();
  if (!selfCheck.valid) {
    console.warn(`Warning: Agent verification failed: ${selfCheck.errors.join(", ")}`);
  } else {
    console.log("Agent integrity verified.");
  }

  // Define LangChain tools that use JACS
  const signMessageTool = tool(
    async ({ data }) => {
      try {
        // Parse if it's a JSON string
        let payload: unknown;
        try {
          payload = JSON.parse(data);
        } catch {
          payload = data;
        }

        const signed = await jacs.signMessage(payload);
        return JSON.stringify({
          success: true,
          document_id: signed.documentId,
          agent_id: signed.agentId,
          timestamp: signed.timestamp,
          signed_document: signed.raw,
        }, null, 2);
      } catch (error) {
        return JSON.stringify({
          success: false,
          error: String(error),
        });
      }
    },
    {
      name: "sign_message",
      description: "Sign arbitrary data with JACS cryptographic signature. Returns a signed document that can be verified.",
      schema: z.object({
        data: z.string().describe("The data to sign, as a JSON string or plain text"),
      }),
    }
  );

  const verifyDocumentTool = tool(
    async ({ signed_document }) => {
      try {
        const result = await jacs.verify(signed_document);
        return JSON.stringify({
          valid: result.valid,
          signer_id: result.signerId,
          timestamp: result.timestamp,
          errors: result.errors,
        }, null, 2);
      } catch (error) {
        return JSON.stringify({
          valid: false,
          error: String(error),
        });
      }
    },
    {
      name: "verify_document",
      description: "Verify a JACS-signed document and check its cryptographic signature.",
      schema: z.object({
        signed_document: z.string().describe("The signed JACS document JSON string to verify"),
      }),
    }
  );

  const getAgentInfoTool = tool(
    async () => {
      const info = jacs.getAgentInfo();
      if (!info) {
        return JSON.stringify({ error: "No agent loaded" });
      }
      return JSON.stringify({
        agent_id: info.agentId,
        name: info.name,
        config_path: info.configPath,
        public_key_path: info.publicKeyPath,
      }, null, 2);
    },
    {
      name: "get_agent_info",
      description: "Get information about the current JACS agent.",
      schema: z.object({}),
    }
  );

  const verifySelfTool = tool(
    async () => {
      const result = await jacs.verifySelf();
      return JSON.stringify({
        valid: result.valid,
        errors: result.errors,
      }, null, 2);
    },
    {
      name: "verify_self",
      description: "Verify the loaded agent's own integrity.",
      schema: z.object({}),
    }
  );

  const getPublicKeyTool = tool(
    async () => {
      const pem = jacs.getPublicKey();
      return pem;
    },
    {
      name: "get_public_key",
      description: "Get the agent's public key in PEM format for sharing with others.",
      schema: z.object({}),
    }
  );

  const createAgreementTool = tool(
    async ({ document, agent_ids, question, context }) => {
      try {
        let payload: unknown;
        try {
          payload = JSON.parse(document);
        } catch {
          payload = document;
        }

        const agreement = await jacs.createAgreement(
          payload,
          agent_ids,
          question || undefined,
          context || undefined
        );

        return JSON.stringify({
          success: true,
          document_id: agreement.documentId,
          agent_id: agreement.agentId,
          timestamp: agreement.timestamp,
          agreement_document: agreement.raw,
        }, null, 2);
      } catch (error) {
        return JSON.stringify({
          success: false,
          error: String(error),
        });
      }
    },
    {
      name: "create_agreement",
      description: "Create a multi-party agreement requiring signatures from specified agents.",
      schema: z.object({
        document: z.string().describe("The document content as JSON string"),
        agent_ids: z.array(z.string()).describe("List of agent IDs required to sign"),
        question: z.string().optional().describe("Optional question or purpose of the agreement"),
        context: z.string().optional().describe("Optional additional context for signers"),
      }),
    }
  );

  const checkAgreementTool = tool(
    async ({ agreement_document }) => {
      try {
        const status = await jacs.checkAgreement(agreement_document);
        return JSON.stringify({
          complete: status.complete,
          signers: status.signers,
          pending: status.pending,
        }, null, 2);
      } catch (error) {
        return JSON.stringify({
          error: String(error),
        });
      }
    },
    {
      name: "check_agreement",
      description: "Check the status of a multi-party agreement.",
      schema: z.object({
        agreement_document: z.string().describe("The agreement document JSON string"),
      }),
    }
  );

  return [
    signMessageTool,
    verifyDocumentTool,
    getAgentInfoTool,
    verifySelfTool,
    getPublicKeyTool,
    createAgreementTool,
    checkAgreementTool,
  ];
}

async function main() {
  console.log("\n=== JACS + LangChain.js Basic Agent Example ===\n");

  // Initialize JACS tools
  const tools = await initializeJACSTools();
  console.log(`\nLoaded ${tools.length} JACS tools:`);
  tools.forEach(t => console.log(`  - ${t.name}: ${t.description?.slice(0, 50)}...`));

  // Initialize the LLM
  let model;
  if (process.env.ANTHROPIC_API_KEY) {
    model = new ChatAnthropic({
      model: "claude-sonnet-4-20250514",
    });
    console.log("\nUsing Anthropic Claude");
  } else {
    model = new ChatOpenAI({
      model: "gpt-4",
    });
    console.log("\nUsing OpenAI GPT-4");
  }

  // Create the agent
  const agent = createReactAgent({
    llm: model,
    tools,
  });

  console.log("\n" + "=".repeat(60));
  console.log("Agent ready! Running example interactions...");
  console.log("=".repeat(60) + "\n");

  // Example 1: Get agent info
  console.log("--- Example 1: Getting agent information ---");
  const result1 = await agent.invoke({
    messages: [
      {
        role: "user",
        content: "What is your agent ID and configuration?",
      },
    ],
  });
  console.log(`Response: ${result1.messages[result1.messages.length - 1].content}\n`);

  // Example 2: Sign a message
  console.log("--- Example 2: Signing a message ---");
  const result2 = await agent.invoke({
    messages: [
      {
        role: "user",
        content: 'Please sign this message: {"action": "approve", "item_id": "TX-12345", "amount": 1000}',
      },
    ],
  });
  console.log(`Response: ${result2.messages[result2.messages.length - 1].content}\n`);

  // Example 3: Verify agent integrity
  console.log("--- Example 3: Verifying agent integrity ---");
  const result3 = await agent.invoke({
    messages: [
      {
        role: "user",
        content: "Please verify your own integrity and tell me if you are valid.",
      },
    ],
  });
  console.log(`Response: ${result3.messages[result3.messages.length - 1].content}\n`);

  // Example 4: Sign and verify workflow
  console.log("--- Example 4: Complete sign-verify workflow ---");
  const result4 = await agent.invoke({
    messages: [
      {
        role: "user",
        content: `Please do the following:
1. Sign the message: {"transaction": "payment", "to": "Alice", "amount": 500}
2. Then verify the signed document you just created
3. Report whether the verification succeeded`,
      },
    ],
  });
  console.log(`Response: ${result4.messages[result4.messages.length - 1].content}\n`);

  console.log("=".repeat(60));
  console.log("Example complete!");
  console.log("=".repeat(60));
}

main().catch(console.error);
