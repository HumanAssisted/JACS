#!/usr/bin/env tsx
/**
 * LangGraph.js Agent with JACS Signing Callback
 *
 * This example demonstrates using a LangGraph.js agent with a custom callback
 * that automatically signs all tool outputs, maintaining a cryptographically
 * verifiable audit trail.
 *
 * Prerequisites:
 *   1. Install dependencies: npm install
 *   2. Set up a JACS agent: npx jacs init && npx jacs create
 *   3. Set your LLM API key: export ANTHROPIC_API_KEY=your-key
 *
 * Usage:
 *   npx tsx signing-callback.ts
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
 * Represents a signed tool output in the audit trail.
 */
interface SignedOutput {
  toolName: string;
  toolInput: Record<string, unknown>;
  toolOutput: unknown;
  documentId: string;
  agentId: string;
  timestamp: string;
  rawSignedDocument: string;
  runId?: string;
}

/**
 * Maintains an audit trail of all signed outputs.
 */
class SignedOutputsAuditTrail {
  private outputs: SignedOutput[] = [];

  add(output: SignedOutput): void {
    this.outputs.push(output);
  }

  getAll(): SignedOutput[] {
    return [...this.outputs];
  }

  getByTool(toolName: string): SignedOutput[] {
    return this.outputs.filter((o) => o.toolName === toolName);
  }

  exportJson(): string {
    return JSON.stringify(
      this.outputs.map((o) => ({
        tool_name: o.toolName,
        tool_input: o.toolInput,
        tool_output: o.toolOutput,
        document_id: o.documentId,
        agent_id: o.agentId,
        timestamp: o.timestamp,
        run_id: o.runId,
      })),
      null,
      2
    );
  }

  verifyAll(): Map<string, boolean> {
    const results = new Map<string, boolean>();
    for (const output of this.outputs) {
      try {
        const result = jacs.verify(output.rawSignedDocument);
        results.set(output.documentId, result.valid);
      } catch {
        results.set(output.documentId, false);
      }
    }
    return results;
  }
}

/**
 * A callback handler that automatically signs tool outputs using JACS.
 *
 * This callback intercepts tool outputs from LangChain/LangGraph agents
 * and signs them with the JACS agent's cryptographic key, creating
 * a verifiable audit trail.
 */
class JACSSigningCallback {
  auditTrail: SignedOutputsAuditTrail;
  private isLoaded: boolean;

  constructor(configPath?: string) {
    this.auditTrail = new SignedOutputsAuditTrail();
    this.isLoaded = false;

    // Load the JACS agent
    const path = configPath || CONFIG_PATH;
    try {
      if (!jacs.isLoaded()) {
        jacs.load(path);
        console.log(`JACS agent loaded from ${path}`);
      }
      this.isLoaded = true;
    } catch (error) {
      console.warn(`Warning: Could not load JACS agent: ${error}`);
      console.warn("Signing will be disabled.");
    }
  }

  /**
   * Sign a tool output and add it to the audit trail.
   */
  signOutput(
    toolName: string,
    toolInput: Record<string, unknown>,
    toolOutput: unknown,
    runId?: string
  ): SignedOutput | null {
    if (!this.isLoaded) {
      return null;
    }

    try {
      // Create the payload to sign
      const payload = {
        type: "tool_output",
        tool_name: toolName,
        tool_input: toolInput,
        tool_output: toolOutput,
        signed_at: new Date().toISOString(),
        ...(runId && { run_id: runId }),
      };

      // Sign with JACS
      const signed = jacs.signMessage(payload);

      // Create audit trail entry
      const signedOutput: SignedOutput = {
        toolName,
        toolInput,
        toolOutput,
        documentId: signed.documentId,
        agentId: signed.agentId,
        timestamp: signed.timestamp,
        rawSignedDocument: signed.raw,
        runId,
      };

      // Add to audit trail
      this.auditTrail.add(signedOutput);

      return signedOutput;
    } catch (error) {
      console.warn(`Warning: Failed to sign output: ${error}`);
      return null;
    }
  }
}

/**
 * Create example tools for demonstration.
 */
function createExampleTools() {
  const calculateTool = tool(
    async ({ expression }) => {
      try {
        // Simple safe evaluation (in production, use a proper math parser)
        const result = Function(`"use strict"; return (${expression})`)();
        return String(result);
      } catch (error) {
        return `Error: ${error}`;
      }
    },
    {
      name: "calculate",
      description: "Evaluate a mathematical expression and return the result.",
      schema: z.object({
        expression: z.string().describe("The mathematical expression to evaluate"),
      }),
    }
  );

  const getCurrentTimeTool = tool(
    async () => {
      return new Date().toISOString();
    },
    {
      name: "get_current_time",
      description: "Get the current UTC time.",
      schema: z.object({}),
    }
  );

  const generateReportTool = tool(
    async ({ title, content }) => {
      return JSON.stringify({
        title,
        content,
        generated_at: new Date().toISOString(),
        version: "1.0",
      });
    },
    {
      name: "generate_report",
      description: "Generate a report with the given title and content.",
      schema: z.object({
        title: z.string().describe("The title of the report"),
        content: z.string().describe("The content of the report"),
      }),
    }
  );

  return [calculateTool, getCurrentTimeTool, generateReportTool];
}

async function main() {
  console.log("\n=== JACS + LangGraph.js Signing Callback Example ===\n");

  // Initialize JACS agent first
  console.log(`Loading JACS agent from: ${CONFIG_PATH}`);
  try {
    const agentInfo = jacs.load(CONFIG_PATH);
    console.log(`Agent loaded: ${agentInfo.agentId}`);
  } catch (error) {
    console.error(`Error loading JACS agent: ${error}`);
    console.error("Please run: npx jacs init && npx jacs create");
    process.exit(1);
  }

  // Create signing callback
  const callback = new JACSSigningCallback();

  // Create example tools
  const tools = createExampleTools();
  console.log(`Available tools: ${tools.map((t) => t.name).join(", ")}`);

  // Initialize the LLM
  let model;
  if (process.env.ANTHROPIC_API_KEY) {
    model = new ChatAnthropic({
      model: "claude-sonnet-4-20250514",
    });
    console.log("Using Anthropic Claude");
  } else {
    model = new ChatOpenAI({
      model: "gpt-4",
    });
    console.log("Using OpenAI GPT-4");
  }

  // Create the agent
  const agent = createReactAgent({
    llm: model,
    tools,
  });

  console.log("\n--- Running example interactions ---\n");

  // Example 1: Mathematical calculation
  console.log("1. Running calculation...");
  const result1 = await agent.invoke({
    messages: [{ role: "user", content: "What is 42 * 17?" }],
  });
  const response1 = result1.messages[result1.messages.length - 1].content;
  callback.signOutput(
    "final_response",
    { query: "What is 42 * 17?" },
    response1
  );
  console.log(`   Result: ${response1}`);

  // Example 2: Get current time
  console.log("2. Getting current time...");
  const result2 = await agent.invoke({
    messages: [{ role: "user", content: "What time is it now in UTC?" }],
  });
  const response2 = result2.messages[result2.messages.length - 1].content;
  callback.signOutput(
    "final_response",
    { query: "What time is it now in UTC?" },
    response2
  );
  console.log(`   Result: ${response2}`);

  // Example 3: Generate a report
  console.log("3. Generating a report...");
  const result3 = await agent.invoke({
    messages: [
      {
        role: "user",
        content: "Generate a report titled 'Q4 Summary' with content about sales growth",
      },
    ],
  });
  const response3 = result3.messages[result3.messages.length - 1].content;
  callback.signOutput(
    "final_response",
    { query: "Generate Q4 Summary report" },
    response3
  );
  const responseStr = typeof response3 === 'string' ? response3 : JSON.stringify(response3);
  console.log(`   Result: ${responseStr.slice(0, 100)}...`);

  // Display audit trail
  console.log("\n--- Audit Trail ---\n");
  const allOutputs = callback.auditTrail.getAll();
  console.log(`Total signed outputs: ${allOutputs.length}`);

  for (let i = 0; i < allOutputs.length; i++) {
    const output = allOutputs[i];
    console.log(`\n${i + 1}. Tool: ${output.toolName}`);
    console.log(`   Document ID: ${output.documentId}`);
    console.log(`   Agent ID: ${output.agentId}`);
    console.log(`   Timestamp: ${output.timestamp}`);
  }

  // Verify all outputs
  console.log("\n--- Verifying All Signed Outputs ---\n");
  const verificationResults = callback.auditTrail.verifyAll();
  for (const [docId, valid] of verificationResults) {
    const status = valid ? "VALID" : "INVALID";
    console.log(`Document ${docId.slice(0, 8)}...: ${status}`);
  }

  // Export audit trail
  console.log("\n--- Exported Audit Trail (JSON) ---\n");
  console.log(callback.auditTrail.exportJson());
}

main().catch(console.error);
