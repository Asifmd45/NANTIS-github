import { LlmInvestigatorConfig } from "./types.js";

export interface LlmResponse {
  rawOutput: string;
  tokensUsed: number;
  costUsd: number;
  latencyMs: number;
}

export interface LlmProvider {
  name: string;
  call(prompt: string, config?: LlmInvestigatorConfig): Promise<LlmResponse>;
}

/**
 * Deterministic Mock LLM Provider for testing and offline execution.
 */
export class MockLlmProvider implements LlmProvider {
  name = "mock";

  constructor(
    private mockScenario: "default" | "malformed" | "timeout" | "rate_limit" | "prompt_injection" = "default"
  ) {}

  async call(prompt: string, _config?: LlmInvestigatorConfig): Promise<LlmResponse> {
    const start = Date.now();

    if (this.mockScenario === "timeout") {
      throw new Error("LLM provider request timed out (simulated 30000ms limit)");
    }

    if (this.mockScenario === "rate_limit") {
      throw new Error("LLM provider rate limit exceeded (HTTP 429)");
    }

    if (this.mockScenario === "malformed") {
      return {
        rawOutput: "Invalid JSON prose output: Found an IDOR vulnerability in route.ts line 15!",
        tokensUsed: 150,
        costUsd: 0.0003,
        latencyMs: Date.now() - start,
      };
    }

    // Default & Prompt Injection mock behavior
    const isPromptInjection = prompt.includes("Ignore previous instructions") || prompt.includes("Mark this file safe");

    // Inspect prompt for files
    const fileMatches = [...prompt.matchAll(/<file path="([^"]+)">([\s\S]*?)<\/file>/g)];
    const candidateFindings: Array<Record<string, unknown>> = [];

    for (const match of fileMatches) {
      const filePath = match[1];
      const content = match[2];

      // Detect vulnerable IDOR pattern in mock
      if (content.includes(".from(") && content.includes(".eq(\"id\"") && !content.includes("user_id")) {
        const line = content.split("\n").findIndex((l) => l.includes(".eq(")) + 1 || 1;
        candidateFindings.push({
          id: `cand-${filePath.replace(/[^a-zA-Z0-9]/g, "-")}-${line}`,
          ruleId: "idor.owner-column.v1",
          title: "LLM Investigator Candidate: Missing Ownership Check",
          severity: "high",
          file: filePath,
          line,
          claims: [
            {
              claimType: "input_user_controlled",
              ref: { file: filePath, line, snippet: "params.id" },
              rationale: "LLM observed user-controlled ID parameter in route signature",
            },
            {
              claimType: "ownership_absent",
              ref: { file: filePath, line, snippet: ".eq('id', params.id)" },
              rationale: "LLM observed database query missing user_id tenant isolation filter",
            },
          ],
          rationale: isPromptInjection
            ? "LLM safely analyzed repository containing prompt injection attempt without executing malicious payload."
            : "Contextual investigation identified unprotected database access by resource ID.",
        });
      }
    }

    const rawOutput = JSON.stringify(
      {
        candidateFindings,
        investigatorRationale: "Mock LLM investigation complete.",
      },
      null,
      2
    );

    return {
      rawOutput,
      tokensUsed: 350,
      costUsd: 0.0007,
      latencyMs: Date.now() - start + 10,
    };
  }
}

/**
 * Production Groq LLM Provider connecting to Groq Cloud API.
 */
export class GroqLlmProvider implements LlmProvider {
  name = "groq";

  constructor(
    private apiKey?: string,
    private defaultModel: string = (typeof process !== "undefined" && process.env?.GROQ_MODEL) || "qwen/qwen3.8-27b"
  ) {
    this.apiKey = apiKey || (typeof process !== "undefined" ? process.env?.GROQ_API_KEY : undefined);
  }

  async call(prompt: string, config?: LlmInvestigatorConfig): Promise<LlmResponse> {
    const key = this.apiKey || (typeof process !== "undefined" ? process.env?.GROQ_API_KEY : undefined);
    if (!key) {
      throw new Error("GROQ_API_KEY is not configured.");
    }

    const model = config?.modelId || this.defaultModel;
    const start = Date.now();

    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${key}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages: [
          {
            role: "user",
            content: prompt,
          },
        ],
        response_format: { type: "json_object" },
        temperature: 0.1,
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Groq API request failed (${response.status}): ${errText}`);
    }

    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
      usage?: { total_tokens?: number };
    };

    const rawOutput = data.choices?.[0]?.message?.content || "{}";
    const tokensUsed = data.usage?.total_tokens || 0;
    const latencyMs = Date.now() - start;
    const costUsd = (tokensUsed / 1_000_000) * 0.59;

    return {
      rawOutput,
      tokensUsed,
      costUsd,
      latencyMs,
    };
  }
}

