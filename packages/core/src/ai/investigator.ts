import { Finding } from "../types.js";
import { createFinding } from "../evidence.js";
import {
  LlmInvestigatorConfig,
  LlmInvestigationResult,
  CandidateFinding,
  LlmInvestigationResponseSchema,
  ModelMetadata,
} from "./types.js";
import { LlmInputGate } from "./input-gate.js";
import { buildSecurityHunterPrompt } from "./prompt.js";
import { LlmProvider, MockLlmProvider, GroqLlmProvider } from "./provider.js";
import { indexRepository } from "../idor/indexer.js";
import { SupabaseAnalyzer } from "../idor/supabase-analyzer.js";
import { SecurityVerifiers } from "../idor/verifiers.js";

export const INVESTIGATOR_VERSION = "0.1.0-phase3";
export const PROMPT_VERSION = "1.0.0-security-hunter";

/**
 * Bounded LLM Security Investigator & Evidence Interpreter.
 * Enforces: LLM = investigator, Deterministic engine = authority.
 */
export class LlmSecurityHunter {
  private inputGate: LlmInputGate;

  constructor(private config: LlmInvestigatorConfig = {}, private provider?: LlmProvider) {
    this.inputGate = new LlmInputGate({
      maxFiles: config.maxFiles,
      maxTotalBytes: config.maxTotalBytes,
    });
    if (provider) {
      this.provider = provider;
    } else if (
      typeof process !== "undefined" &&
      process.env?.GROQ_API_KEY &&
      process.env.GROQ_API_KEY.trim().length > 0 &&
      process.env.NODE_ENV !== "test"
    ) {
      this.provider = new GroqLlmProvider();
    } else {
      this.provider = new MockLlmProvider();
    }
  }

  /**
   * Executes LLM investigation pass over repository filesMap.
   */
  async investigate(filesMap: Map<string, string>): Promise<LlmInvestigationResult> {
    const diagnostics: string[] = [];

    // If LLM is disabled, return clean empty result
    if (this.config.enabled === false) {
      return this.createEmptyResult("LLM Investigator disabled via configuration.");
    }

    const startMs = Date.now();

    // Step 1: Input Gate Filtering & Masking
    const context = this.inputGate.prepareContext(filesMap);
    if (context.files.size === 0) {
      return this.createEmptyResult("No relevant files selected for LLM investigation.");
    }

    // Step 2: Prompt Construction
    const prompt = buildSecurityHunterPrompt(context);

    // Step 3: Model Invocation (swallow failures safely)
    let rawOutput = "";
    let tokensUsed = 0;
    let costUsd = 0;
    let latencyMs = 0;

    try {
      const response = await this.provider!.call(prompt, this.config);
      rawOutput = response.rawOutput;
      tokensUsed = response.tokensUsed;
      costUsd = response.costUsd;
      latencyMs = response.latencyMs;
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      diagnostics.push(`LLM provider execution failed: ${errMsg}`);
      return {
        candidateFindings: [],
        verifiedFindings: [],
        metadata: {
          modelId: this.config.modelId || this.provider!.name,
          promptVersion: PROMPT_VERSION,
          investigatorVersion: INVESTIGATOR_VERSION,
          contextFingerprint: context.contextFingerprint,
          costUsd: 0,
          latencyMs: Date.now() - startMs,
        },
        diagnostics,
      };
    }

    // Step 4: Structured Output Schema Gate
    let candidateFindings: CandidateFinding[] = [];
    try {
      const parsedJson = JSON.parse(rawOutput);
      const validated = LlmInvestigationResponseSchema.parse(parsedJson);
      candidateFindings = validated.candidateFindings;
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      diagnostics.push(`Structured output validation failed: ${errMsg}`);
      return {
        candidateFindings: [],
        verifiedFindings: [],
        metadata: {
          modelId: this.config.modelId || this.provider!.name,
          promptVersion: PROMPT_VERSION,
          investigatorVersion: INVESTIGATOR_VERSION,
          contextFingerprint: context.contextFingerprint,
          costUsd,
          latencyMs,
          tokensUsed,
        },
        diagnostics,
      };
    }

    // Step 5: Hallucination Verification & Reference Check
    const validCandidates: CandidateFinding[] = [];
    for (const cand of candidateFindings) {
      const normCandFile = cand.file.replace(/\\/g, "/");
      if (!filesMap.has(normCandFile)) {
        diagnostics.push(`Discarded candidate '${cand.id}': Hallucinated file '${cand.file}' not present in repository.`);
        continue;
      }

      const invalidRef = cand.claims.find((c) => !filesMap.has(c.ref.file.replace(/\\/g, "/")));
      if (invalidRef) {
        diagnostics.push(`Discarded candidate '${cand.id}': Hallucinated claim reference file '${invalidRef.ref.file}'.`);
        continue;
      }

      validCandidates.push(cand);
    }

    // Step 6: Deterministic Verification of LLM Candidates
    const verifiedFindings: Finding[] = [];
    const indexedRepo = indexRepository(filesMap);
    const supabaseAnalyzer = new SupabaseAnalyzer(indexedRepo);
    const verifiers = new SecurityVerifiers();

    for (const cand of validCandidates) {
      const normFile = cand.file.replace(/\\/g, "/");
      const ep = indexedRepo.endpoints.find((e) => e.filePath === normFile);
      const q = indexedRepo.queries.find((query) => query.file === normFile);

      if (ep && q) {
        const tableStatus = supabaseAnalyzer.getTableSecurityStatus(q.table);
        const paramName = ep.params[0]?.name || "id";
        const verification = verifiers.verifyIdorScenario(ep, paramName, q, tableStatus);

        if (verification.isVulnerable) {
          const fingerprint = `llm.candidate:${normFile}:${cand.ruleId}:${cand.line}`;
          verifiedFindings.push(
            createFinding({
              ruleId: cand.ruleId || "idor.owner-column.v1",
              title: cand.title || "LLM Security Investigator Discovered Finding",
              severity: cand.severity || "high",
              confidenceTier: verification.unresolvedSteps.length > 0 ? "needs-review" : "likely",
              file: normFile,
              lineRange: { startLine: cand.line, endLine: cand.line + 2 },
              evidenceChain: verification.evidenceChain,
              unresolvedSteps: verification.unresolvedSteps,
              explanation: `${cand.rationale}\n\nDeterministic Verification: ${verification.verdictReason}`,
              fingerprint,
              origin: "llm",
            })
          );
        }
      }
    }

    const metadata: ModelMetadata = {
      modelId: this.config.modelId || this.provider!.name,
      promptVersion: PROMPT_VERSION,
      investigatorVersion: INVESTIGATOR_VERSION,
      contextFingerprint: context.contextFingerprint,
      costUsd,
      latencyMs: Date.now() - startMs,
      tokensUsed,
    };

    return {
      candidateFindings: validCandidates,
      verifiedFindings,
      metadata,
      diagnostics,
    };
  }

  private createEmptyResult(reason: string): LlmInvestigationResult {
    return {
      candidateFindings: [],
      verifiedFindings: [],
      metadata: {
        modelId: this.config.modelId || "none",
        promptVersion: PROMPT_VERSION,
        investigatorVersion: INVESTIGATOR_VERSION,
        contextFingerprint: "empty",
        costUsd: 0,
        latencyMs: 0,
      },
      diagnostics: [reason],
    };
  }
}
