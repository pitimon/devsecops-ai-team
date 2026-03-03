#!/usr/bin/env node

/**
 * DevSecOps AI Team — MCP Server
 * Exposes security scanning tools as MCP tools via stdio transport.
 *
 * Tools:
 *   devsecops_scan              — Run a security scan
 *   devsecops_results           — Retrieve scan results in a given format
 *   devsecops_gate              — Evaluate severity policy gate
 *   devsecops_compliance        — Cross-walk findings against compliance frameworks
 *   devsecops_status            — Check runner status and available images
 *   devsecops_compare           — Compare two scan results for trend analysis
 *   devsecops_compliance_status — Aggregate compliance status across all frameworks
 *   devsecops_suggest_fix       — Suggest remediation for a finding
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Support running as esbuild bundle (dist/server.js) — adjust ROOT_DIR accordingly
const isBundled = !existsSync(resolve(__dirname, "package.json"));
const ROOT_DIR = resolve(__dirname, isBundled ? "../.." : "..");
const RUNNER_DIR = resolve(ROOT_DIR, "runner");
const FORMATTER_DIR = resolve(ROOT_DIR, "formatters");
const MAPPINGS_DIR = resolve(ROOT_DIR, "mappings");

// ─── Helpers ───

function runCommand(file, args = [], options = {}) {
  const timeout = options.timeout || 120_000;
  try {
    const result = execFileSync(file, args, {
      encoding: "utf-8",
      timeout,
      cwd: options.cwd || ROOT_DIR,
      env: { ...process.env, ...options.env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { success: true, output: result.trim() };
  } catch (err) {
    return {
      success: false,
      output: err.stdout?.trim() || "",
      error: err.stderr?.trim() || err.message,
      exitCode: err.status,
    };
  }
}

function readJsonFile(filePath) {
  try {
    return JSON.parse(readFileSync(filePath, "utf-8"));
  } catch {
    return null;
  }
}

function mcpError(text) {
  return { isError: true, content: [{ type: "text", text }] };
}

function mcpJson(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}

function checkExistence(dir, fileList) {
  const status = {};
  for (const f of fileList) {
    status[f] = existsSync(resolve(dir, f));
  }
  return status;
}

// ─── Tool Definitions ───

const TOOLS = [
  {
    name: "devsecops_scan",
    description:
      "Run a security scan using a specified tool (semgrep, gitleaks, grype, trivy, checkov, zap, syft). Returns job_id and normalized findings.",
    inputSchema: {
      type: "object",
      properties: {
        tool: {
          type: "string",
          enum: [
            "semgrep",
            "gitleaks",
            "grype",
            "trivy",
            "checkov",
            "zap",
            "syft",
          ],
          description: "Security scanning tool to use",
        },
        target: {
          type: "string",
          description:
            "Target path or URL to scan (defaults to current workspace)",
        },
        rules: {
          type: "string",
          description: "Tool-specific rules/config (e.g., semgrep ruleset)",
        },
        format: {
          type: "string",
          enum: ["json", "sarif", "markdown", "html", "pdf", "csv"],
          description: "Output format (default: json)",
        },
      },
      required: ["tool"],
    },
  },
  {
    name: "devsecops_results",
    description:
      "Retrieve results for a completed scan job in the requested format.",
    inputSchema: {
      type: "object",
      properties: {
        job_id: {
          type: "string",
          description: "Job ID returned from devsecops_scan",
        },
        format: {
          type: "string",
          enum: ["json", "sarif", "markdown", "html", "pdf", "csv"],
          description: "Output format (default: json)",
        },
      },
      required: ["job_id"],
    },
  },
  {
    name: "devsecops_gate",
    description:
      "Evaluate scan results against RBAC severity policy. Returns PASS/FAIL with violation details based on role.",
    inputSchema: {
      type: "object",
      properties: {
        results_file: {
          type: "string",
          description: "Path to normalized JSON results file",
        },
        role: {
          type: "string",
          enum: ["developer", "security-lead", "release-manager"],
          description:
            "RBAC role determining gate strictness (default: developer)",
        },
        policy_file: {
          type: "string",
          description:
            "Path to severity policy JSON (defaults to mappings/severity-policy.json)",
        },
      },
      required: ["results_file"],
    },
  },
  {
    name: "devsecops_compliance",
    description:
      "Map findings to compliance frameworks (OWASP, NIST, MITRE ATT&CK, NCSA). Returns cross-walk matrix.",
    inputSchema: {
      type: "object",
      properties: {
        findings_file: {
          type: "string",
          description: "Path to normalized JSON findings file",
        },
        frameworks: {
          type: "array",
          items: {
            type: "string",
            enum: ["owasp", "nist", "mitre", "ncsa"],
          },
          description: "Frameworks to map against (default: all)",
        },
      },
      required: ["findings_file"],
    },
  },
  {
    name: "devsecops_status",
    description:
      "Check DevSecOps runner status: Docker availability, available tool images, and configuration.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "devsecops_compare",
    description:
      "Compare two scan results to show new, fixed, and unchanged findings. Returns trend analysis.",
    inputSchema: {
      type: "object",
      properties: {
        baseline_file: {
          type: "string",
          description: "Path to baseline/older scan results (normalized JSON)",
        },
        current_file: {
          type: "string",
          description: "Path to current/newer scan results (normalized JSON)",
        },
      },
      required: ["baseline_file", "current_file"],
    },
  },
  {
    name: "devsecops_compliance_status",
    description:
      "Aggregate compliance status across all 4 frameworks (OWASP, NIST, MITRE, NCSA) for a findings file. Returns per-framework coverage and gaps.",
    inputSchema: {
      type: "object",
      properties: {
        findings_file: {
          type: "string",
          description: "Path to normalized JSON findings file",
        },
      },
      required: ["findings_file"],
    },
  },
  {
    name: "devsecops_suggest_fix",
    description:
      "Suggest remediation for a finding based on CWE, OWASP category, and reference knowledge.",
    inputSchema: {
      type: "object",
      properties: {
        cwe_id: {
          type: "string",
          description: "CWE identifier (e.g., CWE-89)",
        },
        rule_id: {
          type: "string",
          description: "Semgrep rule ID (e.g., a03-sql-injection)",
        },
        finding_file: {
          type: "string",
          description: "Path to a specific finding JSON file",
        },
      },
    },
  },
];

// ─── Tool Handlers ───

function readNormalizedFindings(jobId) {
  if (!jobId) return null;
  const normalizedPath = resolve(`/results/${jobId}`, "normalized.json");
  return existsSync(normalizedPath) ? readJsonFile(normalizedPath) : null;
}

async function handleScan({ tool, target, rules, format }) {
  const dispatcher = resolve(RUNNER_DIR, "job-dispatcher.sh");
  if (!existsSync(dispatcher)) {
    return mcpError(
      "job-dispatcher.sh not found. Ensure the runner/ directory is intact.",
    );
  }

  const args = [dispatcher, "--tool", tool];
  if (target) args.push("--target", target);
  if (rules) args.push("--rules", rules);
  if (format) args.push("--format", format);

  const result = runCommand("bash", args, { timeout: 120_000 });
  const jobMatch = result.output.match(/Job:\s*(job-[\w-]+)/);
  const jobId = jobMatch ? jobMatch[1] : null;
  const findings = readNormalizedFindings(jobId);

  return mcpJson({
    job_id: jobId,
    tool,
    target: target || "/workspace",
    success: result.success,
    exit_code: result.exitCode || 0,
    findings: findings?.findings || [],
    summary: findings?.summary || {},
    output: result.output,
    error: result.error || null,
  });
}

const FORMAT_EXT_MAP = {
  json: "normalized.json",
  sarif: "results.sarif",
  markdown: "results.md",
  html: "results.html",
  pdf: "results.pdf",
  csv: "results.csv",
};

async function handleResults({ job_id, format }) {
  const collector = resolve(RUNNER_DIR, "result-collector.sh");
  if (!existsSync(collector)) {
    return mcpError("result-collector.sh not found.");
  }

  const fmt = format || "json";
  const result = runCommand(
    "bash",
    [collector, "--job-id", job_id, "--format", fmt],
    { timeout: 30_000 },
  );

  const outputFile = resolve(
    `/results/${job_id}`,
    FORMAT_EXT_MAP[fmt] || "normalized.json",
  );
  let content = result.output;
  if (existsSync(outputFile)) {
    try {
      content = readFileSync(outputFile, "utf-8");
    } catch {
      /* use command output */
    }
  }

  return { content: [{ type: "text", text: content }] };
}

function evaluateGateViolations(summary, failOn) {
  const violations = [];
  for (const severity of failOn) {
    const count = summary[severity.toLowerCase()] || 0;
    if (count > 0) {
      violations.push({ severity: severity.toUpperCase(), found: count });
    }
  }
  return violations;
}

async function handleGate({ results_file, role, policy_file }) {
  const policyPath =
    policy_file || resolve(MAPPINGS_DIR, "severity-policy.json");
  const policy = readJsonFile(policyPath);
  if (!policy) return mcpError(`Policy file not found: ${policyPath}`);
  const results = readJsonFile(results_file);
  if (!results) return mcpError(`Results file not found: ${results_file}`);

  const roleName = role || policy.default_role || "developer";
  const roleConfig = policy.roles?.[roleName];
  if (!roleConfig) {
    return mcpError(
      `Unknown role: ${roleName}. Available: ${Object.keys(policy.roles || {}).join(", ")}`,
    );
  }

  const summary = results.summary || {};
  const failOn = roleConfig.fail_on || ["CRITICAL"];
  const violations = evaluateGateViolations(summary, failOn);

  return mcpJson({
    gate: violations.length === 0 ? "PASS" : "FAIL",
    role: roleName,
    fail_on: failOn,
    violations,
    summary,
    total_findings: (results.findings || []).length,
    policy_file: policyPath,
  });
}

function loadMappings(frameworkList) {
  const mappings = {};
  for (const fw of frameworkList) {
    const file = resolve(MAPPINGS_DIR, `cwe-to-${fw}.json`);
    if (existsSync(file)) mappings[fw] = readJsonFile(file) || {};
  }
  return mappings;
}

function buildCrosswalk(findings, mappings) {
  return findings
    .filter((f) => f.cwe_id)
    .map((f) => {
      const entry = {
        finding_id: f.id,
        cwe_id: f.cwe_id,
        severity: f.severity,
        title: f.title,
      };
      for (const [fw, mapping] of Object.entries(mappings)) {
        const key = f.cwe_id.replace("CWE-", "");
        entry[fw] = mapping[key] || mapping[f.cwe_id] || null;
      }
      return entry;
    });
}

async function handleCompliance({ findings_file, frameworks }) {
  const results = readJsonFile(findings_file);
  if (!results) return mcpError(`Findings file not found: ${findings_file}`);

  const targetFrameworks = frameworks || ["owasp", "nist", "mitre", "ncsa"];
  const mappings = loadMappings(targetFrameworks);
  const findings = results.findings || [];
  const crosswalk = buildCrosswalk(findings, mappings);

  return mcpJson({
    frameworks: targetFrameworks,
    total_findings: findings.length,
    mapped_findings: crosswalk.length,
    unmapped: findings.length - crosswalk.length,
    crosswalk,
  });
}

const TOOL_IMAGES = {
  semgrep: "returntocorp/semgrep",
  gitleaks: "zricethezav/gitleaks",
  grype: "anchore/grype",
  trivy: "aquasec/trivy",
  checkov: "bridgecrew/checkov",
  zap: "ghcr.io/zaproxy/zaproxy",
  syft: "anchore/syft",
};

function checkDockerTools() {
  const dockerResult = runCommand(
    "docker",
    ["info", "--format", "{{.ServerVersion}}"],
    { timeout: 5_000 },
  );
  if (!dockerResult.success)
    return { available: false, version: null, tools: {} };

  const imagesResult = runCommand(
    "docker",
    ["images", "--format", "{{.Repository}}:{{.Tag}}"],
    { timeout: 5_000 },
  );
  const installed = imagesResult.success ? imagesResult.output.split("\n") : [];
  const tools = {};
  for (const [tool, image] of Object.entries(TOOL_IMAGES)) {
    tools[tool] = {
      image,
      installed: installed.some((i) => i.startsWith(image)),
    };
  }
  return { available: true, version: dockerResult.output, tools };
}

async function handleStatus() {
  const docker = checkDockerTools();

  return mcpJson({
    docker: { available: docker.available, version: docker.version },
    tools: docker.tools,
    runner: checkExistence(RUNNER_DIR, [
      "job-dispatcher.sh",
      "result-collector.sh",
    ]),
    formatters: checkExistence(FORMATTER_DIR, [
      "json-normalizer.sh",
      "sarif-formatter.sh",
      "markdown-formatter.sh",
      "html-formatter.sh",
      "dedup-findings.sh",
    ]),
    mappings: readdirSync(MAPPINGS_DIR).filter((f) => f.endsWith(".json")),
  });
}

async function handleCompare({ baseline_file, current_file }) {
  const baseline = readJsonFile(baseline_file);
  if (!baseline) return mcpError(`Baseline file not found: ${baseline_file}`);
  const current = readJsonFile(current_file);
  if (!current) return mcpError(`Current file not found: ${current_file}`);

  const baseFindings = baseline.findings || [];
  const currFindings = current.findings || [];

  // Match by rule_id + file + line_start for identity
  const baseKeys = new Set(
    baseFindings.map(
      (f) => `${f.rule_id}:${f.location?.file}:${f.location?.line_start}`,
    ),
  );
  const currKeys = new Set(
    currFindings.map(
      (f) => `${f.rule_id}:${f.location?.file}:${f.location?.line_start}`,
    ),
  );

  const newFindings = currFindings.filter(
    (f) =>
      !baseKeys.has(
        `${f.rule_id}:${f.location?.file}:${f.location?.line_start}`,
      ),
  );
  const fixedFindings = baseFindings.filter(
    (f) =>
      !currKeys.has(
        `${f.rule_id}:${f.location?.file}:${f.location?.line_start}`,
      ),
  );
  const unchanged = currFindings.filter((f) =>
    baseKeys.has(`${f.rule_id}:${f.location?.file}:${f.location?.line_start}`),
  );

  return mcpJson({
    baseline_total: baseFindings.length,
    current_total: currFindings.length,
    new_findings: newFindings.length,
    fixed_findings: fixedFindings.length,
    unchanged: unchanged.length,
    trend:
      currFindings.length < baseFindings.length
        ? "improving"
        : currFindings.length > baseFindings.length
          ? "degrading"
          : "stable",
    delta: currFindings.length - baseFindings.length,
    new: newFindings,
    fixed: fixedFindings,
  });
}

async function handleComplianceStatus({ findings_file }) {
  const results = readJsonFile(findings_file);
  if (!results) return mcpError(`Findings file not found: ${findings_file}`);

  const findings = results.findings || [];
  const frameworks = ["owasp", "nist", "mitre", "ncsa"];
  const mappings = loadMappings(frameworks);

  const status = {};
  for (const fw of frameworks) {
    const mapping = mappings[fw];
    if (!mapping) {
      status[fw] = { available: false, mapped: 0, unmapped: 0 };
      continue;
    }
    const mappingData = mapping.mappings || mapping;
    let mapped = 0;
    let unmapped = 0;
    const mappedCwes = [];
    const unmappedCwes = [];

    for (const f of findings) {
      if (!f.cwe_id) {
        unmapped++;
        continue;
      }
      const key = f.cwe_id;
      if (mappingData[key]) {
        mapped++;
        if (!mappedCwes.includes(key)) mappedCwes.push(key);
      } else {
        unmapped++;
        if (!unmappedCwes.includes(key)) unmappedCwes.push(key);
      }
    }
    status[fw] = {
      available: true,
      mapped,
      unmapped,
      coverage_pct:
        findings.length > 0 ? Math.round((mapped / findings.length) * 100) : 0,
      mapped_cwes: mappedCwes,
      unmapped_cwes: unmappedCwes,
    };
  }

  return mcpJson({
    total_findings: findings.length,
    frameworks: status,
  });
}

async function handleSuggestFix({ cwe_id, rule_id, finding_file }) {
  // If finding_file provided, extract cwe_id and rule_id from it
  let effectiveCwe = cwe_id;
  let effectiveRule = rule_id;

  if (finding_file) {
    const finding = readJsonFile(finding_file);
    if (finding) {
      effectiveCwe =
        effectiveCwe || finding.cwe_id || finding.findings?.[0]?.cwe_id;
      effectiveRule =
        effectiveRule || finding.rule_id || finding.findings?.[0]?.rule_id;
    }
  }

  if (!effectiveCwe && !effectiveRule) {
    return mcpError(
      "Could not determine CWE or rule ID. Provide cwe_id, rule_id, or a valid finding_file.",
    );
  }

  const suggestions = {
    cwe_id: effectiveCwe,
    rule_id: effectiveRule,
    remediation: [],
  };

  // Look up CWE in OWASP mapping for category context
  if (effectiveCwe) {
    const owaspMap = readJsonFile(resolve(MAPPINGS_DIR, "cwe-to-owasp.json"));
    if (owaspMap?.mappings?.[effectiveCwe]) {
      suggestions.owasp = owaspMap.mappings[effectiveCwe];
    }
    const nistMap = readJsonFile(resolve(MAPPINGS_DIR, "cwe-to-nist.json"));
    if (nistMap?.mappings?.[effectiveCwe]) {
      suggestions.nist = nistMap.mappings[effectiveCwe];
    }
  }

  // Check if rule is from custom rules — load fix from rules YAML
  if (effectiveRule) {
    const ruleFiles = [
      "a01-access-control-rules.yml",
      "a03-injection-rules.yml",
      "a09-logging-rules.yml",
      "a10-ssrf-rules.yml",
    ];
    for (const rf of ruleFiles) {
      const rulePath = resolve(ROOT_DIR, "rules", rf);
      if (existsSync(rulePath)) {
        try {
          const content = readFileSync(rulePath, "utf-8");
          // Simple YAML parse — find the rule by id and extract fix
          const ruleMatch = content.match(
            new RegExp(`id:\\s*${effectiveRule}[\\s\\S]*?(?=\\n  - id:|$)`),
          );
          if (ruleMatch) {
            const fixMatch = ruleMatch[0].match(
              /fix:\s*\|\n([\s\S]*?)(?=\n\s{4}\w|\n  - id:|$)/,
            );
            if (fixMatch) {
              suggestions.remediation.push({
                source: rf,
                fix: fixMatch[1].trim(),
              });
            }
            const msgMatch = ruleMatch[0].match(
              /message:\s*>\n\s*([\s\S]*?)(?=\n\s{4}\w)/,
            );
            if (msgMatch) {
              suggestions.description = msgMatch[1]
                .trim()
                .replace(/\n\s+/g, " ");
            }
          }
        } catch {
          /* skip */
        }
      }
    }
  }

  // Check reference files for broader guidance
  const refDir = resolve(ROOT_DIR, "skills", "references");
  if (existsSync(refDir)) {
    const refFiles = readdirSync(refDir).filter((f) => f.endsWith(".md"));
    suggestions.reference_files = refFiles;
  }

  return mcpJson(suggestions);
}

// ─── Zod Schemas ───

const ScanSchema = z.object({
  tool: z.enum([
    "semgrep",
    "gitleaks",
    "grype",
    "trivy",
    "checkov",
    "zap",
    "syft",
  ]),
  target: z.string().optional(),
  rules: z.string().optional(),
  format: z
    .enum(["json", "sarif", "markdown", "html", "pdf", "csv"])
    .optional(),
});

const ResultsSchema = z.object({
  job_id: z.string().min(1),
  format: z
    .enum(["json", "sarif", "markdown", "html", "pdf", "csv"])
    .optional(),
});

const GateSchema = z.object({
  results_file: z.string().min(1),
  role: z.enum(["developer", "security-lead", "release-manager"]).optional(),
  policy_file: z.string().optional(),
});

const ComplianceSchema = z.object({
  findings_file: z.string().min(1),
  frameworks: z.array(z.enum(["owasp", "nist", "mitre", "ncsa"])).optional(),
});

const StatusSchema = z.object({}).passthrough();

const CompareSchema = z.object({
  baseline_file: z.string().min(1),
  current_file: z.string().min(1),
});

const ComplianceStatusSchema = z.object({
  findings_file: z.string().min(1),
});

const SuggestFixSchema = z
  .object({
    cwe_id: z.string().optional(),
    rule_id: z.string().optional(),
    finding_file: z.string().optional(),
  })
  .refine((data) => data.cwe_id || data.rule_id || data.finding_file, {
    message: "At least one of cwe_id, rule_id, or finding_file is required",
  });

function validateInput(schema, args) {
  const result = schema.safeParse(args || {});
  if (!result.success) {
    const issues = result.error.issues.map(
      (i) => `${i.path.join(".")}: ${i.message}`,
    );
    return {
      valid: false,
      error: {
        isError: true,
        content: [
          {
            type: "text",
            text: `Input validation failed:\n${issues.join("\n")}`,
          },
        ],
      },
    };
  }
  return { valid: true, data: result.data };
}

// ─── Server Setup ───

const server = new Server(
  { name: "devsecops-mcp-server", version: "2.6.1" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "devsecops_scan": {
      const v = validateInput(ScanSchema, args);
      if (!v.valid) return v.error;
      return handleScan(v.data);
    }
    case "devsecops_results": {
      const v = validateInput(ResultsSchema, args);
      if (!v.valid) return v.error;
      return handleResults(v.data);
    }
    case "devsecops_gate": {
      const v = validateInput(GateSchema, args);
      if (!v.valid) return v.error;
      return handleGate(v.data);
    }
    case "devsecops_compliance": {
      const v = validateInput(ComplianceSchema, args);
      if (!v.valid) return v.error;
      return handleCompliance(v.data);
    }
    case "devsecops_status": {
      validateInput(StatusSchema, args);
      return handleStatus();
    }
    case "devsecops_compare": {
      const v = validateInput(CompareSchema, args);
      if (!v.valid) return v.error;
      return handleCompare(v.data);
    }
    case "devsecops_compliance_status": {
      const v = validateInput(ComplianceStatusSchema, args);
      if (!v.valid) return v.error;
      return handleComplianceStatus(v.data);
    }
    case "devsecops_suggest_fix": {
      const v = validateInput(SuggestFixSchema, args);
      if (!v.valid) return v.error;
      return handleSuggestFix(v.data);
    }
    default:
      return {
        isError: true,
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
      };
  }
});

// ─── Start ───

const transport = new StdioServerTransport();
await server.connect(transport);
