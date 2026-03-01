#!/usr/bin/env node

/**
 * DevSecOps AI Team — MCP Server
 * Exposes security scanning tools as MCP tools via stdio transport.
 *
 * Tools:
 *   devsecops_scan       — Run a security scan
 *   devsecops_results    — Retrieve scan results in a given format
 *   devsecops_gate       — Evaluate severity policy gate
 *   devsecops_compliance — Cross-walk findings against compliance frameworks
 *   devsecops_status     — Check runner status and available images
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { execSync, execFileSync } from "node:child_process";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, "..");
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

function runShellCommand(cmd, options = {}) {
  const timeout = options.timeout || 120_000;
  try {
    const result = execSync(cmd, {
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
          enum: ["json", "sarif", "markdown", "html"],
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
          enum: ["json", "sarif", "markdown", "html"],
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
      "Map findings to compliance frameworks (OWASP, NIST, MITRE ATT&CK). Returns cross-walk matrix.",
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
            enum: ["owasp", "nist", "mitre"],
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
];

// ─── Tool Handlers ───

async function handleScan({ tool, target, rules, format }) {
  const dispatcher = resolve(RUNNER_DIR, "job-dispatcher.sh");
  if (!existsSync(dispatcher)) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: "job-dispatcher.sh not found. Ensure the runner/ directory is intact.",
        },
      ],
    };
  }

  const args = [dispatcher, "--tool", tool];
  if (target) args.push("--target", target);
  if (rules) args.push("--rules", rules);
  if (format) args.push("--format", format);

  const result = runCommand("bash", args, { timeout: 120_000 });

  // Extract job_id from output
  const jobMatch = result.output.match(/Job:\s*(job-[\w-]+)/);
  const jobId = jobMatch ? jobMatch[1] : null;

  // Try to read normalized results
  let findings = null;
  if (jobId) {
    const resultsDir = `/results/${jobId}`;
    const normalizedPath = resolve(resultsDir, "normalized.json");
    if (existsSync(normalizedPath)) {
      findings = readJsonFile(normalizedPath);
    }
  }

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            job_id: jobId,
            tool,
            target: target || "/workspace",
            success: result.success,
            exit_code: result.exitCode || 0,
            findings: findings?.findings || [],
            summary: findings?.summary || {},
            output: result.output,
            error: result.error || null,
          },
          null,
          2,
        ),
      },
    ],
  };
}

async function handleResults({ job_id, format }) {
  const collector = resolve(RUNNER_DIR, "result-collector.sh");
  if (!existsSync(collector)) {
    return {
      isError: true,
      content: [{ type: "text", text: "result-collector.sh not found." }],
    };
  }

  const fmt = format || "json";
  const result = runCommand(
    "bash",
    [collector, "--job-id", job_id, "--format", fmt],
    { timeout: 30_000 },
  );

  // Try to read the formatted output
  const resultsDir = `/results/${job_id}`;
  const formatExtMap = {
    json: "normalized.json",
    sarif: "results.sarif",
    markdown: "results.md",
    html: "results.html",
  };
  const outputFile = resolve(
    resultsDir,
    formatExtMap[fmt] || "normalized.json",
  );

  let content = result.output;
  if (existsSync(outputFile)) {
    try {
      content = readFileSync(outputFile, "utf-8");
    } catch {
      /* use command output */
    }
  }

  return {
    content: [{ type: "text", text: content }],
  };
}

async function handleGate({ results_file, role, policy_file }) {
  const policyPath =
    policy_file || resolve(MAPPINGS_DIR, "severity-policy.json");
  const policy = readJsonFile(policyPath);
  const results = readJsonFile(results_file);

  if (!policy) {
    return {
      isError: true,
      content: [{ type: "text", text: `Policy file not found: ${policyPath}` }],
    };
  }
  if (!results) {
    return {
      isError: true,
      content: [
        { type: "text", text: `Results file not found: ${results_file}` },
      ],
    };
  }

  // RBAC: resolve role from policy
  const roleName = role || policy.default_role || "developer";
  const roleConfig = policy.roles?.[roleName];
  if (!roleConfig) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: `Unknown role: ${roleName}. Available roles: ${Object.keys(policy.roles || {}).join(", ")}`,
        },
      ],
    };
  }

  const findings = results.findings || [];
  const summary = results.summary || {};
  const failOn = roleConfig.fail_on || ["CRITICAL"];
  const violations = [];

  for (const severity of failOn) {
    const key = severity.toLowerCase();
    const count = summary[key] || 0;
    if (count > 0) {
      violations.push({
        severity: severity.toUpperCase(),
        found: count,
      });
    }
  }

  const gate = violations.length === 0 ? "PASS" : "FAIL";

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            gate,
            role: roleName,
            fail_on: failOn,
            violations,
            summary,
            total_findings: findings.length,
            policy_file: policyPath,
          },
          null,
          2,
        ),
      },
    ],
  };
}

async function handleCompliance({ findings_file, frameworks }) {
  const results = readJsonFile(findings_file);
  if (!results) {
    return {
      isError: true,
      content: [
        { type: "text", text: `Findings file not found: ${findings_file}` },
      ],
    };
  }

  const targetFrameworks = frameworks || ["owasp", "nist", "mitre"];
  const mappings = {};

  for (const fw of targetFrameworks) {
    const mappingFile = resolve(MAPPINGS_DIR, `cwe-to-${fw}.json`);
    if (existsSync(mappingFile)) {
      mappings[fw] = readJsonFile(mappingFile) || {};
    }
  }

  const findings = results.findings || [];
  const crosswalk = findings
    .filter((f) => f.cwe_id)
    .map((f) => {
      const entry = {
        finding_id: f.id,
        cwe_id: f.cwe_id,
        severity: f.severity,
        title: f.title,
      };
      for (const [fw, mapping] of Object.entries(mappings)) {
        const cweKey = f.cwe_id.replace("CWE-", "");
        entry[fw] = mapping[cweKey] || mapping[f.cwe_id] || null;
      }
      return entry;
    });

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            frameworks: targetFrameworks,
            total_findings: findings.length,
            mapped_findings: crosswalk.length,
            unmapped: findings.length - crosswalk.length,
            crosswalk,
          },
          null,
          2,
        ),
      },
    ],
  };
}

async function handleStatus() {
  // Check Docker
  const dockerResult = runCommand(
    "docker",
    ["info", "--format", "{{.ServerVersion}}"],
    {
      timeout: 5_000,
    },
  );
  const dockerAvailable = dockerResult.success;
  const dockerVersion = dockerAvailable ? dockerResult.output : null;

  // Check available images
  const toolImages = {
    semgrep: "returntocorp/semgrep",
    gitleaks: "zricethezav/gitleaks",
    grype: "anchore/grype",
    trivy: "aquasec/trivy",
    checkov: "bridgecrew/checkov",
    zap: "ghcr.io/zaproxy/zaproxy",
    syft: "anchore/syft",
  };

  const availableTools = {};
  if (dockerAvailable) {
    const imagesResult = runCommand(
      "docker",
      ["images", "--format", "{{.Repository}}:{{.Tag}}"],
      { timeout: 5_000 },
    );
    const installedImages = imagesResult.success
      ? imagesResult.output.split("\n")
      : [];

    for (const [tool, image] of Object.entries(toolImages)) {
      availableTools[tool] = {
        image,
        installed: installedImages.some((i) => i.startsWith(image)),
      };
    }
  }

  // Check runner scripts
  const scripts = ["job-dispatcher.sh", "result-collector.sh"];
  const runnerStatus = {};
  for (const script of scripts) {
    runnerStatus[script] = existsSync(resolve(RUNNER_DIR, script));
  }

  // Check formatters
  const formatters = [
    "json-normalizer.sh",
    "sarif-formatter.sh",
    "markdown-formatter.sh",
    "html-formatter.sh",
    "dedup-findings.sh",
  ];
  const formatterStatus = {};
  for (const fmt of formatters) {
    formatterStatus[fmt] = existsSync(resolve(FORMATTER_DIR, fmt));
  }

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            docker: { available: dockerAvailable, version: dockerVersion },
            tools: availableTools,
            runner: runnerStatus,
            formatters: formatterStatus,
            mappings: readdirSync(MAPPINGS_DIR).filter((f) =>
              f.endsWith(".json"),
            ),
          },
          null,
          2,
        ),
      },
    ],
  };
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
  format: z.enum(["json", "sarif", "markdown", "html"]).optional(),
});

const ResultsSchema = z.object({
  job_id: z.string().min(1),
  format: z.enum(["json", "sarif", "markdown", "html"]).optional(),
});

const GateSchema = z.object({
  results_file: z.string().min(1),
  role: z.enum(["developer", "security-lead", "release-manager"]).optional(),
  policy_file: z.string().optional(),
});

const ComplianceSchema = z.object({
  findings_file: z.string().min(1),
  frameworks: z.array(z.enum(["owasp", "nist", "mitre"])).optional(),
});

const StatusSchema = z.object({}).passthrough();

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
  { name: "devsecops-mcp-server", version: "2.1.0" },
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
