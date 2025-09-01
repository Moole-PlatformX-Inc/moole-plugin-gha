const core = require("@actions/core");
const fs = require("fs").promises;
const path = require("path");
const crypto = require("crypto");

// pin your server URL
const API_URL = "http://localhost:8081/api/tools/scanner/ci-cd/scan";

// fixed priority for top-level build file detection (first hit wins)
const CANDIDATE_BUILD_FILES = [
  "package.json",
  "go.mod",
  "pom.xml",
  "build.gradle",
  "composer.json",
];

function toBool(val, def = false) {
  if (val === undefined || val === null || val === "") return def;
  return ["true", "1", "yes", "y", "on"].includes(String(val).toLowerCase());
}

async function readIfExists(fullPath, name) {
  try {
    const buf = await fs.readFile(fullPath);
    return {
      name,
      path: name,
      size_bytes: buf.length,
      sha256: crypto.createHash("sha256").update(buf).digest("hex"),
      content_b64: buf.toString("base64"),
    };
  } catch (err) {
    if (err.code !== "ENOENT") core.warning(`Error reading ${name}: ${err.message}`);
    return null;
  }
}

function safeTruncate(str, max = 500) {
  if (!str) return "";
  return str.length <= max ? str : str.slice(0, max) + `… (+${str.length - max} more)`;
}

async function writeReportLink(reportUrl) {
  if (!reportUrl) return;
  // log a plain URL (clickable in logs)
  console.log(`Full report   : ${reportUrl}`);
  // add a clickable anchor to the Job Summary
  await core.summary
    .addRaw(`\n[**Open this for Full report**](${reportUrl})\n`)
    .write();
}

function normalizeSeverity(sev) {
  if (!sev) return "UNKNOWN";
  const s = String(sev).toUpperCase();
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(s) ? s : "UNKNOWN";
}
// ===== response parsing for Moole summary =====
// put this near the top, below safeTruncate()

// ---- CVSS parser (from your code, JS-ified) ----
function extractCvssMetricFields(cvssMetrics) {
  let baseSeverity, baseScore, attackVector;
  let metricsObj = {};

  if (typeof cvssMetrics === "string") {
    try { metricsObj = JSON.parse(cvssMetrics); } catch { metricsObj = {}; }
  } else if (cvssMetrics && typeof cvssMetrics === "object") {
    metricsObj = cvssMetrics;
  }

  const metricsArrays = Object.values(metricsObj);
  const allMetrics = metricsArrays.flat();
  const primary = allMetrics.find(m => m?.type === "Primary") || allMetrics.find(m => m?.type === "Secondary");

  if (primary && primary.cvssData) {
    baseSeverity = primary.cvssData.baseSeverity;
    baseScore = primary.cvssData.baseScore != null ? String(primary.cvssData.baseScore) : undefined;
    attackVector = primary.cvssData.attackVector;
  }
  return { baseSeverity, baseScore, attackVector };
}

// replace your old extractSeverityFromCve with this:
function extractSeverityFromCve(cve) {
  const { baseSeverity } = extractCvssMetricFields(cve?.cvssMetrics);
  return normalizeSeverity(baseSeverity);
}

function collectSummaryFromDeps(deps) {
  const gavs = new Set();
  const cveIds = new Set();
  const severities = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  const walk = (arr) => {
    for (const d of arr || []) {
      if (d.gav) gavs.add(d.gav);
      for (const cve of d.cves || []) {
        const id = cve.cveId || cve.id || cve.CVE || cve.cve;
        if (!id) continue;
        if (!cveIds.has(id)) {
          cveIds.add(id);
          const sev = extractSeverityFromCve(cve);
          severities[sev] = (severities[sev] || 0) + 1;
        }
      }
      walk(d.transitiveDependencies || []);
    }
  };
  walk(deps || []);
  return { packagesCount: gavs.size, vulnerabilitiesCount: cveIds.size, severities };
}

const c = {
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  magenta: (s) => `\x1b[35m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
};

function getBranchName(ref) {
  if (!ref) return "";
  if (ref.startsWith("refs/heads/")) return ref.slice("refs/heads/".length);
  if (ref.startsWith("refs/tags/")) return ref.slice("refs/tags/".length);
  return ref; // fallback (PR refs, etc.)
}

async function run() {
  try {
    // 🔐 tokens (body only). At least one must be present.
    const apiTokenBody = core.getInput("api_token") || "";
    const pat = core.getInput("pat") || "";
    if (apiTokenBody) core.setSecret(apiTokenBody);
    if (pat) core.setSecret(pat);
    if (!apiTokenBody && !pat) {
      core.setFailed('Either "api_token" or "pat" must be provided.');
      return;
    }

    // header key

    // project/env inputs
    const project = core.getInput("project", { required: true });
    const environment = core.getInput("environment", { required: true });

    const rootDir = core.getInput("root_dir") || ".";
    const failOnMissing = toBool(core.getInput("fail_on_missing_files"), true);
    const debugPayload = toBool(core.getInput("debug_payload"), false);
    const maxPayloadMB = Number(core.getInput("max_payload_mb") || "5");

    let metadata = {};
    const rawMeta = core.getInput("additional_fields");
    if (rawMeta) {
      try { metadata = JSON.parse(rawMeta); }
      catch (e) { core.setFailed(`additional_fields is not valid JSON: ${e.message}`); return; }
    }

    // GH context
    const repo = process.env.GITHUB_REPOSITORY || "";
    const commit_sha = process.env.GITHUB_SHA || "";
    const ref = process.env.GITHUB_REF || "";
    const run_id = process.env.GITHUB_RUN_ID || "";
    const run_attempt = process.env.GITHUB_RUN_ATTEMPT || "";
    const branch = getBranchName(ref);
    const repoUrl = repo ? `https://github.com/${repo}.git` : "";

    // 🔎 detect exactly one top-level build file in priority order
    let selectedBuild = null;
    for (const name of CANDIDATE_BUILD_FILES) {
      const full = path.join(process.env.GITHUB_WORKSPACE || process.cwd(), rootDir, name);
      const f = await readIfExists(full, name);
      if (f) {
        selectedBuild = f;
        core.info(`✓ Found top-level build file: ${name} (${f.size_bytes} bytes)`);
        break;
      } else {
        core.info(`- Missing ${name}, skipping`);
      }
    }

    if (!selectedBuild) {
      const msg = "No top-level build file found in the specified directory.";
      if (failOnMissing) { core.setFailed(msg); return; }
      core.warning(msg);
    }

    // 🔧 build the request body (singular build file)
    const payload = {
      projectId: project,
      envId: environment,
      tool: "GITACTIONS",
      repoUrl,
      branch,
      commitSha: commit_sha,
      ci_provider: "github_actions",
      run_id,
      run_attempt,
      timestamp: new Date().toISOString(),

      // tokens in the body
      projectToken: apiTokenBody || undefined,
      pat: pat || undefined,

      // single top-level build file
      buildFile: selectedBuild ? selectedBuild.name : undefined,
      buildFileContent: selectedBuild ? selectedBuild.content_b64 : undefined,

      metadata,
    };

    const asJson = JSON.stringify(payload);
    const bytes = Buffer.byteLength(asJson, "utf8");
    const maxBytes = maxPayloadMB * 1024 * 1024;
    if (bytes > maxBytes) {
      core.setFailed(`Payload (${bytes} bytes) exceeds limit (${maxPayloadMB} MB).`);
      return;
    }


    // headers: no Authorization; add x-api-key
    const headers = {
      "Content-Type": "application/json",
      "x-api-key": "AbCdEfGh123456",
    };

    const res = await fetch(API_URL, { method: "POST", headers, body: asJson });
    const text = await res.text();

    core.setOutput("files_found", selectedBuild ? "1" : "0");
    core.setOutput("response_code", String(res.status));
    core.setOutput("response_body", safeTruncate(text, 500));

    // summarize response (if JSON)
    let summary, reportUrl;
    try {
      const data = JSON.parse(text);
      reportUrl = data.generatedReportUri || data.reportUrl || data.reportURL || data.report || "";
      summary = collectSummaryFromDeps(data.dependencies || []);
    } catch {}

    if (!res.ok) {
      if (summary) {
        core.setOutput("packages_count", String(summary.packagesCount));
        core.setOutput("vulnerabilities_count", String(summary.vulnerabilitiesCount));
        core.setOutput("severity_counts", JSON.stringify(summary.severities));
        if (reportUrl) {
          core.setOutput("report_url", reportUrl);
          await writeReportLink(reportUrl);   // <-- add link even on error
        }
      }
      core.setFailed(`HTTP ${res.status}: ${safeTruncate(text, 500)}`);
      return;
    }

    if (summary) {
      const { packagesCount, vulnerabilitiesCount, severities } = summary;
      const sevStr =
        `${c.magenta(`Critical=${severities.CRITICAL || 0}`)}  ` +
        `${c.red(`High=${severities.HIGH || 0}`)}  ` +
        `${c.yellow(`Medium=${severities.MEDIUM || 0}`)}  ` +
        `${c.green(`Low=${severities.LOW || 0}`)}` +
        (severities.UNKNOWN ? `  ${c.dim(`Unknown=${severities.UNKNOWN}`)}` : "");

      console.log("");
      console.log(c.bold("Moole Security — Summary"));
      console.log(`Repository  : ${repoUrl}`);
      console.log(`Branch      : ${branch}`);
      console.log(`Packages    : ${packagesCount}`);
      console.log(`Vulnerabilities: ${vulnerabilitiesCount}`);
      console.log(`Severity    : ${sevStr}`);
      if (reportUrl) {
        core.setOutput("report_url", reportUrl);
        await writeReportLink(reportUrl);   // <-- clickable link in Job Summary
      }
      console.log("");

      core.setOutput("packages_count", String(packagesCount));
      core.setOutput("vulnerabilities_count", String(vulnerabilitiesCount));
      core.setOutput("severity_counts", JSON.stringify({
        CRITICAL: severities.CRITICAL || 0,
        HIGH: severities.HIGH || 0,
        MEDIUM: severities.MEDIUM || 0,
        LOW: severities.LOW || 0,
      }));
      if (reportUrl) core.setOutput("report_url", reportUrl);
    } else {
      core.info("No JSON summary parsed from response (skipping Moole summary).");
    }

  } catch (err) {
    core.setFailed(err.message || String(err));
  }
}

run();