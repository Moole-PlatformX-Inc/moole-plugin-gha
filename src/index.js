const core = require("@actions/core");
const fs = require("fs").promises;
const path = require("path");
const crypto = require("crypto");
const API_URL = "http://localhost:8081/api/tools/scanner/ci-cd/scan";

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
    if (err.code !== "ENOENT") {
      core.warning(`Error reading ${name}: ${err.message}`);
    }
    return null; // not found or error -> skip
  }
}

function safeTruncate(str, max = 500) {
  if (!str) return "";
  if (str.length <= max) return str;
  return str.slice(0, max) + `… (+${str.length - max} more)`;
}

// ----- Moole summary helpers -----
function normalizeSeverity(sev) {
  if (!sev) return "UNKNOWN";
  const s = String(sev).toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(s)) return s;
  return "UNKNOWN";
}

// cvssMetrics may be an object OR a JSON string. Try both.
function extractSeverityFromCve(cve) {
  if (!cve) return "UNKNOWN";
  if (cve.baseSeverity) return normalizeSeverity(cve.baseSeverity);

  let metrics = cve.cvssMetrics;
  if (!metrics) return "UNKNOWN";
  if (typeof metrics === "string") {
    try { metrics = JSON.parse(metrics); } catch { return "UNKNOWN"; }
  }

  // v3.1 or v3.0 shapes
  const paths = [
    ["cvssMetricV31", 0, "cvssData", "baseSeverity"],
    ["cvssMetricV30", 0, "cvssData", "baseSeverity"],
  ];
  for (const p of paths) {
    let cur = metrics;
    for (const key of p) cur = cur?.[key];
    if (cur) return normalizeSeverity(cur);
  }
  return "UNKNOWN";
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

  return {
    packagesCount: gavs.size,
    vulnerabilitiesCount: cveIds.size,
    severities // includes UNKNOWN if any could not be parsed
  };
}

const c = {
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  magenta: (s) => `\x1b[35m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
};

async function run() {
  try {
    const apiToken = core.getInput("api_token") || "";
    if (apiToken) core.setSecret(apiToken);

    const userToken = core.getInput("user_token", { required: true });
    if (userToken) core.setSecret(userToken);

    const project = core.getInput("project_name", { required: true });
    const environment = core.getInput("environment", { required: true });
    const rootDir = core.getInput("root_dir") || ".";
    const fileList = core
      .getInput("file_list")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    const failOnMissing = toBool(core.getInput("fail_on_missing_files"), false);
    const debugPayload = toBool(core.getInput("debug_payload"), false);
    const maxPayloadMB = Number(core.getInput("max_payload_mb") || "5");

    let metadata = {};
    const rawMeta = core.getInput("additional_fields");
    if (rawMeta) {
      try {
        metadata = JSON.parse(rawMeta);
      } catch (e) {
        core.setFailed(`additional_fields is not valid JSON: ${e.message}`);
        return;
      }
    }

    const repo = process.env.GITHUB_REPOSITORY || "";
    const commit_sha = process.env.GITHUB_SHA || "";
    const ref = process.env.GITHUB_REF || "";
    const run_id = process.env.GITHUB_RUN_ID || "";
    const run_attempt = process.env.GITHUB_RUN_ATTEMPT || "";

    const filesPayload = [];
    for (const name of fileList) {
      const full = path.join(process.env.GITHUB_WORKSPACE || process.cwd(), rootDir, name);
      const fileData = await readIfExists(full, name);
      if (fileData) {
        filesPayload.push(fileData);
        core.info(`✓ Found ${name} (${fileData.size_bytes} bytes)`);
      } else {
        core.info(`- Missing ${name}, skipping`);
      }
    }

    if (filesPayload.length === 0) {
      const msg = "No target files were found in the specified directory.";
      if (failOnMissing) {
        core.setFailed(msg);
        return;
      } else {
        core.warning(msg);
      }
    }

    const payload = {
      project,
      environment,
      ci_provider: "github_actions",
      repo,
      ref,
      commit_sha,
      run_id,
      run_attempt,
      timestamp: new Date().toISOString(),
      // include user-provided token in the BODY (as requested)
      user_token: userToken,
      files: filesPayload,
      metadata,
    };

    // Size guardrail
    const asJson = JSON.stringify(payload);
    const bytes = Buffer.byteLength(asJson, "utf8");
    const maxBytes = maxPayloadMB * 1024 * 1024;
    if (bytes > maxBytes) {
      core.setFailed(
        `Payload (${bytes} bytes) exceeds limit (${maxPayloadMB} MB). Consider reducing files or raising max_payload_mb.`
      );
      return;
    }

    if (debugPayload) {
      const peek = {
        ...payload,
        user_token: "<redacted>",
        files: payload.files.map(f => ({
          name: f.name,
          size_bytes: f.size_bytes,
          sha256: f.sha256,
          content_b64_first_80: f.content_b64.slice(0, 80)
        }))
      };
      core.info(`Debug peek (truncated): ${JSON.stringify(peek, null, 2)}`);
    }

    // POST
    const headers = { "Content-Type": "application/json" };
    if (apiToken) headers["Authorization"] = `Bearer ${apiToken}`;

    const res = await fetch(API_URL, {
      method: "POST",
      headers,
      body: asJson,
    });

    const text = await res.text();
    core.setOutput("files_found", String(filesPayload.length));
    core.setOutput("response_code", String(res.status));
    core.setOutput("response_body", safeTruncate(text, 500));

    // Try to parse and summarize whatever we got back
    let summary;
    let reportUrl;
    try {
      const data = JSON.parse(text);
      const deps = data.dependencies || [];
      reportUrl = data.reportUrl || data.reportURL || data.report || "";
      summary = collectSummaryFromDeps(deps);
    } catch {
      // maybe not JSON, we’ll just skip summary
    }

    if (!res.ok) {
      // show server error and bail
      if (summary) {
        // still expose parsed counters if we managed to parse the body
        core.setOutput("packages_count", String(summary.packagesCount));
        core.setOutput("vulnerabilities_count", String(summary.vulnerabilitiesCount));
        core.setOutput("severity_counts", JSON.stringify(summary.severities));
        if (reportUrl) core.setOutput("report_url", reportUrl);
      }
      core.setFailed(`HTTP ${res.status}: ${safeTruncate(text, 500)}`);
      return;
    }

    // Pretty console summary (Moole-style)
    if (summary) {
      const { packagesCount, vulnerabilitiesCount, severities } = summary;
      const sevStr =
        `${c.magenta(`Critical=${severities.CRITICAL || 0}`)}  ` +
        `${c.red(`High=${severities.HIGH || 0}`)}  ` +
        `${c.yellow(`Medium=${severities.MEDIUM || 0}`)}  ` +
        `${c.green(`Low=${severities.LOW || 0}`)}` +
        (severities.UNKNOWN ? `  ${c.dim(`Unknown=${severities.UNKNOWN}`)}` : "");

      console.log(""); // spacer
      console.log(c.bold("Moole Security — Summary"));
      console.log(`Repository  : https://github.com/${repo}.git`);
      console.log(`Branch      : ${ref}`);
      console.log(`Packages    : ${packagesCount}`);
      console.log(`Vulnerabilities: ${vulnerabilitiesCount}`);
      console.log(`Severity    : ${sevStr}`);
      if (reportUrl) console.log(`Report      : ${reportUrl}`);
      console.log(""); // spacer

      // expose as outputs for downstream steps
      core.setOutput("packages_count", String(packagesCount));
      core.setOutput("vulnerabilities_count", String(vulnerabilitiesCount));
      core.setOutput("severity_counts", JSON.stringify({
        CRITICAL: severities.CRITICAL || 0,
        HIGH: severities.HIGH || 0,
        MEDIUM: severities.MEDIUM || 0,
        LOW: severities.LOW || 0
      }));
      if (reportUrl) core.setOutput("report_url", reportUrl);
    } else {
      core.info("No JSON summary parsed from response (skipping Moole summary).");
    }

    core.info(`✅ Sent payload successfully (HTTP ${res.status})`);
  } catch (err) {
    core.setFailed(err.message || String(err));
  }
}

run();