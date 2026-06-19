/**
 * Anonymizer — Strips all sensitive data from scan findings
 * Outputs only boolean pass/fail metadata + scores
 * NEVER includes raw values, secrets, file contents, or IPs
 */

import { v4 as uuidv4 } from 'uuid';

/**
 * Create an anonymous scan report from raw findings
 * @param {Array} findings - Raw scan findings
 * @param {{ score: number, grade: string, enterpriseReady: boolean }} scoreResult - Score calculation
 * @param {{ type: string }} projectInfo - Detected project type
 * @returns {Object} Anonymous JSON safe for upload
 */
export function anonymizeScanResults(findings, scoreResult, projectInfo) {
  // Deduplicate findings by rule ID (keep first occurrence)
  const seenRules = new Set();
  const uniqueFindings = [];
  for (const f of findings) {
    if (!seenRules.has(f.rule)) {
      seenRules.add(f.rule);
      uniqueFindings.push(f);
    }
  }

  return {
    scan_id: uuidv4(),
    timestamp: new Date().toISOString(),
    scanner_version: '0.1.0',
    project_type: projectInfo.type || 'unknown',

    // Score metadata only
    score: scoreResult.score,
    grade: scoreResult.grade,
    enterprise_ready: scoreResult.enterpriseReady,

    // Findings — ONLY rule ID, severity, and pass/fail boolean
    // NO file paths, NO secret values, NO detail strings
    findings: uniqueFindings.map(f => ({
      rule: f.rule,
      severity: f.severity,
      passed: f.passed,
    })),

    // Aggregate stats
    drift_detected: uniqueFindings.some(f => f.severity === 'DRIFT' && !f.passed),
    compliance_gap_count: uniqueFindings.filter(f => !f.passed).length,
  };
}

/**
 * Validate that the anonymous payload contains no secrets
 * Extra safety check before upload
 */
export function validateNoSecrets(payload) {
  const json = JSON.stringify(payload);

  // Pattern checks — these should NEVER appear in upload payload
  const forbiddenPatterns = [
    /AKIA[0-9A-Z]{16}/,           // AWS Access Key ID
    /[0-9a-zA-Z/+]{40}/,          // AWS Secret Key (40 char base64)
    /-----BEGIN.*PRIVATE KEY-----/, // PEM private keys
    /postgres:\/\//,               // DB connection strings
    /mysql:\/\//,
    /mongodb:\/\//,
    /password\s*[:=]\s*\S+/i,     // Password patterns
  ];

  for (const pattern of forbiddenPatterns) {
    if (pattern.test(json)) {
      throw new Error(
        `SAFETY CHECK FAILED: Upload payload may contain sensitive data matching pattern: ${pattern.source}. Upload aborted.`
      );
    }
  }

  return true;
}
