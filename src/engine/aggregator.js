/**
 * Scoring Engine — Aggregates scan findings into a security score
 * Weighted scoring: CRITICAL=40, HIGH=20, MEDIUM=10, DRIFT=5
 */

const SEVERITY_WEIGHTS = {
  CRITICAL: 40,
  HIGH: 20,
  MEDIUM: 10,
  DRIFT: 5,
};

/**
 * Calculate the overall security score from findings
 * @param {Array<{ rule: string, severity: string, passed: boolean }>} findings
 * @returns {{ score: number, grade: string, label: string, enterpriseReady: boolean, breakdown: Object }}
 */
export function calculateScore(findings) {
  const failedFindings = findings.filter(f => !f.passed);

  let deductions = 0;
  const breakdown = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    DRIFT: 0,
  };

  // Deduplicate by rule ID — only count each rule once
  const seenRules = new Set();
  for (const f of failedFindings) {
    if (seenRules.has(f.rule)) continue;
    seenRules.add(f.rule);

    const weight = SEVERITY_WEIGHTS[f.severity] || 0;
    deductions += weight;
    breakdown[f.severity] = (breakdown[f.severity] || 0) + 1;
  }

  const score = Math.max(0, 100 - deductions);

  let grade, label;
  if (score >= 90) {
    grade = 'A';
    label = 'Excellent';
  } else if (score >= 80) {
    grade = 'B';
    label = 'Acceptable';
  } else if (score >= 60) {
    grade = 'C';
    label = 'At Risk';
  } else if (score >= 40) {
    grade = 'D';
    label = 'Vulnerable';
  } else {
    grade = 'F';
    label = 'Critical Exposure';
  }

  const criticalCount = breakdown.CRITICAL || 0;
  const enterpriseReady = score >= 85 && criticalCount === 0;

  return {
    score,
    grade,
    label,
    enterpriseReady,
    breakdown,
    totalFindings: failedFindings.length,
    uniqueRules: seenRules.size,
    deductions,
  };
}

/**
 * Get the SOC 2 compliance gap count
 * Each failed unique rule = 1 control gap
 */
export function getComplianceGapCount(findings) {
  const failedRules = new Set(
    findings.filter(f => !f.passed).map(f => f.rule)
  );
  return failedRules.size;
}

/**
 * Estimate remediation effort based on findings
 */
export function estimateRemediationEffort(findings) {
  const gaps = getComplianceGapCount(findings);
  if (gaps === 0) return 'None needed';
  if (gaps <= 2) return '1–2 days';
  if (gaps <= 5) return '3–5 days without guidance';
  if (gaps <= 8) return '1–2 weeks without guidance';
  return '2+ weeks — consider professional audit';
}
