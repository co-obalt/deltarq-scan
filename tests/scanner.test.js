import { describe, it, expect } from 'vitest';
import { calculateScore, getComplianceGapCount, estimateRemediationEffort } from '../src/engine/aggregator.js';
import { anonymizeScanResults, validateNoSecrets } from '../src/engine/anonymizer.js';

describe('Scoring Engine Tests', () => {
  it('should calculate perfect score when there are no findings', () => {
    const findings = [];
    const result = calculateScore(findings);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A');
    expect(result.enterpriseReady).toBe(true);
  });

  it('should deduct scores correctly based on severities', () => {
    const findings = [
      { rule: 'DB-001', severity: 'CRITICAL', passed: false }, // -40
      { rule: 'IAM-002', severity: 'HIGH', passed: false },    // -20
      { rule: 'DB-002', severity: 'MEDIUM', passed: false },   // -10
    ];
    const result = calculateScore(findings);
    expect(result.score).toBe(30); // 100 - 70 = 30
    expect(result.grade).toBe('F');
    expect(result.enterpriseReady).toBe(false);
  });

  it('should estimate remediation effort correctly', () => {
    const findings = [
      { rule: 'DB-001', severity: 'CRITICAL', passed: false },
      { rule: 'IAM-002', severity: 'HIGH', passed: false },
    ];
    expect(getComplianceGapCount(findings)).toBe(2);
    expect(estimateRemediationEffort(findings)).toBe('1–2 days');
  });
});

describe('Anonymizer Safety Tests', () => {
  it('should anonymize results without exposing raw details', () => {
    const findings = [
      { rule: 'IAM-001', severity: 'CRITICAL', passed: false, detail: 'Secret key leaked', file: '.env' },
    ];
    const scoreResult = calculateScore(findings);
    const projectInfo = { type: 'Node.js' };

    const anonymous = anonymizeScanResults(findings, scoreResult, projectInfo);
    expect(anonymous.findings[0]).not.toHaveProperty('detail');
    expect(anonymous.findings[0]).not.toHaveProperty('file');
    expect(anonymous.findings[0].rule).toBe('IAM-001');
    expect(anonymous.findings[0].passed).toBe(false);
  });

  it('should block payload if it contains sensitive raw credentials', () => {
    const payload = {
      scan_id: '123',
      findings: [
        { rule: 'IAM-002', passed: false, value: 'AKIAIOSFODNN7EXAMPLE' } // AWS access key
      ]
    };
    expect(() => validateNoSecrets(payload)).toThrow(/SAFETY CHECK FAILED/);
  });
});
