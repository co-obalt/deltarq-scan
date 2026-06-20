import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import path from 'path';
import { runFileScanner } from '../src/scanner/fileScanner.js';

const TEMP_DIR = path.resolve('./tests/temp_test_dir');

describe('Security Rules Scanning Tests', () => {
  // Setup clean temp directory before all tests
  beforeAll(() => {
    if (fs.existsSync(TEMP_DIR)) {
      fs.rmSync(TEMP_DIR, { recursive: true, force: true });
    }
    fs.mkdirSync(TEMP_DIR, { recursive: true });
  });

  // Cleanup temp directory after all tests
  afterAll(() => {
    if (fs.existsSync(TEMP_DIR)) {
      fs.rmSync(TEMP_DIR, { recursive: true, force: true });
    }
  });

  it('should detect INFRA-003 (Missing Lockfile) when package.json exists but no lockfile', async () => {
    const testProj = path.join(TEMP_DIR, 'missing-lockfile');
    fs.mkdirSync(testProj, { recursive: true });
    fs.writeFileSync(path.join(testProj, 'package.json'), JSON.stringify({ name: 'test' }));

    const findings = await runFileScanner(testProj);
    const lockFinding = findings.find(f => f.rule === 'INFRA-003');
    expect(lockFinding).toBeDefined();
    expect(lockFinding.passed).toBe(false);
    expect(lockFinding.detail).toContain('no lockfile found');

    // Add a lockfile and verify the issue goes away
    fs.writeFileSync(path.join(testProj, 'package-lock.json'), '{}');
    const newFindings = await runFileScanner(testProj);
    const newLockFinding = newFindings.find(f => f.rule === 'INFRA-003');
    expect(newLockFinding).toBeUndefined();
  });

  it('should detect INFRA-004 (Insecure CI/CD) when workflow uses pull_request_target', async () => {
    const testProj = path.join(TEMP_DIR, 'insecure-ci');
    const workflowsDir = path.join(testProj, '.github/workflows');
    fs.mkdirSync(workflowsDir, { recursive: true });

    // Write insecure workflow
    fs.writeFileSync(
      path.join(workflowsDir, 'test-ci.yml'),
      'on:\n  pull_request_target:\n    branches: [main]\n'
    );

    const findings = await runFileScanner(testProj);
    const ciFinding = findings.find(f => f.rule === 'INFRA-004');
    expect(ciFinding).toBeDefined();
    expect(ciFinding.passed).toBe(false);
    expect(ciFinding.detail).toContain('pull_request_target');

    // Write secure workflow and verify the issue goes away
    fs.writeFileSync(
      path.join(workflowsDir, 'test-ci.yml'),
      'on:\n  pull_request:\n    branches: [main]\n'
    );
    const newFindings = await runFileScanner(testProj);
    const newCiFinding = newFindings.find(f => f.rule === 'INFRA-004');
    expect(newCiFinding).toBeUndefined();
  });

  it('should detect IAM-002 (Hardcoded Cloud/API Secrets) for Stripe, Slack, and GitHub keys', async () => {
    const testProj = path.join(TEMP_DIR, 'secret-keys');
    fs.mkdirSync(testProj, { recursive: true });

    // Test Stripe key
    fs.writeFileSync(path.join(testProj, '.env'), 'STRIPE_API_KEY=sk_live_mockkeystripe\n');
    let findings = await runFileScanner(testProj);
    let secretFinding = findings.find(f => f.rule === 'IAM-002');
    expect(secretFinding).toBeDefined();
    expect(secretFinding.detail).toContain('Stripe Live Secret');

    // Test Slack token
    fs.writeFileSync(path.join(testProj, '.env'), 'SLACK_TOKEN=xoxb-mockkeyslack\n');
    findings = await runFileScanner(testProj);
    secretFinding = findings.find(f => f.rule === 'IAM-002');
    expect(secretFinding).toBeDefined();
    expect(secretFinding.detail).toContain('Slack Token');

    // Test GitHub token
    fs.writeFileSync(path.join(testProj, '.env'), 'GH_TOKEN=ghp_mockkeygithubAAAAAAAAAAAAAAAAAAAAAAA\n');
    findings = await runFileScanner(testProj);
    secretFinding = findings.find(f => f.rule === 'IAM-002');
    expect(secretFinding).toBeDefined();
    expect(secretFinding.detail).toContain('GitHub Token');
  });
});
