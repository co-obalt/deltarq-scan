/**
 * AWS Scanner — Checks AWS IAM configuration for security issues
 * Uses locally configured ~/.aws/credentials (read-only)
 * 
 * Day 1-2: Local file checks only
 * Day 3: AWS SDK integration for live API checks (MFA, CloudTrail, IAM drift)
 */

import path from 'path';
import os from 'os';
import { readFileSafe, findFiles } from '../utils/fileUtils.js';

/**
 * Run AWS-related security scans
 * @param {string} targetDir - The project root directory
 * @returns {Promise<{ findings: Array, awsConfigured: boolean }>}
 */
export async function runAwsScanner(targetDir) {
  const findings = [];

  // Check if AWS credentials exist locally
  const awsDir = path.join(os.homedir(), '.aws');
  const credentialsFile = readFileSafe(path.join(awsDir, 'credentials'));
  const configFile = readFileSafe(path.join(awsDir, 'config'));

  const awsConfigured = !!(credentialsFile || configFile);

  // IAM-001: Scan for wildcard IAM policies in the project
  const policyFindings = await scanIAMPolicies(targetDir);
  findings.push(...policyFindings);

  // --- Day 3: AWS SDK Live Checks (stubbed for now) ---
  // IAM-003: MFA on root account
  // DRIFT-001: New IAM users without MFA
  // DRIFT-002: CloudTrail status

  if (awsConfigured) {
    // Placeholder for live AWS API checks
    // These will use AWS SDK v3 when integrated
    /*
    try {
      const mfaFinding = await checkRootMFA();
      if (mfaFinding) findings.push(mfaFinding);
      
      const driftFindings = await checkIAMDrift();
      findings.push(...driftFindings);
      
      const trailFinding = await checkCloudTrail();
      if (trailFinding) findings.push(trailFinding);
    } catch (err) {
      // AWS API call failed — permissions might be insufficient
    }
    */
  }

  return { findings, awsConfigured };
}

/**
 * Scan project files for IAM policy documents with overly permissive rules
 */
async function scanIAMPolicies(targetDir) {
  const findings = [];

  // Look for IAM policy JSON files
  const policyFiles = await findFiles(targetDir, [
    '**/*policy*.json',
    '**/*iam*.json',
    '**/trust-policy*.json',
    '**/role*.json',
    '**/*permissions*.json',
    '**/serverless.yml',
    '**/serverless.yaml',
    '**/template.yml',
    '**/template.yaml',
    '**/sam.yml',
    '**/sam.yaml',
  ]);

  for (const policyFile of policyFiles) {
    const content = readFileSafe(policyFile);
    if (!content) continue;

    const relPath = path.relative(targetDir, policyFile);

    // Check JSON policy files
    if (policyFile.endsWith('.json')) {
      try {
        const policy = JSON.parse(content);
        const statements = policy.Statement || (policy.PolicyDocument && policy.PolicyDocument.Statement) || [];

        for (const stmt of statements) {
          const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
          const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];

          const hasWildcardAction = actions.some(a => a === '*');
          const hasWildcardResource = resources.some(r => r === '*');

          if (hasWildcardAction && hasWildcardResource && stmt.Effect === 'Allow') {
            findings.push({
              rule: 'IAM-001',
              severity: 'CRITICAL',
              passed: false,
              detail: `Wildcard IAM policy (Action:* + Resource:*) found in ${relPath}`,
              file: relPath,
            });
            break; // One finding per file is enough
          }
        }
      } catch {
        // Not valid JSON or unexpected structure
      }
    }

    // Check YAML serverless/SAM templates for wildcard policies
    if (policyFile.endsWith('.yml') || policyFile.endsWith('.yaml')) {
      if (content.includes('"*"') || content.includes("'*'")) {
        // Rough check — look for Action: "*" and Resource: "*" patterns
        const hasWildcardAction = content.includes('Action') && 
                                  (content.includes("'*'") || content.includes('"*"'));
        const hasWildcardResource = content.includes('Resource') && 
                                    (content.includes("'*'") || content.includes('"*"'));

        if (hasWildcardAction && hasWildcardResource) {
          findings.push({
            rule: 'IAM-001',
            severity: 'CRITICAL',
            passed: false,
            detail: `Wildcard IAM policy detected in ${relPath} (serverless/SAM template)`,
            file: relPath,
          });
        }
      }
    }
  }

  return findings;
}
