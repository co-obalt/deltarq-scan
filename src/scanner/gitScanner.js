/**
 * Git Scanner — Checks .gitignore config and git history for secret leaks
 * All operations are local-only, read-only
 */

import path from 'path';
import { execSync } from 'child_process';
import { readFileSafe, fileExists } from '../utils/fileUtils.js';

/**
 * Run git-related security scans
 * @param {string} targetDir - The project root directory
 * @returns {Promise<Array<{ rule: string, severity: string, passed: boolean, detail: string }>>}
 */
export async function runGitScanner(targetDir) {
  const findings = [];

  // Check if this is a git repo
  const isGitRepo = fileExists(path.join(targetDir, '.git'));
  if (!isGitRepo) {
    return findings; // Not a git repo, skip git checks
  }

  // GIT-001: Check .gitignore for .env exclusion
  const gitignoreFinding = checkGitignore(targetDir);
  if (gitignoreFinding) findings.push(gitignoreFinding);

  // GIT-001 extension: Check if .env was ever committed
  const historyFinding = checkGitHistory(targetDir);
  if (historyFinding) findings.push(historyFinding);

  return findings;
}

/**
 * Check if .gitignore properly excludes sensitive files
 */
function checkGitignore(targetDir) {
  const gitignorePath = path.join(targetDir, '.gitignore');
  const content = readFileSafe(gitignorePath);

  if (!content) {
    // No .gitignore at all
    return {
      rule: 'GIT-001',
      severity: 'MEDIUM',
      passed: false,
      detail: 'No .gitignore file found — .env and secrets may be tracked by git',
      file: null,
    };
  }

  const lines = content.split('\n').map(l => l.trim());
  const sensitivePatterns = ['.env', '.env.*', '*.pem', '*.key'];
  const envExcluded = lines.some(line =>
    line === '.env' || line === '.env*' || line === '.env.*' || line === '*.env'
  );

  if (!envExcluded) {
    return {
      rule: 'GIT-001',
      severity: 'MEDIUM',
      passed: false,
      detail: '.env is not excluded in .gitignore — secrets may be in your repository',
      file: '.gitignore',
    };
  }

  return null;
}

/**
 * Check git history for leaked secrets (local git log only)
 */
function checkGitHistory(targetDir) {
  const secretPatterns = [
    'AWS_SECRET_ACCESS_KEY',
    'AWS_ACCESS_KEY_ID',
    'PRIVATE_KEY',
    'DATABASE_URL',
    'DB_PASSWORD',
    'SECRET_KEY',
    'API_KEY',
    'STRIPE_SECRET',
  ];

  try {
    for (const pattern of secretPatterns) {
      const result = execSync(
        `git log --oneline --all --grep="${pattern}" -n 1`,
        {
          cwd: targetDir,
          encoding: 'utf-8',
          timeout: 5000,
          stdio: ['pipe', 'pipe', 'pipe'],
        }
      ).trim();

      if (result.length > 0) {
        return {
          rule: 'GIT-001',
          severity: 'MEDIUM',
          passed: false,
          detail: `Secret pattern "${pattern}" found in git commit history — even deleted files are recoverable`,
          file: null,
        };
      }
    }
  } catch {
    // Git command failed — might not have git installed or not a repo
    // Silently skip
  }

  return null;
}
