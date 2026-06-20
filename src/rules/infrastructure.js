/**
 * Infrastructure security rules
 * Checks Docker and container configuration for security gaps
 */

export const INFRA_001 = {
  id: 'INFRA-001',
  name: 'Docker Running as Root',
  severity: 'CRITICAL',
  category: 'Infrastructure',
  description: 'Your containers run as root. Container escape = full host compromise.',
  remediation: 'Add a USER directive in your Dockerfile to run as a non-root user.',
  sopLink: 'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user',
};

export const INFRA_002 = {
  id: 'INFRA-002',
  name: 'Database Port Exposed to All Interfaces',
  severity: 'HIGH',
  category: 'Infrastructure',
  description: 'Your Postgres port is exposed to the open internet via Docker. Shodan already knows about hosts like yours.',
  remediation: 'Bind database ports to 127.0.0.1 only (e.g., "127.0.0.1:5432:5432").',
  sopLink: 'https://docs.docker.com/compose/networking/',
};

export const INFRA_003 = {
  id: 'INFRA-003',
  name: 'Missing Lockfile (Supply Chain)',
  severity: 'HIGH',
  category: 'Infrastructure',
  description: 'No package-lock.json or yarn.lock found. This violates SOC 2 requirements for deterministic, reproducible builds and leaves you vulnerable to dependency hijacking.',
  remediation: 'Generate and commit a lockfile using your package manager (e.g., run npm install).',
  sopLink: 'https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json',
};

export const INFRA_004 = {
  id: 'INFRA-004',
  name: 'Insecure CI/CD Pipeline',
  severity: 'CRITICAL',
  category: 'Infrastructure',
  description: 'Your GitHub Actions workflow uses dangerous triggers (like pull_request_target). Malicious PRs could steal your repository secrets or tamper with your releases.',
  remediation: 'Remove the pull_request_target trigger, or carefully gate access using environment protection rules.',
  sopLink: 'https://securitylab.github.com/research/github-actions-preventing-pwn-requests/',
};
