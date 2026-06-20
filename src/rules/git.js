/**
 * Git Configuration & Secret Exposure rules
 * Checks for gitignore configuration and git history leaks
 */

export const GIT_001 = {
  id: 'GIT-001',
  name: 'Git Secret & Config Exposure',
  severity: 'MEDIUM',
  category: 'Git Configuration',
  description: 'Secrets or sensitive files are tracked in git or not excluded in .gitignore, exposing credentials in repository history.',
  remediation: 'Add .env and credential files to .gitignore and purge any existing secrets from git history using git-filter-repo.',
  sopLink: 'https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning',
};
