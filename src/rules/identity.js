/**
 * Identity & Access Management rules
 * Checks IAM policies and credential management
 */

export const IAM_001 = {
  id: 'IAM-001',
  name: 'Wildcard IAM Policy',
  severity: 'CRITICAL',
  category: 'Identity',
  description: 'Your IAM policy grants God-mode access. Any compromised Lambda = full account takeover.',
  remediation: 'Apply least-privilege IAM policies. Replace "Action": "*" with specific service actions.',
  sopLink: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege',
};

export const IAM_002 = {
  id: 'IAM-002',
  name: 'Hardcoded Cloud/API Secrets',
  severity: 'HIGH',
  category: 'Identity',
  description: 'Hardcoded API tokens or cloud keys with no rotation = one git leak away from a massive breach or financial loss.',
  remediation: 'Use IAM roles, environment-based credentials, or secret managers (like AWS Secrets Manager or Vault) instead of hardcoding keys.',
  sopLink: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
};

export const IAM_003 = {
  id: 'IAM-003',
  name: 'No MFA on Root Account',
  severity: 'MEDIUM',
  category: 'Identity',
  description: 'Your AWS root account has no MFA. This is the master key to your entire infrastructure.',
  remediation: 'Enable MFA on the AWS root account immediately.',
  sopLink: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa',
};
