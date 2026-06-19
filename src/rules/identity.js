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
  name: 'Long-Lived Access Keys in .env',
  severity: 'HIGH',
  category: 'Identity',
  description: 'Hardcoded AWS keys with no rotation = one git leak away from a $50,000 crypto mining bill.',
  remediation: 'Use IAM roles, environment-based credentials, or AWS SSO instead of hardcoded keys.',
  sopLink: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
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
