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
