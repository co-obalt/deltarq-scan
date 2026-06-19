/**
 * Data & Database security rules
 * Checks database configuration for encryption, access, and resilience
 */

export const DB_001 = {
  id: 'DB-001',
  name: 'Postgres No SSL + Public Endpoint',
  severity: 'CRITICAL',
  category: 'Data',
  description: 'Your DB connection is unencrypted on a public-reachable host. MITM attack can dump your entire user table in transit.',
  remediation: 'Enable sslmode=require in your DATABASE_URL and ensure the host is not publicly accessible.',
  sopLink: 'https://www.postgresql.org/docs/current/ssl-tcp.html',
};

export const DB_002 = {
  id: 'DB-002',
  name: 'Connection Pool — No Max Limit',
  severity: 'MEDIUM',
  category: 'Data',
  description: 'Unbounded connection pools under load = DB crash. Also a common DoS attack vector.',
  remediation: 'Set a pool.max or pool.size limit in your database configuration (recommended: 10-20 for small apps).',
  sopLink: 'https://node-postgres.com/apis/pool',
};
