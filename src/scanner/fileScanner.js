/**
 * File Scanner — Scans .env, Dockerfile, docker-compose.yml for security issues
 * This is the core scanner that checks local config files
 */

import path from 'path';
import yaml from 'js-yaml';
import { readFileSafe, findFiles, parseEnvContent } from '../utils/fileUtils.js';

/**
 * Run all file-based scans on the target directory
 * @param {string} targetDir - The project root directory
 * @returns {Promise<Array<{ rule: string, severity: string, passed: boolean, detail: string }>>}
 */
export async function runFileScanner(targetDir) {
  const findings = [];

  // Scan .env files
  const envFindings = await scanEnvFiles(targetDir);
  findings.push(...envFindings);

  // Scan Dockerfiles
  const dockerFindings = await scanDockerfiles(targetDir);
  findings.push(...dockerFindings);

  // Scan docker-compose files
  const composeFindings = await scanDockerCompose(targetDir);
  findings.push(...composeFindings);

  // Scan for audit logging patterns
  const logFindings = await scanForAuditLogs(targetDir);
  findings.push(...logFindings);

  return findings;
}

/**
 * Scan .env files for database and credential issues
 */
async function scanEnvFiles(targetDir) {
  const findings = [];
  const envFiles = await findFiles(targetDir, ['.env', '.env.*', '**/.env', '!.env.example']);

  for (const envFile of envFiles) {
    const content = readFileSafe(envFile);
    if (!content) continue;

    const parsed = parseEnvContent(content);
    const relPath = path.relative(targetDir, envFile);

    // DB-001: Check DATABASE_URL for sslmode=disable or public host
    const dbUrl = parsed.DATABASE_URL || parsed.DB_URL || parsed.POSTGRES_URL;
    if (dbUrl) {
      const hasSSLDisabled = dbUrl.includes('sslmode=disable') || !dbUrl.includes('sslmode');
      const isPublicHost = !isPrivateHost(dbUrl);

      if (hasSSLDisabled && isPublicHost) {
        findings.push({
          rule: 'DB-001',
          severity: 'CRITICAL',
          passed: false,
          detail: `Unencrypted DB connection on public host found in ${relPath}`,
          file: relPath,
        });
      }
    }

    // Also check POSTGRES_HOST directly
    const pgHost = parsed.POSTGRES_HOST || parsed.DB_HOST;
    const pgSSL = parsed.POSTGRES_SSLMODE || parsed.DB_SSLMODE;
    if (pgHost && !isPrivateHost(`host://${pgHost}`) && (!pgSSL || pgSSL === 'disable')) {
      findings.push({
        rule: 'DB-001',
        severity: 'CRITICAL',
        passed: false,
        detail: `Postgres host "${pgHost}" appears publicly accessible without SSL in ${relPath}`,
        file: relPath,
      });
    }

    // IAM-002: Check for hardcoded AWS keys
    const hasAccessKey = parsed.AWS_ACCESS_KEY_ID || parsed.AWS_ACCESS_KEY;
    const hasSecretKey = parsed.AWS_SECRET_ACCESS_KEY || parsed.AWS_SECRET_KEY;
    if (hasAccessKey && hasSecretKey) {
      findings.push({
        rule: 'IAM-002',
        severity: 'HIGH',
        passed: false,
        detail: `Hardcoded AWS credentials found in ${relPath}`,
        file: relPath,
      });
    }

    // DB-002: Check for connection pool config
    const hasPoolMax = parsed.DB_POOL_MAX || parsed.POOL_MAX || parsed.DB_POOL_SIZE;
    if (dbUrl && !hasPoolMax) {
      // Check if there's any pool config hint in the .env
      const envContent = content.toLowerCase();
      const hasPoolConfig = envContent.includes('pool_max') ||
                           envContent.includes('pool_size') ||
                           envContent.includes('max_connections');
      if (!hasPoolConfig) {
        findings.push({
          rule: 'DB-002',
          severity: 'MEDIUM',
          passed: false,
          detail: `No connection pool limit configured in ${relPath}`,
          file: relPath,
        });
      }
    }
  }

  return findings;
}

/**
 * Scan Dockerfiles for security issues
 */
async function scanDockerfiles(targetDir) {
  const findings = [];
  const dockerfiles = await findFiles(targetDir, ['Dockerfile', 'Dockerfile.*', '**/Dockerfile']);

  for (const dockerfile of dockerfiles) {
    const content = readFileSafe(dockerfile);
    if (!content) continue;

    const relPath = path.relative(targetDir, dockerfile);

    // INFRA-001: Check for USER directive
    const lines = content.split('\n');
    const hasUserDirective = lines.some(line => {
      const trimmed = line.trim();
      return trimmed.startsWith('USER ') && !trimmed.startsWith('#');
    });

    if (!hasUserDirective) {
      findings.push({
        rule: 'INFRA-001',
        severity: 'CRITICAL',
        passed: false,
        detail: `No USER directive in ${relPath} — container runs as root`,
        file: relPath,
      });
    }
  }

  return findings;
}

/**
 * Scan docker-compose files for exposed ports
 */
async function scanDockerCompose(targetDir) {
  const findings = [];
  const composeFiles = await findFiles(targetDir, [
    'docker-compose.yml',
    'docker-compose.yaml',
    'docker-compose.*.yml',
    'docker-compose.*.yaml',
    'compose.yml',
    'compose.yaml',
  ]);

  for (const composeFile of composeFiles) {
    const content = readFileSafe(composeFile);
    if (!content) continue;

    const relPath = path.relative(targetDir, composeFile);

    try {
      const compose = yaml.load(content);
      if (!compose || !compose.services) continue;

      for (const [serviceName, service] of Object.entries(compose.services)) {
        if (!service.ports) continue;

        for (const portMapping of service.ports) {
          const portStr = String(portMapping);

          // INFRA-002: Check if DB ports are exposed to all interfaces
          const dbPorts = ['5432', '3306', '27017', '6379', '1433'];
          const isDBPort = dbPorts.some(p => portStr.includes(p));
          const isBoundToAll = !portStr.startsWith('127.0.0.1:') &&
                               !portStr.startsWith('localhost:');

          if (isDBPort && isBoundToAll) {
            findings.push({
              rule: 'INFRA-002',
              severity: 'HIGH',
              passed: false,
              detail: `Service "${serviceName}" exposes port ${portStr} to all interfaces in ${relPath}`,
              file: relPath,
            });
          }
        }
      }
    } catch {
      // YAML parse error — skip this file
    }
  }

  return findings;
}

/**
 * Scan source files for audit logging patterns
 */
async function scanForAuditLogs(targetDir) {
  const findings = [];

  // Look for common logging config files/patterns
  const sourceFiles = await findFiles(targetDir, [
    '**/*.js',
    '**/*.ts',
    '**/*.py',
    '**/logging.conf',
    '**/logger.*',
  ]);

  // Known audit/logging library patterns
  const auditPatterns = [
    'winston',
    'morgan',
    'pino',
    'bunyan',
    'log4js',
    'audit',
    'access.log',
    'structlog',
    'loguru',
    'logging.config',
    'AuditLog',
    'auditLog',
    'audit_log',
  ];

  let foundAuditLog = false;

  for (const file of sourceFiles) {
    const content = readFileSafe(file);
    if (!content) continue;

    for (const pattern of auditPatterns) {
      if (content.includes(pattern)) {
        foundAuditLog = true;
        break;
      }
    }
    if (foundAuditLog) break;
  }

  // Also check package.json for logging dependencies
  if (!foundAuditLog) {
    const pkgJson = readFileSafe(path.join(targetDir, 'package.json'));
    if (pkgJson) {
      try {
        const pkg = JSON.parse(pkgJson);
        const allDeps = {
          ...pkg.dependencies,
          ...pkg.devDependencies,
        };
        for (const pattern of auditPatterns) {
          if (allDeps[pattern]) {
            foundAuditLog = true;
            break;
          }
        }
      } catch {
        // JSON parse error
      }
    }
  }

  // Check requirements.txt for Python projects
  if (!foundAuditLog) {
    const reqTxt = readFileSafe(path.join(targetDir, 'requirements.txt'));
    if (reqTxt) {
      for (const pattern of auditPatterns) {
        if (reqTxt.toLowerCase().includes(pattern)) {
          foundAuditLog = true;
          break;
        }
      }
    }
  }

  if (!foundAuditLog) {
    findings.push({
      rule: 'LOG-001',
      severity: 'HIGH',
      passed: false,
      detail: 'No structured audit trail or logging library detected in project',
      file: null,
    });
  }

  return findings;
}

/**
 * Check if a host in a connection URL is private (localhost, 127.0.0.1, etc.)
 */
function isPrivateHost(url) {
  const privatePatterns = [
    '127.0.0.1',
    'localhost',
    '0.0.0.0',
    '10.',
    '172.16.',
    '172.17.',
    '172.18.',
    '172.19.',
    '172.20.',
    '172.21.',
    '172.22.',
    '172.23.',
    '172.24.',
    '172.25.',
    '172.26.',
    '172.27.',
    '172.28.',
    '172.29.',
    '172.30.',
    '172.31.',
    '192.168.',
    '.internal',
    '.local',
    'rds.amazonaws.com',  // RDS endpoints are private within VPC
  ];

  const urlLower = url.toLowerCase();
  return privatePatterns.some(p => urlLower.includes(p));
}
