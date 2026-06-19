/**
 * Database Scanner — Analyzes database connection patterns for security issues
 * No actual database connections are made — pattern matching only
 */

import path from 'path';
import { readFileSafe, findFiles, parseEnvContent } from '../utils/fileUtils.js';

/**
 * Run database-specific security scans
 * @param {string} targetDir - The project root directory
 * @returns {Promise<Array<{ rule: string, severity: string, passed: boolean, detail: string }>>}
 */
export async function runDbScanner(targetDir) {
  const findings = [];

  // Scan all source files for database connection patterns
  const sourceFiles = await findFiles(targetDir, [
    '**/*.js',
    '**/*.ts',
    '**/*.py',
    '**/*.rb',
    '**/*.go',
    '**/config/**',
    '**/database.*',
    '**/db.*',
  ]);

  for (const file of sourceFiles) {
    const content = readFileSafe(file);
    if (!content) continue;

    const relPath = path.relative(targetDir, file);

    // DB-002: Check for connection pool configuration in source code
    const hasDbConnection = content.includes('createPool') ||
                           content.includes('Pool(') ||
                           content.includes('new Pool') ||
                           content.includes('ConnectionPool') ||
                           content.includes('pool') ||
                           content.includes('create_engine') ||
                           content.includes('Sequelize');

    if (hasDbConnection) {
      const hasPoolLimit = content.includes('max:') ||
                          content.includes('max =') ||
                          content.includes('pool_size') ||
                          content.includes('maxConnections') ||
                          content.includes('max_connections') ||
                          content.includes('pool_max_size');

      if (!hasPoolLimit) {
        findings.push({
          rule: 'DB-002',
          severity: 'MEDIUM',
          passed: false,
          detail: `Database connection in ${relPath} may not have a pool size limit`,
          file: relPath,
        });
        // Only report once
        break;
      }
    }
  }

  return findings;
}
