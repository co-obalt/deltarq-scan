import fs from 'fs';
import path from 'path';
import { glob } from 'glob';

/**
 * Safely read a file, returning null if it doesn't exist or errors
 */
export function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

/**
 * Check if a file exists
 */
export function fileExists(filePath) {
  try {
    return fs.existsSync(filePath);
  } catch {
    return false;
  }
}

/**
 * Find files matching glob patterns in a directory
 * @param {string} baseDir - Directory to search in
 * @param {string[]} patterns - Glob patterns to match
 * @returns {Promise<string[]>} Array of matched file paths
 */
export async function findFiles(baseDir, patterns) {
  const results = [];
  for (const pattern of patterns) {
    const matches = await glob(pattern, {
      cwd: baseDir,
      absolute: true,
      nodir: true,
      dot: true,
      ignore: ['**/node_modules/**', '**/.git/**'],
    });
    results.push(...matches);
  }
  return [...new Set(results)];
}

/**
 * Parse a .env file content into key-value pairs
 * @param {string} content - Raw .env file content
 * @returns {Object} Parsed key-value pairs
 */
export function parseEnvContent(content) {
  const result = {};
  if (!content) return result;

  const lines = content.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) continue;

    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;

    const key = trimmed.substring(0, eqIndex).trim();
    let value = trimmed.substring(eqIndex + 1).trim();

    // Remove surrounding quotes
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    result[key] = value;
  }
  return result;
}

/**
 * Resolve a target path, defaulting to CWD
 */
export function resolveTargetDir(targetArg) {
  if (targetArg) {
    return path.resolve(targetArg);
  }
  return process.cwd();
}
