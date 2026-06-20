/**
 * Rule Registry — Central index of all scan rules
 * Import and re-export all rules for the scanner engine
 */

import { INFRA_001, INFRA_002, INFRA_003, INFRA_004 } from './infrastructure.js';
import { IAM_001, IAM_002, IAM_003 } from './identity.js';
import { DB_001, DB_002 } from './data.js';
import { LOG_001 } from './logging.js';
import { GIT_001 } from './git.js';

/**
 * All registered rules, indexed by ID
 */
export const RULES = {
  'INFRA-001': INFRA_001,
  'INFRA-002': INFRA_002,
  'INFRA-003': INFRA_003,
  'INFRA-004': INFRA_004,
  'IAM-001': IAM_001,
  'IAM-002': IAM_002,
  'IAM-003': IAM_003,
  'DB-001': DB_001,
  'DB-002': DB_002,
  'LOG-001': LOG_001,
  'GIT-001': GIT_001,
};

/**
 * Get all rules as an array
 */
export function getAllRules() {
  return Object.values(RULES);
}

/**
 * Get a rule by its ID
 */
export function getRule(id) {
  return RULES[id] || null;
}

/**
 * Get rules filtered by severity
 */
export function getRulesBySeverity(severity) {
  return getAllRules().filter(r => r.severity === severity);
}

/**
 * Severity levels in order of priority
 */
export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'DRIFT'];
