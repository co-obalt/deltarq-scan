/**
 * Logging & Audit Trail rules
 * Checks for structured logging and audit capabilities
 */

export const LOG_001 = {
  id: 'LOG-001',
  name: 'No Structured Audit Trail',
  severity: 'HIGH',
  category: 'Logging',
  description: 'You have no audit trail. If you\'re breached, you won\'t know who accessed what or when. SOC 2 Type II requires this.',
  remediation: 'Implement structured logging with a library like Winston, Pino, or Morgan for access/auth events.',
  sopLink: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
};
