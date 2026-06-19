/**
 * Terminal Reporter — Rich chalk-based terminal output
 * Renders the branded DELTARQ scan report with colors, tables, and icons
 */

import chalk from 'chalk';
import Table from 'cli-table3';
import { getRule, SEVERITY_ORDER } from '../rules/index.js';
import { getComplianceGapCount, estimateRemediationEffort } from '../engine/aggregator.js';

// Color scheme
const COLORS = {
  brand: chalk.hex('#6C5CE7'),        // DELTARQ purple
  brandBold: chalk.hex('#6C5CE7').bold,
  critical: chalk.red.bold,
  high: chalk.hex('#FF6B35').bold,     // Orange
  medium: chalk.yellow.bold,
  drift: chalk.blue.bold,
  pass: chalk.green.bold,
  dim: chalk.dim,
  white: chalk.white,
  whiteBold: chalk.white.bold,
  score: {
    excellent: chalk.green.bold,
    acceptable: chalk.green,
    atRisk: chalk.yellow.bold,
    vulnerable: chalk.hex('#FF6B35').bold,
    critical: chalk.red.bold,
  },
};

const SEVERITY_ICONS = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  DRIFT: '🔵',
};

const SEVERITY_COLORS = {
  CRITICAL: COLORS.critical,
  HIGH: COLORS.high,
  MEDIUM: COLORS.medium,
  DRIFT: COLORS.drift,
};

/**
 * Print the branded header banner
 */
export function printBanner(targetDir) {
  const line = COLORS.brand('─'.repeat(56));
  console.log();
  console.log(line);
  console.log(COLORS.brandBold('   DELTARQ Security Scanner') + COLORS.dim(' v0.1.0'));
  console.log(COLORS.dim(`   Scanning: ${targetDir}`));
  console.log(line);
  console.log();
}

/**
 * Print a scan phase result line
 * @param {string} label - Phase description
 * @param {string} result - Result text
 * @param {'ok'|'warning'|'error'|'skip'} status - Result status
 */
export function printScanPhase(label, result, status = 'ok') {
  const icons = {
    ok: chalk.green('✓'),
    warning: chalk.yellow('⚠'),
    error: chalk.red('✗'),
    skip: chalk.dim('○'),
  };

  const icon = icons[status] || icons.ok;
  const labelPadded = label.padEnd(35);
  const resultColor = status === 'error' ? COLORS.critical :
                      status === 'warning' ? COLORS.medium :
                      status === 'skip' ? COLORS.dim :
                      COLORS.pass;

  console.log(`   ${icon} ${COLORS.white(labelPadded)} ${resultColor(result)}`);
}

/**
 * Print the full scan report
 */
export function printReport(findings, scoreResult, projectInfo) {
  const line = COLORS.brand('─'.repeat(56));
  const failedFindings = findings.filter(f => !f.passed);

  // Deduplicate by rule ID for display
  const seenRules = new Set();
  const uniqueFindings = [];
  for (const f of failedFindings) {
    if (!seenRules.has(f.rule)) {
      seenRules.add(f.rule);
      uniqueFindings.push(f);
    }
  }

  // Sort by severity
  uniqueFindings.sort((a, b) => {
    return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  });

  console.log();
  console.log(line);

  // Score display
  const scoreColor = getScoreColor(scoreResult.score);
  console.log(
    `   YOUR SECURITY SCORE: ${scoreColor(`${scoreResult.score}/100`)}   ` +
    `[${scoreColor(`${scoreResult.grade} — ${scoreResult.label}`)}]`
  );
  console.log(line);
  console.log();

  // Findings
  if (uniqueFindings.length === 0) {
    console.log(COLORS.pass('   ✓ No security issues detected! Your project looks solid.'));
    console.log();
  } else {
    for (const finding of uniqueFindings) {
      const icon = SEVERITY_ICONS[finding.severity] || '⚪';
      const sevColor = SEVERITY_COLORS[finding.severity] || COLORS.dim;
      const rule = getRule(finding.rule);
      const ruleName = rule ? rule.name : finding.rule;
      const ruleDesc = rule ? rule.description : finding.detail;

      console.log(
        `   ${icon} ${sevColor(finding.severity.padEnd(10))} ${COLORS.whiteBold(finding.rule)}  ${COLORS.white(ruleName)}`
      );
      console.log(
        `   ${' '.repeat(3)} ${' '.repeat(10)} ${COLORS.dim('→')} ${COLORS.dim(ruleDesc)}`
      );
      console.log();
    }
  }

  // Footer stats
  console.log(line);
  const gapCount = getComplianceGapCount(findings);
  const effort = estimateRemediationEffort(findings);

  const readyIcon = scoreResult.enterpriseReady ? COLORS.pass('✓') : COLORS.critical('✗');
  const readyLabel = scoreResult.enterpriseReady
    ? COLORS.pass('Ready')
    : COLORS.critical('Not Ready');

  console.log(`   ENTERPRISE READINESS: ${readyIcon} ${readyLabel}`);
  console.log(`   SOC 2 Gap Count: ${COLORS.whiteBold(String(gapCount) + ' controls failing')}`);
  console.log(`   Estimated remediation effort: ${COLORS.whiteBold(effort)}`);
  console.log(line);
  console.log();
}

/**
 * Print the summary table (alternative compact view)
 */
export function printSummaryTable(findings) {
  const failedFindings = findings.filter(f => !f.passed);
  const seenRules = new Set();
  const unique = [];
  for (const f of failedFindings) {
    if (!seenRules.has(f.rule)) {
      seenRules.add(f.rule);
      unique.push(f);
    }
  }

  if (unique.length === 0) return;

  const table = new Table({
    head: [
      chalk.white.bold('Severity'),
      chalk.white.bold('Rule'),
      chalk.white.bold('Issue'),
      chalk.white.bold('Status'),
    ],
    colWidths: [12, 12, 40, 10],
    style: {
      head: [],
      border: ['dim'],
    },
    chars: {
      'top': '─', 'top-mid': '┬', 'top-left': '┌', 'top-right': '┐',
      'bottom': '─', 'bottom-mid': '┴', 'bottom-left': '└', 'bottom-right': '┘',
      'left': '│', 'left-mid': '├', 'mid': '─', 'mid-mid': '┼',
      'right': '│', 'right-mid': '┤', 'middle': '│',
    },
  });

  for (const f of unique) {
    const rule = getRule(f.rule);
    const sevColor = SEVERITY_COLORS[f.severity] || COLORS.dim;
    const icon = SEVERITY_ICONS[f.severity] || '⚪';

    table.push([
      `${icon} ${sevColor(f.severity)}`,
      COLORS.whiteBold(f.rule),
      COLORS.white(rule ? rule.name : f.detail),
      COLORS.critical('FAIL'),
    ]);
  }

  console.log(table.toString());
  console.log();
}

/**
 * Get the color function for a score value
 */
function getScoreColor(score) {
  if (score >= 90) return COLORS.score.excellent;
  if (score >= 80) return COLORS.score.acceptable;
  if (score >= 60) return COLORS.score.atRisk;
  if (score >= 40) return COLORS.score.vulnerable;
  return COLORS.score.critical;
}
