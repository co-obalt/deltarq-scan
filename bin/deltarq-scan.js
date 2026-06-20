#!/usr/bin/env node

/**
 * DELTARQ Security Scanner — CLI Entry Point
 * 
 * Usage:
 *   npx deltarq-scan [target-dir] [options]
 * 
 * Options:
 *   --no-upload    Skip the dashboard upload prompt
 *   --json         Output raw JSON instead of terminal report
 *   --verbose      Show detailed output including upload payload preview
 *   --help         Show this help message
 */

import { resolveTargetDir } from '../src/utils/fileUtils.js';
import { detectProjectType } from '../src/utils/detect.js';
import { runFileScanner } from '../src/scanner/fileScanner.js';
import { runGitScanner } from '../src/scanner/gitScanner.js';
import { runDbScanner } from '../src/scanner/dbScanner.js';
import { runAwsScanner } from '../src/scanner/awsScanner.js';
import { calculateScore } from '../src/engine/aggregator.js';
import { anonymizeScanResults } from '../src/engine/anonymizer.js';
import { printBanner, printScanPhase, printReport } from '../src/output/terminal.js';
import { uploadWithConsent } from '../src/output/uploader.js';
import chalk from 'chalk';
import ora from 'ora';
import fs from 'fs';

// Parse CLI arguments
const args = process.argv.slice(2);
const flags = {
  noUpload: args.includes('--no-upload'),
  json: args.includes('--json'),
  verbose: args.includes('--verbose'),
  help: args.includes('--help') || args.includes('-h'),
};
const targetArg = args.find(a => !a.startsWith('--') && !a.startsWith('-'));

// Help message
if (flags.help) {
  console.log(`
  ${chalk.hex('#6C5CE7').bold('DELTARQ Security Scanner')} ${chalk.dim('v0.1.0')}
  
  ${chalk.white('Local-first CLI security audit tool for startups.')}
  ${chalk.white('Scans your infrastructure for SOC 2 readiness gaps.')}

  ${chalk.white.bold('Usage:')}
    npx deltarq-scan [target-dir] [options]

  ${chalk.white.bold('Options:')}
    ${chalk.green('--no-upload')}    Skip the dashboard upload prompt
    ${chalk.green('--json')}         Output raw JSON instead of terminal report
    ${chalk.green('--verbose')}      Show detailed output and upload payload preview
    ${chalk.green('--help, -h')}     Show this help message

  ${chalk.white.bold('Examples:')}
    ${chalk.dim('npx deltarq-scan')}                  ${chalk.dim('# Scan current directory')}
    ${chalk.dim('npx deltarq-scan ./my-project')}      ${chalk.dim('# Scan specific directory')}
    ${chalk.dim('npx deltarq-scan --no-upload')}       ${chalk.dim('# Scan without upload prompt')}
    ${chalk.dim('npx deltarq-scan --json')}            ${chalk.dim('# Output JSON report')}

  ${chalk.dim('Learn more: https://github.com/deltarq/deltarq-scan')}
`);
  process.exit(0);
}

// Main scan flow
async function main() {
  const targetDir = resolveTargetDir(targetArg);
  
  if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
    console.error(chalk.red.bold(`\n  ✗ Error: Target path "${targetDir}" is not a valid directory.\n`));
    process.exit(1);
  }

  const allFindings = [];

  // Print banner (unless JSON mode)
  if (!flags.json) {
    printBanner(targetDir);
  }

  // Phase 1: Detect project type
  const spinner = !flags.json ? ora({ text: 'Detecting project type...', indent: 3 }).start() : null;
  const projectInfo = detectProjectType(targetDir);

  if (!flags.json) {
    spinner.stop();
    printScanPhase('Detecting project type...', projectInfo.label, 'ok');
  }

  // Phase 2: File Scanner (IAM, DB, Docker, Logging)
  if (!flags.json) {
    const fileSpinner = ora({ text: 'Scanning configuration files...', indent: 3 }).start();
    var fileFindings = await runFileScanner(targetDir);
    fileSpinner.stop();

    const fileIssues = fileFindings.filter(f => !f.passed).length;
    printScanPhase(
      'Scanning configuration files...',
      fileIssues > 0 ? `${fileIssues} issue${fileIssues > 1 ? 's' : ''} found` : 'No issues',
      fileIssues > 0 ? 'warning' : 'ok'
    );
  } else {
    var fileFindings = await runFileScanner(targetDir);
  }
  allFindings.push(...fileFindings);

  // Phase 3: AWS Scanner
  if (!flags.json) {
    const awsSpinner = ora({ text: 'Scanning IAM configuration...', indent: 3 }).start();
    var { findings: awsFindings, awsConfigured } = await runAwsScanner(targetDir);
    awsSpinner.stop();

    if (!awsConfigured && awsFindings.length === 0) {
      printScanPhase('Scanning IAM configuration...', 'AWS not configured — skipped cloud checks', 'skip');
    } else {
      const awsIssues = awsFindings.filter(f => !f.passed).length;
      printScanPhase(
        'Scanning IAM configuration...',
        awsIssues > 0 ? `${awsIssues} issue${awsIssues > 1 ? 's' : ''} found` : 'No issues',
        awsIssues > 0 ? 'warning' : 'ok'
      );
    }
  } else {
    var { findings: awsFindings } = await runAwsScanner(targetDir);
  }
  allFindings.push(...awsFindings);

  // Phase 4: Database Scanner
  if (!flags.json) {
    const dbSpinner = ora({ text: 'Scanning database config...', indent: 3 }).start();
    var dbFindings = await runDbScanner(targetDir);
    dbSpinner.stop();

    const dbIssues = dbFindings.filter(f => !f.passed).length;
    printScanPhase(
      'Scanning database config...',
      dbIssues > 0 ? `${dbIssues} issue${dbIssues > 1 ? 's' : ''} found` : 'No issues',
      dbIssues > 0 ? 'warning' : 'ok'
    );
  } else {
    var dbFindings = await runDbScanner(targetDir);
  }
  allFindings.push(...dbFindings);

  // Phase 5: Git Scanner
  if (!flags.json) {
    const gitSpinner = ora({ text: 'Scanning git repository...', indent: 3 }).start();
    var gitFindings = await runGitScanner(targetDir);
    gitSpinner.stop();

    const gitIssues = gitFindings.filter(f => !f.passed).length;
    printScanPhase(
      'Scanning git repository...',
      gitIssues > 0 ? 'Warning detected' : 'Clean',
      gitIssues > 0 ? 'warning' : 'ok'
    );
  } else {
    var gitFindings = await runGitScanner(targetDir);
  }
  allFindings.push(...gitFindings);

  // Phase 6: Calculate score
  const scoreResult = calculateScore(allFindings);

  // JSON output mode
  if (flags.json) {
    const anonymous = anonymizeScanResults(allFindings, scoreResult, projectInfo);
    console.log(JSON.stringify(anonymous, null, 2));
    process.exit(scoreResult.score < 40 ? 1 : 0);
    return;
  }

  // Phase 7: Print the report
  printReport(allFindings, scoreResult, projectInfo);

  // Phase 8: Upload prompt
  const anonymousPayload = anonymizeScanResults(allFindings, scoreResult, projectInfo);
  await uploadWithConsent(anonymousPayload, {
    noUpload: flags.noUpload,
    verbose: flags.verbose,
  });

  // Exit with non-zero if critical exposure
  process.exit(scoreResult.score < 40 ? 1 : 0);
}

// Run
main().catch((err) => {
  console.error(chalk.red.bold('\n  ✗ Scanner encountered an error:\n'));
  console.error(chalk.red(`    ${err.message}`));
  if (flags.verbose) {
    console.error(chalk.dim(`\n    ${err.stack}`));
  }
  process.exit(2);
});
