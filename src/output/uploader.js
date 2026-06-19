/**
 * Uploader — Handles anonymous scan data upload to DELTARQ dashboard
 * Includes consent prompt and transparent preview before any data leaves
 */

import readline from 'readline';
import chalk from 'chalk';
import { validateNoSecrets } from '../engine/anonymizer.js';

const DELTARQ_API_URL = process.env.DELTARQ_API_URL || 'https://deltarq-scan.vercel.app/v1/scans';
const DELTARQ_DASHBOARD_URL = process.env.DELTARQ_DASHBOARD_URL || 'https://deltarq-scan.vercel.app';

/**
 * Prompt the user for consent and upload anonymous scan results
 * @param {Object} anonymousPayload - The anonymized scan JSON
 * @param {{ noUpload: boolean }} options - CLI options
 * @returns {Promise<{ uploaded: boolean, reportUrl?: string }>}
 */
export async function uploadWithConsent(anonymousPayload, options = {}) {
  if (options.noUpload) {
    return { uploaded: false };
  }

  console.log();
  console.log(chalk.hex('#6C5CE7').bold('  Would you like to see your full report on the DELTARQ dashboard?'));
  console.log(chalk.dim('  (No sensitive data is uploaded — only boolean pass/fail metadata)'));
  console.log();

  // Show preview of what will be uploaded
  if (options.verbose) {
    console.log(chalk.dim('  Preview of upload payload:'));
    console.log(chalk.dim('  ' + JSON.stringify(anonymousPayload, null, 2).split('\n').join('\n  ')));
    console.log();
  }

  const consent = await askYesNo('  [Y/n]: ');

  if (!consent) {
    console.log();
    console.log(chalk.dim('  Skipped upload. Your scan results are only on this machine.'));
    return { uploaded: false };
  }

  // Safety check before upload
  try {
    validateNoSecrets(anonymousPayload);
  } catch (err) {
    console.log();
    console.log(chalk.red.bold(`  ✗ ${err.message}`));
    return { uploaded: false, error: err.message };
  }

  // Perform the upload
  console.log();
  process.stdout.write(chalk.dim('  Uploading anonymous scan metadata...  '));

  try {
    const response = await fetch(DELTARQ_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `deltarq-scan/${anonymousPayload.scanner_version}`,
      },
      body: JSON.stringify(anonymousPayload),
    });

    if (!response.ok) {
      // Non-critical failure — the scan still ran successfully
      console.log(chalk.yellow('⚠ Upload failed (non-critical)'));
      console.log(chalk.dim(`  Server responded with status ${response.status}`));
      return { uploaded: false };
    }

    const result = await response.json();
    const reportUrl = result.report_url || `${DELTARQ_DASHBOARD_URL}/report/${anonymousPayload.scan_id}`;

    console.log(chalk.green('✓ Done'));
    console.log();
    console.log(chalk.white('  Your report is live at:'));
    console.log(chalk.hex('#6C5CE7').bold(`  ${reportUrl}`));
    console.log();
    console.log(chalk.white('  Book a 20-min call to fix these gaps with a DELTARQ engineer:'));
    console.log(chalk.hex('#6C5CE7').bold('  → https://calendar.app.google/ExhxfcYvbV5PKMs36'));
    console.log();

    return { uploaded: true, reportUrl };

  } catch (err) {
    // Network error — API might be down or no internet
    console.log(chalk.yellow('⚠ Upload failed'));
    console.log(chalk.dim(`  ${err.message}`));
    console.log(chalk.dim('  Your scan results are still available locally.'));
    console.log();

    // Still show the CTA
    console.log(chalk.white('  Book a 20-min call to fix these gaps with a DELTARQ engineer:'));
    console.log(chalk.hex('#6C5CE7').bold('  → https://calendar.app.google/ExhxfcYvbV5PKMs36'));
    console.log();

    return { uploaded: false };
  }
}

/**
 * Ask a yes/no question in the terminal
 * @param {string} prompt - The prompt text
 * @returns {Promise<boolean>}
 */
function askYesNo(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question(prompt, (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      resolve(normalized === '' || normalized === 'y' || normalized === 'yes');
    });
  });
}
