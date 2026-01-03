/**
 * Security Gate Action - Entry Point
 *
 * This is the main entry point for the GitHub Action.
 * It orchestrates config loading, scanner execution, policy evaluation, and output generation.
 *
 * @module index
 */

import * as core from '@actions/core';
import { resolve } from 'path';

import {
  loadConfig,
  validateConfigSemantics,
  ConfigValidationError,
  ConfigParseError,
  ConfigSemanticError,
} from './config';
import { runScanners } from './scanners';
import { evaluatePolicyFromResults } from './policy';
import { writeSummary, emitAnnotations } from './output';
import { handleSarifOutput } from './output/sarif';

/**
 * Exit codes for the action
 */
export const ExitCode = {
  /** All checks passed */
  Success: 0,
  /** Policy violation - findings above threshold */
  PolicyViolation: 1,
  /** Configuration error */
  ConfigError: 2,
  /** Scanner execution error */
  ScannerError: 3,
} as const;

/**
 * Action version
 */
const VERSION = '0.2.0';

/**
 * Logger that respects verbose flag.
 */
class Logger {
  constructor(private verbose: boolean) {}

  info(message: string): void {
    core.info(message);
  }

  debug(message: string): void {
    if (this.verbose) {
      core.debug(message);
    }
  }

  warn(message: string): void {
    core.warning(message);
  }

  error(message: string): void {
    core.error(message);
  }
}

/**
 * Read and validate action inputs.
 */
function getInputs(): {
  configPath: string;
  failOn: string;
  mode: string;
  verbose: boolean;
  workingDirectory: string;
  sarifOutput: string;
} {
  return {
    configPath: core.getInput('config_path') || '.security-gate.yml',
    failOn: core.getInput('fail_on') || 'high',
    mode: core.getInput('mode') || 'auto',
    verbose: core.getBooleanInput('verbose'),
    workingDirectory: core.getInput('working_directory') || '.',
    sarifOutput: core.getInput('sarif_output') || '',
  };
}

/**
 * Main entry point for the Security Gate Action
 */
async function run(): Promise<void> {
  let exitCode: (typeof ExitCode)[keyof typeof ExitCode] = ExitCode.Success;

  try {
    // Read inputs
    const inputs = getInputs();
    const logger = new Logger(inputs.verbose);

    // Resolve working directory
    const workingDirectory = resolve(process.cwd(), inputs.workingDirectory);

    // Print banner
    core.info(`🔒 Security Gate Action v${VERSION}`);
    logger.debug(`   Config: ${inputs.configPath}`);
    logger.debug(`   Fail on: ${inputs.failOn}`);
    logger.debug(`   Mode: ${inputs.mode}`);
    logger.debug(`   Directory: ${workingDirectory}`);

    // Load and validate configuration
    logger.debug('Loading configuration...');
    const { config, configFile, usingDefaults } = await loadConfig({
      configPath: inputs.configPath,
      workingDirectory,
    });

    if (usingDefaults) {
      logger.debug('Using default configuration');
    } else {
      logger.debug(`Loaded configuration from: ${configFile}`);
    }

    // Validate configuration semantics
    validateConfigSemantics(config, { workingDirectory });

    // Run scanners
    logger.debug('Starting scanner orchestration...');
    const results = await runScanners(config, {
      workingDirectory,
      verbose: inputs.verbose,
    });

    // Evaluate policy using the new evaluator
    const policyResult = evaluatePolicyFromResults(results, config.fail_on);

    // Set outputs
    core.setOutput('findings_count', policyResult.counts.total);
    core.setOutput('high_count', policyResult.counts.high);
    core.setOutput('medium_count', policyResult.counts.medium);
    core.setOutput('low_count', policyResult.counts.low);
    core.setOutput('passed', policyResult.passed);

    // Report results
    if (policyResult.counts.total === 0) {
      core.info('✅ No security findings detected');
    } else {
      core.info(
        `📊 Found ${policyResult.counts.total} finding(s): ` +
          `${policyResult.counts.high} high, ${policyResult.counts.medium} medium, ${policyResult.counts.low} low`
      );
    }

    // Emit annotations for findings
    logger.debug('Emitting annotations...');
    const annotationResult = emitAnnotations(results);
    if (annotationResult.capped) {
      logger.debug(`Annotation limit reached: ${annotationResult.skipped} skipped`);
    }

    // Generate SARIF output if configured
    if (inputs.sarifOutput) {
      logger.debug('Generating SARIF output...');
      const sarifPath = handleSarifOutput(results, {
        outputPath: resolve(workingDirectory, inputs.sarifOutput),
      });
      if (sarifPath) {
        core.setOutput('sarif_path', sarifPath);
        logger.info(`SARIF output written to: ${sarifPath}`);
      }
    }

    // Write GitHub summary
    logger.debug('Writing summary...');
    await writeSummary(results, policyResult);

    // Determine exit status
    if (!policyResult.passed) {
      exitCode = ExitCode.PolicyViolation;
      core.setFailed(
        policyResult.failureReason ??
          `Security Gate failed: policy threshold (${config.fail_on}) exceeded`
      );
    } else if (results.hasErrors) {
      // Scanner errors but policy passed - warn but don't fail
      core.warning('Some scanners encountered errors but policy passed');
    }

    core.info(`✅ Security Gate completed in ${results.totalDurationMs}ms`);
  } catch (error) {
    // Handle specific error types
    if (
      error instanceof ConfigValidationError ||
      error instanceof ConfigParseError ||
      error instanceof ConfigSemanticError
    ) {
      exitCode = ExitCode.ConfigError;
      core.setFailed(`Configuration error: ${error.message}`);
    } else if (error instanceof Error) {
      exitCode = ExitCode.ScannerError;
      // Avoid leaking sensitive information in error messages
      core.setFailed(`Security Gate failed: ${error.message}`);
    } else {
      exitCode = ExitCode.ScannerError;
      core.setFailed('Security Gate failed with an unknown error');
    }
  }

  // Set process exit code
  if (exitCode !== ExitCode.Success) {
    process.exitCode = exitCode;
  }
}

// Run the action
void run();
