/**
 * Summary Generator
 *
 * Generates GitHub Actions summary markdown from scan results.
 * Uses core.summary for proper GitHub rendering.
 *
 * @module output/summary
 */

import * as core from '@actions/core';

import type { Finding, ScanResults, ScannerName } from '../scanners/types';
import type { PolicyResult } from '../policy/types';

/** Action version for footer */
const VERSION = '0.1.0';

/** Maximum number of high-severity findings to show expanded */
const MAX_EXPANDED_HIGH_FINDINGS = 20;

/** Maximum number of findings per severity in collapsed sections */
const MAX_COLLAPSED_FINDINGS = 50;

/** Scanner display names and emojis */
const SCANNER_INFO: Record<ScannerName, { emoji: string; name: string }> = {
  secrets: { emoji: '🔑', name: 'Secrets' },
  dependencies: { emoji: '📦', name: 'Dependencies' },
  iac: { emoji: '🏗️', name: 'Infrastructure' },
  container: { emoji: '🐳', name: 'Containers' },
};

/**
 * Generate and write the GitHub Actions summary.
 *
 * @param results - Aggregated scan results
 * @param policyResult - Policy evaluation result
 * @returns The generated markdown string
 */
export async function writeSummary(
  results: ScanResults,
  policyResult: PolicyResult
): Promise<string> {
  const markdown = generateSummaryMarkdown(results, policyResult);

  // Write to GitHub summary
  core.summary.addRaw(markdown);
  await core.summary.write();

  return markdown;
}

/**
 * Generate summary markdown without writing.
 * Useful for testing.
 *
 * @param results - Aggregated scan results
 * @param policyResult - Policy evaluation result
 * @returns Generated markdown string
 */
export function generateSummaryMarkdown(results: ScanResults, policyResult: PolicyResult): string {
  const lines: string[] = [];

  // Header with status
  lines.push('## 🔒 Security Gate Results');
  lines.push('');
  lines.push(generateStatusLine(policyResult));
  lines.push(generateScanMetaLine(results));
  lines.push('');

  // Findings by category table
  lines.push('### Findings by Category');
  lines.push('');
  lines.push(generateCategoryTable(results));
  lines.push('');

  // Collect all findings
  const allFindings = collectAllFindings(results);

  // High-severity findings (expanded)
  const highFindings = allFindings.filter((f) => f.severity === 'high');
  if (highFindings.length > 0) {
    lines.push('### High Severity Findings');
    lines.push('');
    lines.push(generateFindingsSection(highFindings, MAX_EXPANDED_HIGH_FINDINGS));
    lines.push('');
  }

  // Medium-severity findings (collapsed)
  const mediumFindings = allFindings.filter((f) => f.severity === 'medium');
  if (mediumFindings.length > 0) {
    lines.push(
      generateCollapsedSection(
        `Medium Severity Findings (${mediumFindings.length})`,
        generateFindingsSection(mediumFindings, MAX_COLLAPSED_FINDINGS)
      )
    );
    lines.push('');
  }

  // Low-severity findings (collapsed)
  const lowFindings = allFindings.filter((f) => f.severity === 'low');
  if (lowFindings.length > 0) {
    lines.push(
      generateCollapsedSection(
        `Low Severity Findings (${lowFindings.length})`,
        generateFindingsSection(lowFindings, MAX_COLLAPSED_FINDINGS)
      )
    );
    lines.push('');
  }

  // Footer
  lines.push('---');
  lines.push('');
  lines.push(`_Security Gate v${VERSION}_`);

  return lines.join('\n');
}

/**
 * Generate status line with pass/fail indicator.
 */
function generateStatusLine(policyResult: PolicyResult): string {
  const { passed, counts, failOn } = policyResult;

  if (counts.total === 0) {
    return '**Status**: ✅ Passed (no findings)';
  }

  const statusIcon = passed ? '✅' : '❌';
  const statusText = passed ? 'Passed' : 'Failed';

  const countParts: string[] = [];
  if (counts.high > 0) {
    countParts.push(`${counts.high} high`);
  }
  if (counts.medium > 0) {
    countParts.push(`${counts.medium} medium`);
  }
  if (counts.low > 0) {
    countParts.push(`${counts.low} low`);
  }

  const countsStr = countParts.length > 0 ? countParts.join(', ') : 'no';

  return `**Status**: ${statusIcon} ${statusText} (${countsStr} findings, threshold: ${failOn})`;
}

/**
 * Generate scan metadata line.
 */
function generateScanMetaLine(results: ScanResults): string {
  const scannerCount = results.scanners.length;
  const fileCount = results.totalFilesScanned;
  const duration = (results.totalDurationMs / 1000).toFixed(1);

  return `**Scanned**: ${scannerCount} scanner(s), ${fileCount} file(s), ${duration}s`;
}

/**
 * Generate findings by category table.
 */
function generateCategoryTable(results: ScanResults): string {
  const lines: string[] = [];

  lines.push('| Scanner | High | Medium | Low |');
  lines.push('| ------- | ---- | ------ | --- |');

  for (const scanner of results.scanners) {
    const info = SCANNER_INFO[scanner.name];
    const counts = countFindingsBySeverityLocal(scanner.findings);

    lines.push(
      `| ${info.emoji} ${info.name} | ${counts.high} | ${counts.medium} | ${counts.low} |`
    );
  }

  return lines.join('\n');
}

/**
 * Count findings by severity (local implementation to avoid circular imports).
 */
function countFindingsBySeverityLocal(findings: Finding[]): {
  high: number;
  medium: number;
  low: number;
} {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    counts[finding.severity]++;
  }
  return counts;
}

/**
 * Generate findings section.
 */
function generateFindingsSection(findings: Finding[], maxFindings: number): string {
  const lines: string[] = [];
  const displayed = findings.slice(0, maxFindings);

  for (const finding of displayed) {
    lines.push(generateFindingBlock(finding));
    lines.push('');
  }

  if (findings.length > maxFindings) {
    lines.push(`_...and ${findings.length - maxFindings} more findings_`);
  }

  return lines.join('\n');
}

/**
 * Generate a single finding block.
 */
function generateFindingBlock(finding: Finding): string {
  const lines: string[] = [];
  const info = SCANNER_INFO[finding.scanner];

  // Title with emoji
  const ruleIdStr = finding.ruleId ? `: ${finding.ruleId}` : '';
  lines.push(`#### ${info.emoji} ${finding.title}${ruleIdStr}`);
  lines.push('');

  // File location
  const lineStr =
    finding.startLine !== undefined
      ? finding.endLine !== undefined && finding.endLine !== finding.startLine
        ? `:${finding.startLine}-${finding.endLine}`
        : `:${finding.startLine}`
      : '';
  lines.push(`- **File**: \`${finding.file}${lineStr}\``);

  // Message
  lines.push(`- **Message**: ${finding.message}`);

  // Snippet (already masked by the scanner)
  if (finding.snippet) {
    lines.push('');
    lines.push('```');
    lines.push(finding.snippet);
    lines.push('```');
  }

  return lines.join('\n');
}

/**
 * Generate a collapsible section.
 */
function generateCollapsedSection(title: string, content: string): string {
  return `<details>
<summary>${title}</summary>

${content}

</details>`;
}

/**
 * Collect all findings from scan results.
 */
function collectAllFindings(results: ScanResults): Finding[] {
  const allFindings: Finding[] = [];
  for (const scanner of results.scanners) {
    allFindings.push(...scanner.findings);
  }
  return allFindings;
}

/**
 * Generate a minimal summary for when there are no findings.
 */
export function generateEmptySummary(): string {
  return `## 🔒 Security Gate Results

**Status**: ✅ Passed (no findings)

No security issues were detected in this scan.

---

_Security Gate v${VERSION}_`;
}
