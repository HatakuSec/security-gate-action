/**
 * Annotations Emitter
 *
 * Emits GitHub Actions annotations for findings.
 * Uses core.error, core.warning, and core.notice based on severity.
 *
 * @module output/annotations
 */

import * as core from '@actions/core';

import type { Finding, ScanResults, Severity } from '../scanners/types';

/**
 * Maximum number of annotations to emit.
 * GitHub has a limit on annotations per workflow run.
 * We cap to avoid hitting limits and impacting performance.
 */
const MAX_ANNOTATIONS = 50;

/**
 * Result of annotation emission.
 */
export interface AnnotationResult {
  /** Total number of annotations emitted */
  emitted: number;
  /** Number of annotations skipped due to cap */
  skipped: number;
  /** Whether any annotations were skipped */
  capped: boolean;
}

/**
 * Annotation properties for GitHub Actions.
 */
interface AnnotationProperties {
  title?: string;
  file?: string;
  startLine?: number;
  endLine?: number;
}

/**
 * Emit annotations for all findings.
 *
 * @param results - Aggregated scan results
 * @returns Annotation emission result
 */
export function emitAnnotations(results: ScanResults): AnnotationResult {
  // Collect all findings
  const allFindings: Finding[] = [];
  for (const scanner of results.scanners) {
    allFindings.push(...scanner.findings);
  }

  return emitFindingAnnotations(allFindings);
}

/**
 * Emit annotations for a list of findings.
 *
 * @param findings - Findings to annotate
 * @returns Annotation emission result
 */
export function emitFindingAnnotations(findings: Finding[]): AnnotationResult {
  // Sort by severity (high first) to prioritise important annotations
  const sorted = [...findings].sort((a, b) => {
    const order: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
    return order[a.severity] - order[b.severity];
  });

  let emitted = 0;
  let skipped = 0;

  for (const finding of sorted) {
    if (emitted >= MAX_ANNOTATIONS) {
      skipped++;
      continue;
    }

    emitAnnotation(finding);
    emitted++;
  }

  // If we skipped any, log a notice
  if (skipped > 0) {
    core.notice(
      `Annotation limit reached: ${skipped} additional findings not annotated. See summary for full list.`
    );
  }

  return {
    emitted,
    skipped,
    capped: skipped > 0,
  };
}

/**
 * Emit a single annotation for a finding.
 *
 * @param finding - Finding to annotate
 */
function emitAnnotation(finding: Finding): void {
  const properties = buildAnnotationProperties(finding);
  const message = formatAnnotationMessage(finding);

  switch (finding.severity) {
    case 'high':
      core.error(message, properties);
      break;
    case 'medium':
      core.warning(message, properties);
      break;
    case 'low':
      core.notice(message, properties);
      break;
  }
}

/**
 * Build annotation properties from a finding.
 */
function buildAnnotationProperties(finding: Finding): AnnotationProperties {
  const properties: AnnotationProperties = {};

  // Title with rule ID if available
  if (finding.ruleId) {
    properties.title = `${finding.ruleId}: ${finding.title}`;
  } else {
    properties.title = finding.title;
  }

  // File path
  if (finding.file) {
    properties.file = finding.file;
  }

  // Line numbers
  if (finding.startLine !== undefined) {
    properties.startLine = finding.startLine;

    if (finding.endLine !== undefined) {
      properties.endLine = finding.endLine;
    }
  }

  return properties;
}

/**
 * Format the annotation message.
 */
function formatAnnotationMessage(finding: Finding): string {
  // Start with the message
  let message = finding.message;

  // Add snippet context if available (already masked)
  if (finding.snippet) {
    message += `\n\nContext:\n${finding.snippet}`;
  }

  return message;
}

/**
 * Get severity icon for display.
 */
export function getSeverityIcon(severity: Severity): string {
  switch (severity) {
    case 'high':
      return '🔴';
    case 'medium':
      return '🟡';
    case 'low':
      return '🔵';
  }
}

/**
 * Get annotation level for severity.
 */
export function getAnnotationLevel(severity: Severity): 'error' | 'warning' | 'notice' {
  switch (severity) {
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'notice';
  }
}
