/**
 * Output module
 *
 * Exports output generation functionality.
 *
 * @module output
 */

export type { AnnotationResult } from './annotations';
export {
  emitAnnotations,
  emitFindingAnnotations,
  getSeverityIcon,
  getAnnotationLevel,
} from './annotations';
export { writeSummary, generateSummaryMarkdown, generateEmptySummary } from './summary';
