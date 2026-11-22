/**
 * Deterministic field mapping for data crossing heterogeneous provider boundaries.
 * This engine never evaluates expressions, code, remote URLs, or arbitrary functions.
 * Only own-properties of plain JSON-like objects are read.
 */
export type FieldType = 'string' | 'number' | 'boolean' | 'raw';
export interface FieldMapping {
  readonly from: string;
  readonly to: string;
  readonly type: FieldType;
  readonly required?: boolean;
}
export class MappingError extends Error {
  readonly code: 'INVALID_MAPPING'|'MISSING_FIELD'|'INVALID_VALUE';
  constructor(code: MappingError['code'], message: string) {
    super(message);
    this.code = code;
    this.name = 'MappingError';
  }
}
const fieldName = (s: string): boolean =>
  typeof s === 'string' && /^[A-Za-z_][A-Za-z0-9_-]{0,127}$/.test(s) &&
  !['__proto__','prototype','constructor'].includes(s);
const ownRecord = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) &&
  (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
function selectPath(source: Record<string, unknown>, path: string): { found: boolean; value?: unknown } {
  let current: unknown = source;
  for (const segment of path.split('.')) {
    if (!ownRecord(current) || !Object.hasOwn(current, segment)) return {found:false};
    current = current[segment];
  }
  return {found:true, value:current};
}
function convert(value: unknown, type: FieldType): unknown {
  if (type === 'raw') return value;
  if (type === 'string') {
    if (typeof value === 'string') return value;
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
    if (typeof value === 'boolean') return String(value);
  }
  if (type === 'number') {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string' && value.trim() && Number.isFinite(Number(value))) return Number(value);
  }
  if (type === 'boolean') {
    if (typeof value === 'boolean') return value;
    if (value === 'true') return true;
    if (value === 'false') return false;
  }
  throw new MappingError('INVALID_VALUE', 'Source value cannot be converted to target type');
}
export function mapRecord(source: unknown, mappings: readonly FieldMapping[]): Record<string, unknown> {
  if (!ownRecord(source) || !Array.isArray(mappings) || !mappings.length || mappings.length > 256)
    throw new MappingError('INVALID_MAPPING', 'Expected a plain record and 1–256 mapping rules');
  const target: Record<string, unknown> = Object.create(null);
  const used = new Set<string>();
  for (const mapping of mappings) {
    if (!mapping || !fieldName(mapping.to) || !mapping.from ||
      !mapping.from.split('.').every(fieldName) ||
      !['string','number','boolean','raw'].includes(mapping.type) ||
      used.has(mapping.to)) {
      throw new MappingError('INVALID_MAPPING', 'Invalid or duplicate mapping target');
    }
    used.add(mapping.to);
    const {found,value} = selectPath(source,mapping.from);
    if (!found || value === null || value === undefined) {
      if (mapping.required) throw new MappingError('MISSING_FIELD', 'Missing required source field');
      continue;
    }
    target[mapping.to] = convert(value,mapping.type);
  }
  return target;
}
