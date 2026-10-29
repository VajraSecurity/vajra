/**
 * NestedChildren — recursive pointer-tree renderer used by
 * NodesViewCertInCompliance's guideline table. Extracted verbatim, no logic
 * changes.
 */

import type { CertInGuideline, CertInPointer } from '../utils/certinHierarchy';

function renderTable(table: CertInGuideline['table']) {
  if (!table) return null;
  return (
    <div className="mt-3 overflow-hidden rounded-lg border border-slate-200 bg-slate-50">
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left border-separate border-spacing-0">
          <thead>
            <tr>
              {table.columns.map((column) => (
                <th key={column} className="px-3 py-2 font-semibold uppercase tracking-wide sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">
                  {column}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {table.rows.map((row, rowIndex) => (
              <tr key={rowIndex} className={rowIndex % 2 === 0 ? 'bg-white' : 'bg-slate-50'}>
                {table.columns.map((column) => (
                  <td key={column} className="px-3 py-2 align-top text-slate-700">
                    {String(row[column] ?? '')}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function NestedChildren({ points, depth = 1 }: { points: CertInPointer[]; depth?: number }) {
  if (!points.length) return null;
  return (
    <div className="mt-2 space-y-1.5" style={{ marginLeft: `${depth * 16}px` }}>
      {points.map((point) => (
        <div key={point.id}>
          <div className="flex items-start gap-2 text-sm text-slate-700">
            <span className="shrink-0 font-semibold text-slate-500">{point.marker}.</span>
            <span>{point.text}</span>
          </div>
          {point.table && renderTable(point.table)}
          <NestedChildren points={point.children} depth={depth + 1} />
        </div>
      ))}
    </div>
  );
}

