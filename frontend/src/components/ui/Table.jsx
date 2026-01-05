// ====================================================================
// frontend\src\components\ui\Table.jsx
// --------------------------------------------------------------------
// Reusable data table with:
//  - Glassmorphism styling
//  - Auto responsiveness
//  - Optional row click
// ====================================================================

import React from "react";

export default function Table({ columns = [], data = [], onRowClick }) {
  return (
    <div className="w-full overflow-x-auto rounded-xl glass-card p-0">
      <table className="min-w-full divide-y divide-white/20">
        <thead className="bg-white/10">
          <tr>
            {columns.map((col) => (
              <th
                key={col.accessor}
                className="px-4 py-3 text-left text-sm font-semibold text-white tracking-wide"
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>

        <tbody className="divide-y divide-white/10">
          {data.length === 0 && (
            <tr>
              <td className="px-4 py-6 text-white/70 text-center" colSpan={columns.length}>
                No records found
              </td>
            </tr>
          )}

          {data.map((row, idx) => (
            <tr
              key={idx}
              className={`hover:bg-white/10 transition ${onRowClick ? "cursor-pointer" : ""}`}
              onClick={() => onRowClick && onRowClick(row)}
            >
              {columns.map((col) => (
                <td key={col.accessor} className="px-4 py-3 text-white/90 text-sm">
                  {col.cell ? col.cell(row) : row[col.accessor]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
