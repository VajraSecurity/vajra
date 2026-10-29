/**
 * CERT-In guideline hierarchy builders for NodesViewCertInCompliance —
 * normalizes raw JSON into a nested main-section/sub-section/entry/pointer
 * tree. Extracted verbatim, no logic changes.
 */

export type CertInGuideline = {
  marker: string;
  text: string;
  level: number;
  children?: CertInGuideline[];
  table?: {
    columns: string[];
    rows: Record<string, string | number>[];
  };
};

export type CertInSection = {
  title: string;
  marker: string;
  level: number;
  children: CertInGuideline[];
};

export type CertInPointer = {
  id: string;
  marker: string;
  text: string;
  children: CertInPointer[];
  table?: {
    columns: string[];
    rows: Record<string, string | number>[];
  };
};

export type CertInEntry = {
  id: string;
  standards: string;
  pointers: CertInPointer[];
};

export type CertInSubSection = {
  code: string;
  entries: CertInEntry[];
};

export type CertInMainSection = {
  code: string;
  subSections: CertInSubSection[];
};

export function normalizeGuideline(input: unknown): CertInGuideline {
  const obj = (input && typeof input === 'object') ? (input as Record<string, unknown>) : {};
  const tableObj = (obj.table && typeof obj.table === 'object') ? (obj.table as Record<string, unknown>) : null;
  const rawChildren = Array.isArray(obj.children) ? obj.children : [];

  return {
    marker: String(obj.marker ?? ''),
    text: String(obj.text ?? ''),
    level: Number(obj.level) || 0,
    children: rawChildren.map(normalizeGuideline),
    table: tableObj
      ? {
          columns: Array.isArray(tableObj.columns) ? tableObj.columns.map((c) => String(c ?? '')) : [],
          rows: Array.isArray(tableObj.rows)
            ? tableObj.rows
                .filter((r) => r && typeof r === 'object')
                .map((r) => r as Record<string, string | number>)
            : [],
        }
      : undefined,
  };
}

export function normalizeSection(input: unknown): CertInSection {
  const obj = (input && typeof input === 'object') ? (input as Record<string, unknown>) : {};
  const rawGuidelines = Array.isArray(obj.children) ? obj.children : [];

  return {
    title: String(obj.title ?? 'Untitled checklist'),
    marker: String(obj.marker ?? ''),
    level: Number(obj.level) || 1,
    children: rawGuidelines.map(normalizeGuideline),
  };
}

export function parseSectionParts(marker: string) {
  const clean = marker.trim();
  const [mainCode = 'OTHER', subCode = 'GEN'] = clean.split('.');
  return { mainCode, subCode };
}

export function normalizePointer(point: CertInGuideline, idPrefix: string): CertInPointer {
  const marker = String(point.marker || '').trim();
  const text = String(point.text || '').trim();
  const children = (point.children || []).map((child, childIndex) =>
    normalizePointer(child, `${idPrefix}-${marker}-${childIndex}`),
  );
  return {
    id: `${idPrefix}-${marker}`,
    marker,
    text,
    children,
    table: point.table,
  };
}

export function buildCertInSections(raw: unknown): CertInSection[] {
  if (!Array.isArray(raw)) return [];
  return raw.map(normalizeSection);
}

export function buildHierarchy(sections: CertInSection[]): CertInMainSection[] {
  const mainMap = new Map<string, Map<string, CertInSubSection>>();

  sections.forEach((section, sectionIndex) => {
    const { mainCode, subCode } = parseSectionParts(section.marker);
    if (!mainMap.has(mainCode)) mainMap.set(mainCode, new Map<string, CertInSubSection>());
    const subMap = mainMap.get(mainCode)!;
    if (!subMap.has(subCode)) {
      subMap.set(subCode, { code: subCode, entries: [] });
    }
    const subSection = subMap.get(subCode)!;
    const pointers = section.children.map((p, i) => normalizePointer(p, `${mainCode}-${subCode}-${sectionIndex}-${i}`));
    subSection.entries.push({
      id: `${mainCode}-${subCode}-entry-${sectionIndex}`,
      standards: section.title.trim() || 'Untitled checklist',
      pointers,
    });
  });

  return [...mainMap.entries()].map(([code, subMap]) => ({
    code,
    subSections: [...subMap.values()],
  }));
}

