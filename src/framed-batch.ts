export interface FramedBatchSection {
  output: string;
  status: number;
}

export function parseFramedBatch<Section extends string>(
  output: string,
  nonce: string,
  sections: readonly Section[],
  label: string,
): Map<Section, FramedBatchSection> {
  const parsed = new Map<Section, FramedBatchSection>();
  for (const section of sections) {
    const name = section.toUpperCase();
    const expression = new RegExp(`__MISE_${nonce}_${name}_BEGIN__\\n([\\s\\S]*?)\\n__MISE_${nonce}_${name}_STATUS_(\\d+)__\\n__MISE_${nonce}_${name}_END__`, "g");
    const matches = [...output.matchAll(expression)];
    if (matches.length !== 1) throw new Error(`${label} returned invalid ${section} framing`);
    parsed.set(section, { output: matches[0][1], status: Number(matches[0][2]) });
  }
  return parsed;
}
