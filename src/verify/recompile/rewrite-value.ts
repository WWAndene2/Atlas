// The value of a rewrite hypothesis: a function's source, checked when it is proposed and when it is verified.

export interface RewriteValue {
  language: "c";
  /** A translation unit defining the function, with the declarations it needs. */
  source: string;
  /** The function's name in that source. */
  name: string;
  /** "ghidra": the source uses Ghidra's built-in types (undefined8...), and ghidra-types.h is included before it. */
  prelude?: "ghidra";
  /**
   * A run of neighbouring functions: the source defines every function from this hypothesis's function up to `last`,
   * in their original order, and they are checked as one block (needed when they jump to each other).
   */
  last?: { node: string; name: string };
}

export function isRewriteValue(value: unknown): value is RewriteValue {
  const v = value as Partial<RewriteValue> | null;
  return (
    typeof v === "object" &&
    v !== null &&
    v.language === "c" &&
    typeof v.source === "string" &&
    typeof v.name === "string" &&
    /^[A-Za-z_]\w*$/.test(v.name) &&
    (v.prelude === undefined || v.prelude === "ghidra") &&
    (v.last === undefined ||
      (typeof v.last === "object" &&
        v.last !== null &&
        typeof v.last.node === "string" &&
        typeof v.last.name === "string" &&
        /^[A-Za-z_]\w*$/.test(v.last.name)))
  );
}
