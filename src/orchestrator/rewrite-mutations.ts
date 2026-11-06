// The edits the rewrite repairer tries on a function's C, one at a time: the causes of near misses measured on Lua
// (AGENTS.md 1.7): a missing static, noreturn on a callee, GCC attributes that pin how the function is compiled
// (noipa, cold, no-shrink-wrap, no-isolate-erroneous-paths-dereference), Ghidra's placeholder types taken for real
// ones (undefined8 for long, unsigned long or a pointer), signedness, and the order of a comparison's operands.
// Each mutation is a pure edit of the source text; the repairer keeps those that bring the compiled code closer.

export interface Mutation {
  /** What the edit does, recorded with the repaired rewrite. */
  label: string;
  apply(source: string): string | undefined;
}

const escape = (name: string) => name.replace(/[$]/g, "\\$");

/** The start of the line defining `name` (its body follows), or -1. */
function definitionStart(source: string, name: string): number {
  const m = new RegExp(`^[^\\n;#]*\\b${escape(name)}\\s*\\([^;{]*\\)\\s*\\{`, "m").exec(source);
  return m === null ? -1 : m.index;
}

function functionAttribute(name: string, attribute: string): Mutation {
  return {
    label: `__attribute__((${attribute})) on ${name}`,
    apply(source) {
      const at = definitionStart(source, name);
      if (at < 0 || source.slice(at, at + 200).includes(attribute)) return undefined;
      return `${source.slice(0, at)}__attribute__((${attribute})) ${source.slice(at)}`;
    },
  };
}

function toggleStatic(name: string): Mutation {
  return {
    label: `static on ${name}, or not`,
    apply(source) {
      const at = definitionStart(source, name);
      if (at < 0) return undefined;
      const line = source.slice(at, source.indexOf("\n", at));
      const toggled = /\bstatic\s+/.test(line) ? line.replace(/\bstatic\s+/, "") : `static ${line}`;
      return source.slice(0, at) + toggled + source.slice(at + line.length);
    },
  };
}

/** Callees declared on a line of their own (prototype), as Ghidra's units and most rewrites do. */
function declaredCallees(source: string, name: string): string[] {
  const out = new Set<string>();
  for (const m of source.matchAll(/^[^\n;{}#]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*;\s*$/gm)) {
    if (m[1] !== undefined && m[1] !== name && !/^(if|while|for|switch|return|sizeof)$/.test(m[1])) out.add(m[1]);
  }
  return [...out];
}

function toggleNoreturn(callee: string): Mutation {
  return {
    label: `noreturn on ${callee}, or not`,
    apply(source) {
      const re = new RegExp(`^([^\\n;{}#]*?\\b${escape(callee)}\\s*\\([^;{}]*\\)\\s*;)`, "m");
      const m = re.exec(source);
      if (m === null) return undefined;
      const line = m[1] as string;
      const toggled = line.includes("noreturn")
        ? line.replace(/__attribute__\(\(noreturn\)\)\s*/, "")
        : `__attribute__((noreturn)) ${line}`;
      return source.slice(0, m.index) + toggled + source.slice(m.index + line.length);
    },
  };
}

function replaceType(from: string, to: string): Mutation {
  return {
    label: `${from} written ${to}`,
    apply(source) {
      const re = new RegExp(`\\b${escape(from)}\\b(?!\\s*\\()`, "g");
      const out = source.replace(re, to);
      return out === source ? undefined : out;
    },
  };
}

function swapComparison(index: number): Mutation {
  return {
    label: `operands of comparison ${index + 1} swapped`,
    apply(source) {
      let seen = 0;
      let changed = false;
      // Simple operands only (names, members, numbers): swapping them changes nothing in C's meaning for == and !=.
      const out = source.replace(/([\w.>-]+(?:\[[\w]+\])?)\s*(==|!=)\s*([\w.>-]+(?:\[[\w]+\])?)/g, (all, a, op, b) => {
        if (seen++ !== index || a === b) return all;
        changed = true;
        return `${b} ${op} ${a}`;
      });
      return changed ? out : undefined;
    },
  };
}

/** Every single edit worth trying on `name`'s source, cheapest-to-explain first. */
export function mutationsFor(source: string, name: string): Mutation[] {
  const attributes = [
    "noipa",
    "cold",
    "noinline",
    'optimize("no-shrink-wrap")',
    'optimize("no-isolate-erroneous-paths-dereference")',
  ].map((a) => functionAttribute(name, a));
  const types = [
    ["undefined8", "long"],
    ["undefined8", "unsigned long"],
    ["undefined8", "void *"],
    ["undefined4", "int"],
    ["undefined4", "unsigned int"],
    ["uint", "int"],
    ["int", "uint"],
    ["ulong", "long"],
    ["long", "ulong"],
    ["char", "uchar"],
    ["uchar", "char"],
  ].map(([from, to]) => replaceType(from as string, to as string));
  const callees = declaredCallees(source, name).slice(0, 12).map(toggleNoreturn);
  const comparisons = Array.from({ length: Math.min(8, (source.match(/==|!=/g) ?? []).length) }, (_, i) =>
    swapComparison(i),
  );
  return [toggleStatic(name), ...attributes, ...callees, ...types, ...comparisons];
}
