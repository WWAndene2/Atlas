// Ghidra headless post-script: decompiles functions to C and writes them as one JSON document to the path given as
// the first argument. Each function comes as a whole translation unit: the definitions of the types it uses, extern
// declarations of the globals it touches, prototypes of the functions it calls (noreturn marked), then its body.
// Ghidra prints only the body; without the rest, most of its C did not compile (undeclared globals, unknown types),
// and calls to undeclared functions compiled as returning int. The second argument, if present, is a comma-separated list of entry addresses (0x...); without
// it every function with a body in the file is decompiled. Read by ghidra-decompile.ts, which validates it.
// @category Atlas
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeWriter;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import java.io.StringWriter;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class AtlasDecompile extends GhidraScript {
  @Override
  protected void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length < 1) throw new IllegalArgumentException("usage: AtlasDecompile.java <output.json> [0xaddr,...]");
    List<Function> targets = new ArrayList<>();
    if (args.length > 1 && !args[1].isEmpty()) {
      for (String a : args[1].split(",")) {
        Function f = getFunctionAt(toAddr(Long.parseUnsignedLong(a.substring(2), 16)));
        if (f != null) targets.add(f);
      }
    } else {
      for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
        if (!f.isExternal() && !f.isThunk()) targets.add(f);
      }
    }
    DecompInterface decompiler = new DecompInterface();
    decompiler.openProgram(currentProgram);
    StringBuilder out = new StringBuilder("{\"format\":\"atlas-ghidra-decompile\",\"format_version\":1,\"functions\":[");
    boolean first = true;
    for (Function f : targets) {
      if (monitor.isCancelled()) break;
      DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
      if (!first) out.append(',');
      first = false;
      out.append("{\"address\":").append(json("0x" + Long.toHexString(f.getEntryPoint().getOffset())));
      out.append(",\"label\":").append(json(f.getName()));
      if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
        String body = r.getDecompiledFunction().getC();
        out.append(",\"c\":").append(json(declarations(f, r.getHighFunction()) + body));
      } else {
        out.append(",\"error\":").append(json(r == null ? "no result" : r.getErrorMessage()));
      }
      out.append('}');
    }
    out.append("]}\n");
    decompiler.dispose();
    try (Writer w = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
      w.write(out.toString());
    }
  }

  // Names the prelude (src/verify/recompile/ghidra-types.h) already defines: a second typedef would be an error.
  private static final Set<String> PRELUDE = Set.of("undefined", "undefined1", "undefined2", "undefined4",
      "undefined8", "byte", "uchar", "ushort", "uint", "ulong", "longlong", "ulonglong", "bool", "word", "dword",
      "qword", "uint3", "uint5", "uint6", "uint7", "undefined5", "undefined6", "undefined7", "wchar16", "wchar32",
      "code", "pointer32", "pointer64", "ImageBaseOffset32", "ImageBaseOffset64", "float10");

  private String declarations(Function f, HighFunction hf) {
    Set<DataType> types = new LinkedHashSet<>();
    StringBuilder decls = new StringBuilder();
    Set<String> declared = new LinkedHashSet<>();
    if (hf != null) {
      Iterator<HighSymbol> globals = hf.getGlobalSymbolMap().getSymbols();
      while (globals.hasNext()) {
        HighSymbol g = globals.next();
        DataType dt = g.getDataType();
        String name = g.getName();
        if (dt == null || name == null || !name.matches("[A-Za-z_]\\w*") || !declared.add(name)) continue;
        // A global that is a function's address is declared as a function below, if called.
        if (g.getStorage() != null && g.getStorage().getMinAddress() != null
            && getFunctionAt(g.getStorage().getMinAddress()) != null) continue;
        collect(dt, types);
        decls.append("extern ").append(declare(dt, name)).append(";\n");
      }
      var locals = hf.getLocalSymbolMap().getSymbols();
      while (locals.hasNext()) collect(locals.next().getDataType(), types);
    }
    collectSignature(f.getSignature(), types);
    StringBuilder prototypes = new StringBuilder();
    for (Function callee : f.getCalledFunctions(monitor)) {
      if (callee.equals(f) || !callee.getName().matches("[A-Za-z_]\\w*") || !declared.add(callee.getName())) continue;
      if (callee.hasNoReturn()) prototypes.append("__attribute__((noreturn)) ");
      if (callee.getSignatureSource() == SourceType.DEFAULT) {
        // No analysed signature (most callees of a stripped binary): Ghidra's default, f(void), contradicts the
        // arguments its own C passes (2,467 "too many arguments" on Lua). Declared without a prototype instead,
        // keeping the return type, which is what changes the generated code.
        collect(callee.getReturnType(), types);
        prototypes.append(declare(callee.getReturnType(), callee.getName() + "()")).append(";\n");
      } else {
        collectSignature(callee.getSignature(), types);
        prototypes.append(callee.getSignature().getPrototypeString(false)).append(";\n");
      }
    }
    StringWriter definitions = new StringWriter();
    try {
      new DataTypeWriter(currentProgram.getDataTypeManager(), definitions).write(new java.util.ArrayList<>(types), monitor);
    } catch (Exception e) {
      definitions.write("/* type definitions unavailable: " + e.getMessage() + " */\n");
    }
    StringBuilder unit = new StringBuilder();
    for (String line : definitions.toString().split("\n")) {
      // The writer also emits the built-in typedefs it depends on, which the prelude defines already.
      String t = line.trim();
      // The writer names some built-ins alone on a line (float10 on Windows Lua): not C.
      if (t.matches("[A-Za-z_]\\w*")) continue;
      if (t.startsWith("typedef ") && t.endsWith(";")) {
        String name = t.substring(0, t.length() - 1).replaceAll(".*[\\s*]", "");
        if (PRELUDE.contains(name)) continue;
      }
      unit.append(line).append('\n');
    }
    return unit + decls.toString() + prototypes + "\n";
  }

  private void collectSignature(ghidra.program.model.listing.FunctionSignature sig, Set<DataType> types) {
    collect(sig.getReturnType(), types);
    for (ParameterDefinition p : sig.getArguments()) collect(p.getDataType(), types);
  }

  /**
   * Types that need a definition: structures, unions, enums, typedefs and function types, behind pointers or arrays.
   * Dependencies come first (the writer keeps this order): DataTypeWriter writes what a structure's members need,
   * but a typedef of an array such as jmp_buf it leaves out, or writes after its use (with DWARF, 680 of 706 of Lua
   * 5.4.6's rewrites failed on it), so members and typedef targets are collected here, before the type itself.
   */
  private static void collect(DataType dt, Set<DataType> types) {
    collect(dt, types, new java.util.HashSet<>());
  }

  private static void collect(DataType dt, Set<DataType> types, Set<DataType> visiting) {
    DataType base = dt;
    while (base instanceof Pointer || base instanceof Array) {
      base = base instanceof Pointer ? ((Pointer) base).getDataType() : ((Array) base).getDataType();
    }
    if (base == null || base instanceof BuiltInDataType || PRELUDE.contains(base.getName())) return;
    if (types.contains(base) || !visiting.add(base)) return;
    if (base instanceof Composite) {
      for (DataTypeComponent c : ((Composite) base).getDefinedComponents()) {
        // Through a pointer a member needs only the forward declaration the writer always emits.
        if (!(c.getDataType() instanceof Pointer)) collect(c.getDataType(), types, visiting);
      }
    }
    if (base instanceof TypeDef) collect(((TypeDef) base).getDataType(), types, visiting);
    if (base instanceof FunctionDefinition) {
      FunctionDefinition fd = (FunctionDefinition) base;
      for (ParameterDefinition p : fd.getArguments()) collect(p.getDataType(), types, visiting);
      collect(fd.getReturnType(), types, visiting);
    }
    types.add(base);
  }

  /** A declaration of `name` with type `dt`, arrays written C's way (char name[16], not char[16] name). */
  private static String declare(DataType dt, String name) {
    if (dt instanceof Array) {
      Array a = (Array) dt;
      return declare(a.getDataType(), name + "[" + a.getNumElements() + "]");
    }
    String type = dt.getDisplayName();
    return type.endsWith("*") ? type + name : type + " " + name;
  }

  private static String json(String s) {
    if (s == null) return "null";
    StringBuilder b = new StringBuilder("\"");
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '"' || c == '\\') b.append('\\').append(c);
      else if (c < 0x20 || (c >= 0xd800 && c <= 0xdfff)) b.append(String.format("\\u%04x", (int) c));
      else b.append(c);
    }
    return b.append('"').toString();
  }
}
