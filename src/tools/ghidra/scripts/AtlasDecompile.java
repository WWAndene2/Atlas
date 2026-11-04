// Ghidra headless post-script: decompiles functions to C and writes them as one JSON document to the path given as
// the first argument. The second argument, if present, is a comma-separated list of entry addresses (0x...); without
// it every function with a body in the file is decompiled. Read by ghidra-decompile.ts, which validates it.
// @category Atlas
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
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
        out.append(",\"c\":").append(json(r.getDecompiledFunction().getC()));
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
