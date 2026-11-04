// Ghidra headless post-script: writes the analysed program's functions, calls and strings (with the functions reading each) as one JSON document to
// the path given as the script's first argument. Read by ghidra-output.ts, which validates it; keep both in step.
//
// Addresses are written as Ghidra holds them. Atlas loads with -loader-imagebase 0 so a position-independent ELF
// keeps the addresses its own symbol table uses, instead of Ghidra's default rebase to 0x100000.
// @category Atlas
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

public class AtlasExport extends GhidraScript {
  @Override
  protected void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 1) {
      throw new IllegalArgumentException("usage: AtlasExport.java <output.json>");
    }
    StringBuilder out = new StringBuilder();
    out.append("{\"format\":\"atlas-ghidra-export\",\"format_version\":1");
    out.append(",\"ghidra_version\":").append(json(getGhidraVersion()));
    out.append(",\"sha256\":").append(json(currentProgram.getExecutableSHA256()));
    out.append(",\"language\":").append(json(currentProgram.getLanguageID().getIdAsString()));
    out.append(",\"image_base\":").append(json(hex(currentProgram.getImageBase())));

    out.append(",\"functions\":[");
    StringBuilder calls = new StringBuilder();
    boolean firstFunction = true;
    boolean firstCall = true;
    FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
    while (functions.hasNext() && !monitor.isCancelled()) {
      Function f = functions.next();
      // Alignment padding after a call that never returns (nop, int3) is taken for code by Ghidra's analysis and
      // made a function; measured on AArch64 Lua: 104 of 1098 functions were such padding. Not a function.
      if (!f.isExternal() && isPadding(f)) continue;
      if (!firstFunction) out.append(',');
      firstFunction = false;
      out.append("{\"address\":").append(json(hex(f.getEntryPoint())));
      out.append(",\"size\":").append(f.getBody().getNumAddresses());
      out.append(",\"label\":").append(json(f.getName()));
      out.append(",\"thunk\":").append(f.isThunk());
      // Imports of a dynamically linked file sit in a synthetic EXTERNAL block, outside the file's bytes.
      boolean external = f.isExternal() || isInExternalBlock(f.getEntryPoint());
      out.append(",\"external\":").append(external).append('}');
      if (external) continue;
      // Call sites: every call reference from inside this function's body to the entry of a function.
      ReferenceIterator refs = currentProgram.getReferenceManager().getReferenceIterator(f.getBody().getMinAddress());
      while (refs.hasNext()) {
        Reference r = refs.next();
        if (!f.getBody().contains(r.getFromAddress())) {
          if (r.getFromAddress().compareTo(f.getBody().getMaxAddress()) > 0) break;
          continue;
        }
        if (!r.getReferenceType().isCall()) continue;
        Function callee = getFunctionAt(r.getToAddress());
        if (callee == null) continue;
        if (!firstCall) calls.append(',');
        firstCall = false;
        calls.append("{\"from\":").append(json(hex(f.getEntryPoint())));
        calls.append(",\"to\":").append(json(hex(callee.getEntryPoint())));
        calls.append(",\"site\":").append(json(hex(r.getFromAddress()))).append('}');
      }
    }
    out.append("],\"calls\":[").append(calls).append(']');

    out.append(",\"strings\":[");
    boolean firstString = true;
    DataIterator data = currentProgram.getListing().getDefinedData(true);
    while (data.hasNext() && !monitor.isCancelled()) {
      Data d = data.next();
      if (!d.hasStringValue()) continue;
      Object value = d.getValue();
      if (!(value instanceof String)) continue;
      if (!firstString) out.append(',');
      firstString = false;
      out.append("{\"address\":").append(json(hex(d.getAddress())));
      out.append(",\"value\":").append(json((String) value));
      // Functions whose code refers to the string, each listed once.
      out.append(",\"readers\":[");
      java.util.TreeSet<Long> readers = new java.util.TreeSet<>();
      for (Reference r : getReferencesTo(d.getAddress())) {
        Function reader = getFunctionContaining(r.getFromAddress());
        if (reader != null && !reader.isExternal()) readers.add(reader.getEntryPoint().getOffset());
      }
      boolean firstReader = true;
      for (Long reader : readers) {
        if (!firstReader) out.append(',');
        firstReader = false;
        out.append(json("0x" + Long.toHexString(reader)));
      }
      out.append("]}");
    }
    out.append("]}\n");

    try (Writer w = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
      w.write(out.toString());
    }
  }

  private boolean isInExternalBlock(Address a) {
    var block = currentProgram.getMemory().getBlock(a);
    return block == null || block.getName().equals("EXTERNAL");
  }

  private boolean isPadding(Function f) {
    var instructions = currentProgram.getListing().getInstructions(f.getBody(), true);
    boolean any = false;
    while (instructions.hasNext()) {
      String m = instructions.next().getMnemonicString().toLowerCase();
      if (!m.equals("nop") && !m.equals("int3")) return false;
      any = true;
    }
    return any;
  }

  private static String hex(Address a) {
    return "0x" + Long.toHexString(a.getOffset());
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
