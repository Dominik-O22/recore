// Decompiles every function of the current program and writes what the decompiler recovered of
// each signature, in the format of `recore-decompile corpus` reports, for
// `recore-corpus score-signatures`. Argument: <output json>.
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;

public class ExportSignatures extends GhidraScript {
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        StringBuilder out = new StringBuilder("{\"name\":\"" + currentProgram.getName() + "\",\"functions\":[");
        boolean first = true;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.isExternal()) continue;
            long start = System.nanoTime();
            DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
            double ms = (System.nanoTime() - start) / 1e6;
            HighFunction high = results.getHighFunction();
            boolean ok = results.decompileCompleted() && high != null;
            int params = ok ? high.getFunctionPrototype().getNumParams() : 0;
            boolean returns = ok && !(high.getFunctionPrototype().getReturnType() instanceof VoidDataType);
            int length = ok && results.getDecompiledFunction() != null ? results.getDecompiledFunction().getC().length() : 0;
            out.append(first ? "" : ",").append("{\"addr\":").append(function.getEntryPoint().getOffset())
                .append(",\"status\":\"").append(ok ? "ok" : "error").append("\",\"ms\":").append(ms)
                .append(",\"params\":").append(params).append(",\"returns_value\":").append(returns)
                .append(",\"c_len\":").append(length).append("}");
            first = false;
        }
        out.append("]}");
        try (PrintWriter writer = new PrintWriter(getScriptArgs()[0])) {
            writer.print(out);
        }
        decompiler.dispose();
    }
}
