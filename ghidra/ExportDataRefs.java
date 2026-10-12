// Writes every reference an instruction makes to memory that is not where control goes next,
// one per line as `<from> <to> <access|data> <source>` in decimal, for
// `recore-corpus score-references`. Addresses are shifted as in `ExportRef.java`. Args: <output file>
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class ExportDataRefs extends GhidraScript {
	@Override
	public void run() throws Exception {
		long base = currentProgram.getImageBase().getOffset();
		long shift = currentProgram.getMinAddress().getOffset() >= base && base == 0x100000 ? base : 0;
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
				for (Reference ref : ins.getReferencesFrom()) {
					RefType type = ref.getReferenceType();
					if (!ref.getToAddress().isMemoryAddress() || type.isFlow()) continue;
					String kind = type.isRead() || type.isWrite() ? "access" : "data";
					out.printf("%d %d %s %s%n", ins.getAddress().getOffset() - shift, ref.getToAddress().getOffset() - shift, kind, ref.getSource());
				}
			}
		}
	}
}
