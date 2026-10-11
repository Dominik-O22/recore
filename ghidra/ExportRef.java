// Exports Ghidra's analysis result as JSON for scoring against ground truth.
// Addresses are written relative to the ELF's own addressing (image base subtracted).
// Args: <output.json>
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class ExportRef extends GhidraScript {
	@Override
	public void run() throws Exception {
		long base = currentProgram.getImageBase().getOffset();
		// Non-PIE executables are loaded at their link address, so nothing is subtracted.
		long shift = currentProgram.getMinAddress().getOffset() >= base && base == 0x100000 ? base : 0;
		Address min = currentProgram.getMinAddress();

		StringBuilder functions = new StringBuilder();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (functions.length() > 0) {
				functions.append(',');
			}
			StringBuilder ranges = new StringBuilder();
			f.getBody().forEach(r -> ranges.append(ranges.length() > 0 ? "," : "")
				.append('[').append(r.getMinAddress().getOffset() - shift).append(',')
				.append(r.getMaxAddress().getOffset() - shift + 1).append(']'));
			functions.append(String.format("{\"addr\":%d,\"ranges\":[%s],\"noreturn\":%b,\"thunk\":%b}",
				f.getEntryPoint().getOffset() - shift, ranges, f.hasNoReturn(), f.isThunk()));
		}

		StringBuilder callReturn = new StringBuilder();
		StringBuilder jumpTables = new StringBuilder();
		long instructions = 0;
		for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
			instructions++;
			if (ins.getFlowType().isJump() && ins.getFlowType().isComputed()) {
				// A recovered switch shows up as computed-jump references on the jump instruction.
				java.util.TreeSet<Long> targets = new java.util.TreeSet<>();
				for (ghidra.program.model.symbol.Reference ref : ins.getReferencesFrom()) {
					if (ref.getReferenceType().isJump() && ref.getToAddress().isMemoryAddress()) {
						targets.add(ref.getToAddress().getOffset() - shift);
					}
				}
				if (!targets.isEmpty()) {
					jumpTables.append(jumpTables.length() > 0 ? "," : "").append(String.format("{\"jump\":%d,\"targets\":%s}",
						ins.getAddress().getOffset() - shift, targets));
				}
			}
			// A jump given call semantics (a tail call) also has no fallthrough; only real calls count.
			if (ins.getMnemonicString().startsWith("CALL") && ins.getFlowType().isCall() &&
				ins.getFallThrough() == null) {
				callReturn.append(callReturn.length() > 0 ? "," : "").append(ins.getAddress().getOffset() - shift);
			}
		}

		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			out.printf("{\"name\":\"%s\",\"shift\":%d,\"min\":%d,\"instructions\":%d,\"functions\":[%s],\"noreturn_calls\":[%s],\"jump_tables\":[%s]}%n",
				currentProgram.getName(), shift, min.getOffset(), instructions, functions, callReturn, jumpTables);
		}
	}
}
