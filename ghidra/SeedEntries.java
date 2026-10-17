// Disassembles at the addresses given as arguments and makes each a function, so analysis starts
// where a raw image's vector table says the hardware enters.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class SeedEntries extends GhidraScript {
	@Override
	public void run() throws Exception {
		for (String arg : getScriptArgs()) {
			Address addr = toAddr(Long.decode(arg));
			disassemble(addr);
			createFunction(addr, null);
		}
	}
}
