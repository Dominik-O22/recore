// Marks when auto-analysis starts, which runs after the pre-scripts, so that ExportRef.java can
// write how long it took. Ghidra prints its own total only when it is a second or more.
import ghidra.app.script.GhidraScript;

public class StartTimer extends GhidraScript {
	@Override
	public void run() throws Exception {
		System.setProperty("recore.analysis.start", Long.toString(System.nanoTime()));
	}
}
