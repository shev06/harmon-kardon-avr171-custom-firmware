import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

// Toolchain + project smoke test (read-only): prints SMOKE lines that `make ghidra-smoke` checks.
public class AVRSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        int n = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            n++;
        }
        Function d = getFunctionAt(toAddr(0x0802d230L));
        println("SMOKE program=" + currentProgram.getName() + " base=" + currentProgram.getImageBase() + " functions=" + n);
        println("SMOKE dispatcher=" + (d == null ? "MISSING" : d.getName()));
    }
}
