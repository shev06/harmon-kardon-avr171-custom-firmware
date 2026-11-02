import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

// Decompile every OTHER (not-yet-patched) direct caller of FUN_08019638 to find
// out whether any of them independently consume the "fade" RAM cells
// (DAT_08019c6c -> 0x2001c2b6, DAT_08019c70 -> 0x2001bfd8) that our patch sets,
// i.e. whether something ELSE eventually completes the full shutdown after our
// deferred/safe action, which would explain "going to sleep" message appearing
// but the device still fully powering down shortly after.
public class AVRPowerOffOtherCallers extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();

    void dumpDecompile(String label, long addr) throws Exception {
        Address a = toAddr(addr);
        Function f = getFunctionContaining(a);
        println("\n=== " + label + " (containing " + a + ") ===");
        if (f == null) { println("[no function]"); return; }
        println("function: " + f.getEntryPoint() + " - " + f.getBody().getMaxAddress());
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        if (r.decompileCompleted()) {
            String c = r.getDecompiledFunction().getC();
            println(c);
            boolean refsFadeTarget = c.contains("19c6c") || c.contains("1c2b6");
            boolean refsFadeCounter = c.contains("19c70") || c.contains("1bfd8");
            println(">>> references fade-target(19c6c/1c2b6): " + refsFadeTarget + "   fade-counter(19c70/1bfd8): " + refsFadeCounter);
        } else {
            println("[failed: " + r.getErrorMessage() + "]");
        }
    }

    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);
        long[] addrs = {
            0x08064ede, // FUN_08064ede - suspiciously adjacent to STOP-mode sleep routine FUN_08064de8
            0x08011910,
            0x08013138,
            0x08013506,
            0x080136e0,
            0x08013a70,
            0x08013b08,
        };
        for (long a : addrs) {
            dumpDecompile("Caller cluster", a);
        }
        decompiler.dispose();
        println("\nDONE");
    }
}
