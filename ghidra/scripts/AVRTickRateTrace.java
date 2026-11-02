import ghidra.program.model.symbol.Reference;
import ghidra.program.model.listing.Function;

// Find callers of FUN_08011910 (the per-tick countdown dispatcher) to determine
// what drives its call rate (main loop vs timer ISR), to translate the 100-tick
// countdown (that both button-standby's "safe" branch and our new trampoline arm)
// into a real-world duration.
public class AVRTickRateTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Function target = getFunctionAt(toAddr(0x08011910L));
        println("=== Callers of FUN_08011910 (tick dispatcher) ===");
        for (Reference ref : getReferencesTo(toAddr(0x08011910L))) {
            if (ref.getReferenceType().isCall()) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                println("  " + ref.getFromAddress() + " in " + (caller != null ? caller.getName() + "@" + caller.getEntryPoint() : "null"));
            }
        }

        // FUN_08010184 is the main loop body (called in infinite loop from FUN_08064ede).
        println("\n=== Decompile FUN_08010184 (main loop body) ===");
        ghidra.app.decompiler.DecompInterface decompiler = new ghidra.app.decompiler.DecompInterface();
        decompiler.openProgram(currentProgram);
        Function f = getFunctionAt(toAddr(0x08010184L));
        if (f != null) {
            ghidra.app.decompiler.DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
            if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
            else println("[failed: " + r.getErrorMessage() + "]");
        } else {
            println("[FUN_08010184 not found]");
        }

        // Look for SysTick config (NVIC/SysTick peripheral base 0xE000E010 region) references,
        // which would reveal the hardware tick period in a Cortex-M part.
        println("\n=== Searching for SysTick peripheral (0xE000E010) references ===");
        for (Reference ref : getReferencesTo(toAddr(0xE000E010L))) {
            Function caller = getFunctionContaining(ref.getFromAddress());
            println("  " + ref.getFromAddress() + " in " + (caller != null ? caller.getName() + "@" + caller.getEntryPoint() : "null"));
        }
        decompiler.dispose();
        println("\nDONE");
    }
}
