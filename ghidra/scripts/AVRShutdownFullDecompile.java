import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;

// Full decompile + call-list of FUN_08019638 (the deep/hard shutdown routine),
// plus a one-level decompile of every function it calls, to find the SPECIFIC
// sub-behavior that cuts network/control-port reachability -- distinct from
// the legitimate "go to sleep" sub-behaviors (amp mute, display off, state
// reset) that must be preserved.
public class AVRShutdownFullDecompile extends ghidra.app.script.GhidraScript {
    private DecompInterface decompiler;

    private String decompile(Function f) throws Exception {
        if (f == null) return "[null function]";
        DecompileResults r = decompiler.decompileFunction(f, 90, monitor);
        if (!r.decompileCompleted()) return "[decompile failed: " + r.getErrorMessage() + "]";
        return r.getDecompiledFunction().getC();
    }

    @Override
    public void run() throws Exception {
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        Function shutdownFn = getFunctionAt(toAddr(0x08019638L));
        println("=== FULL DECOMPILE: FUN_08019638 (deep/hard shutdown) ===");
        String body = decompile(shutdownFn);
        println(body);

        println("\n=== Address range: " + shutdownFn.getBody() + " ===");

        println("\n=== Direct calls FROM FUN_08019638 (callees) ===");
        java.util.Set<Address> callees = new java.util.TreeSet<>();
        Instruction insn = getInstructionAt(shutdownFn.getEntryPoint());
        Address end = shutdownFn.getBody().getMaxAddress();
        while (insn != null && insn.getAddress().compareTo(end) <= 0) {
            if (insn.getFlowType().isCall()) {
                for (Reference ref : insn.getReferencesFrom()) {
                    if (ref.getReferenceType().isCall()) {
                        callees.add(ref.getToAddress());
                    }
                }
            }
            insn = insn.getNext();
        }
        for (Address c : callees) {
            Function cf = getFunctionAt(c);
            println("  callee: " + c + "  " + (cf != null ? cf.getName() : "[no function]"));
        }

        println("\n=== One-level decompile of each callee ===");
        for (Address c : callees) {
            Function cf = getFunctionAt(c);
            println("\n--- " + (cf != null ? cf.getName() : "FUN_" + c) + " @ " + c + " ---");
            println(decompile(cf));
        }

        decompiler.dispose();
        println("\nDONE_FULL_DECOMPILE");
    }
}
