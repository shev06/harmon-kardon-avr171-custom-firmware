import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.List;

public class AVRCecStandbyTrace extends ghidra.app.script.GhidraScript {

    private DecompInterface decompiler;

    private void dumpFunction(String label, String addrHex, int depth) throws Exception {
        Address addr = currentProgram.getAddressFactory().getAddress(addrHex);
        Function fn = getFunctionAt(addr);
        if (fn == null) {
            println(label + " @ " + addrHex + ": NO FUNCTION FOUND");
            return;
        }
        println("\n=== " + label + " : " + fn.getName() + " @ " + fn.getEntryPoint() + " ===");
        DecompileResults result = decompiler.decompileFunction(fn, 60, monitor);
        if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
            println(result.getDecompiledFunction().getC());
        } else {
            println("Decompilation incomplete");
        }

        // raw disassembly too (helps for tiny functions where decompiler may over-simplify)
        println("  -- raw disassembly --");
        for (Address a : fn.getBody().getAddresses(true)) {
            Instruction instr = getInstructionAt(a);
            if (instr == null) continue;
            println("  " + a + "  " + instr.toString());
        }

        // list direct callees
        List<String> calleeAddrs = new ArrayList<>();
        for (Address a : fn.getBody().getAddresses(true)) {
            Instruction instr = getInstructionAt(a);
            if (instr == null || !instr.getFlowType().isCall()) continue;
            for (Reference ref : getReferencesFrom(a)) {
                Function callee = getFunctionAt(ref.getToAddress());
                if (callee != null) {
                    String s = callee.getEntryPoint().toString();
                    if (!calleeAddrs.contains(s)) {
                        calleeAddrs.add(s);
                        println("  calls -> " + callee.getEntryPoint() + " " + callee.getName());
                    }
                }
            }
        }

        // does this function reference the sleep-countdown counter or known fade RAM cells?
        String[] watch = {"2001c2ab", "19c6c", "19c70", "19638"};
        for (Address a : fn.getBody().getAddresses(true)) {
            Instruction instr = getInstructionAt(a);
            if (instr == null) continue;
            String s = instr.toString();
            for (String w : watch) {
                if (s.contains(w)) {
                    println("  >>> REF to watched addr/const (" + w + ") at " + a + ": " + s);
                }
            }
        }

        if (depth > 0) {
            for (String calleeAddr : calleeAddrs) {
                dumpFunction(label + " -> callee", calleeAddr, depth - 1);
            }
        }
    }

    @Override
    public void run() throws Exception {
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        println("##### CEC STANDBY TARGET: FUN_0808c9c8 (called as FUN_0808c9c8(1) from CEC <Standby> RX) #####");
        dumpFunction("cec-standby-target", "0x0808c9c8", 2);

        println("\n##### COMPARISON: shared power-off handler FUN_080192e2 (network/button target) #####");
        dumpFunction("network-button-power-off", "0x080192e2", 0);

        println("\n##### COMPARISON: full shutdown routine FUN_08019638 #####");
        dumpFunction("full-shutdown", "0x08019638", 0);

        // Also find ALL callers of FUN_0808c9c8 to see if CEC is its only caller
        println("\n##### CALLERS OF FUN_0808c9c8 #####");
        Address target = currentProgram.getAddressFactory().getAddress("0x0808c9c8");
        Function targetFn = getFunctionAt(target);
        if (targetFn != null) {
            for (Reference ref : getReferencesTo(targetFn.getEntryPoint())) {
                Address from = ref.getFromAddress();
                Function caller = getFunctionContaining(from);
                println("  caller site " + from + " in function " + (caller != null ? caller.getName() + "@" + caller.getEntryPoint() : "UNKNOWN"));
            }
        }

        decompiler.dispose();
    }
}
