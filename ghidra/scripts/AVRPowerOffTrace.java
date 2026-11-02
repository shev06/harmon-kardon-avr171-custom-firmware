import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.List;

public class AVRPowerOffTrace extends ghidra.app.script.GhidraScript {

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

        // does this function (directly, in its own body) reference 0x2001c2ab?
        boolean touchesCounter = false;
        for (Address a : fn.getBody().getAddresses(true)) {
            Instruction instr = getInstructionAt(a);
            if (instr == null) continue;
            String s = instr.toString();
            if (s.contains("2001c2ab")) {
                touchesCounter = true;
                println("  >>> DIRECT COUNTER REF at " + a + ": " + s);
            }
        }
        if (!touchesCounter) {
            println("  (no direct reference to 0x2001c2ab in this function's own body)");
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

        println("##### MAIN-ZONE POWER-ON HANDLER #####");
        dumpFunction("power-on(main zone)", "0x080192ce", 1);

        println("\n##### MAIN-ZONE POWER-OFF HANDLER #####");
        dumpFunction("power-off(main zone)", "0x080192e2", 1);

        println("\n##### MAIN-ZONE POWER-TOGGLE HANDLER #####");
        dumpFunction("power-toggle(main zone)", "0x08019272", 1);

        decompiler.dispose();
    }
}
