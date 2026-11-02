import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

// Characterize real-world impact of the Active Source validation-bypass bug:
// decompile the callee that receives the (possibly garbage) source LA + PA,
// plus the PA own and PA-to-port lookup helpers used in the same branch.
public class AVRCecImpact extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();
    void dump(String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function f = getFunctionContaining(a);
        println("\n=== " + addrStr + " ===");
        if (f == null) { println("[no function]"); return; }
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
        else println("[failed: " + r.getErrorMessage() + "]");
    }
    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);
        dump("0x0808cde0"); // Active Source handler callee
        dump("0x0808cd5a"); // get own physical address
        dump("0x0809b3a4"); // PA -> input/port lookup
        dump("0x0808c9a2"); // input switch (called from Set Stream Path too)
        decompiler.dispose();
    }
}
