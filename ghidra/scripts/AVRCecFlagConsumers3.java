import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

public class AVRCecFlagConsumers3 extends ghidra.app.script.GhidraScript {

    private DecompInterface decomp;

    private void dumpFn(String label, String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function fn = getFunctionAt(a);
        if (fn == null) {
            fn = getFunctionContaining(a);
        }
        if (fn == null) {
            println("=== " + label + " @ " + addrStr + " === NOT A FUNCTION");
            return;
        }
        println("\n=== " + label + " : " + fn.getName() + " @ " + fn.getEntryPoint() + " body ends "
                + fn.getBody().getMaxAddress() + " ===");
        DecompileResults res = decomp.decompileFunction(fn, 60, new ConsoleTaskMonitor());
        if (res != null && res.decompileCompleted()) {
            String c = res.getDecompiledFunction().getC();
            // Guard against runaway huge decompiles in the log
            if (c.length() > 12000) {
                println(c.substring(0, 12000) + "\n...[TRUNCATED " + c.length() + " total chars]...");
            } else {
                println(c);
            }
        } else {
            println("DECOMPILE FAILED: " + (res != null ? res.getErrorMessage() : "null result"));
        }

        boolean callsShutdown = fn.getBody().contains(
                currentProgram.getAddressFactory().getAddress("0x08019638"));
        // contains() on AddressSetView checks the entry range only if built that way; use a cheap text check instead.
        String bodyText = "";
        if (res != null && res.decompileCompleted()) {
            bodyText = res.getDecompiledFunction().getC();
        }
        println(">>> references FUN_08019638 directly in decompiled text: " + bodyText.contains("08019638"));
        println(">>> references FUN_080192e2 directly in decompiled text: " + bodyText.contains("080192e2"));
        println(">>> references FUN_08019272 directly in decompiled text: " + bodyText.contains("08019272"));
    }

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        dumpFn("cluster-reader-A", "0x0808e268");
        dumpFn("cluster-reader-B", "0x0808e51a");
        dumpFn("writer-giant", "0x080930ca");
        dumpFn("reader-giant", "0x08092fd8");
        dumpFn("reader-small", "0x08062e20");
        dumpFn("writer-small", "0x0807c2f4");

        decomp.dispose();
    }
}
