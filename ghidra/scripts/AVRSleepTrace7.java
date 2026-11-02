import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class AVRSleepTrace7 extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();
    void decompileAt(String label, String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function f = getFunctionContaining(a);
        println("\n=== " + label + " (" + addrStr + ") ===");
        if (f == null) { println("no function"); return; }
        println("function: " + f.getEntryPoint() + " " + f.getName() + " body ends " + f.getBody().getMaxAddress());
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
        else println("decompile incomplete");
    }
    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);
        decompileAt("FUN_08064ede (caller of FUN_08010184)", "0x08064ede");

        // Check symbol table / function name at this address - is it named SysTick_Handler or similar?
        Address a = currentProgram.getAddressFactory().getAddress("0x08064ede");
        Function f = getFunctionContaining(a);
        if (f != null) {
            for (Symbol s : currentProgram.getSymbolTable().getSymbols(f.getEntryPoint())) {
                println("symbol: " + s.getName() + " type=" + s.getSymbolType());
            }
        }

        println("\n=== Callers of FUN_08064ede ===");
        for (Reference ref : getReferencesTo(currentProgram.getAddressFactory().getAddress("0x08064ede"))) {
            Function cf = getFunctionContaining(ref.getFromAddress());
            println(ref.getFromAddress() + " in " + (cf == null ? "???" : cf.getEntryPoint() + " " + cf.getName()));
        }

        // Check interrupt vector table region near 0x08000000 for SysTick (vector index 15, offset 0x3C) to see if it points here or nearby
        println("\n=== Vector table entries 0x08000000 + 0x38..0x48 (PendSV/SysTick/IRQ0/IRQ1) ===");
        ghidra.program.model.mem.Memory mem = currentProgram.getMemory();
        for (int off = 0x38; off <= 0x48; off += 4) {
            int val = mem.getInt(currentProgram.getAddressFactory().getAddress("0x08000000").add(off));
            println("offset 0x" + Integer.toHexString(off) + " -> 0x" + Integer.toHexString(val));
        }
        decompiler.dispose();
    }
}
