import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class AVRSleepTrace2 extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();

    void rawDisasm(String startStr, String endStr) throws Exception {
        Address start = currentProgram.getAddressFactory().getAddress(startStr);
        Address end = currentProgram.getAddressFactory().getAddress(endStr);
        Instruction insn = getInstructionAt(start);
        if (insn == null) insn = currentProgram.getListing().getInstructionAfter(start);
        while (insn != null && insn.getAddress().compareTo(end) <= 0) {
            StringBuilder sb = new StringBuilder();
            sb.append(insn.getAddress()).append(": ").append(insn.toString());
            println(sb.toString());
            insn = insn.getNext();
        }
    }

    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);

        println("=== Decompile FUN_08064de8 (PWR_CR + WFI/WFE function) ===");
        Address a = currentProgram.getAddressFactory().getAddress("0x08064de8");
        Function f = getFunctionContaining(a);
        if (f != null) {
            DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
            println("function: " + f.getEntryPoint() + " body ends " + f.getBody().getMaxAddress());
            if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
        }

        println("\n=== Raw disassembly 0x08064de8 - 0x08064e20 ===");
        rawDisasm("0x08064de8", "0x08064e20");

        println("\n=== Callers of FUN_08064de8 ===");
        Address target = currentProgram.getAddressFactory().getAddress("0x08064de8");
        for (Reference ref : getReferencesTo(target)) {
            Function cf = getFunctionContaining(ref.getFromAddress());
            println(ref.getFromAddress() + " " + ref.getReferenceType() + " in " +
                (cf == null ? "???" : cf.getEntryPoint() + " " + cf.getName()));
        }

        // Decompile each caller
        println("\n=== Decompile each caller ===");
        java.util.Set<String> done = new java.util.HashSet<>();
        for (Reference ref : getReferencesTo(target)) {
            Function cf = getFunctionContaining(ref.getFromAddress());
            if (cf != null && done.add(cf.getEntryPoint().toString())) {
                DecompileResults r = decompiler.decompileFunction(cf, 60, monitor);
                println("--- " + cf.getEntryPoint() + " " + cf.getName() + " ---");
                if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
            }
        }

        decompiler.dispose();
    }
}
