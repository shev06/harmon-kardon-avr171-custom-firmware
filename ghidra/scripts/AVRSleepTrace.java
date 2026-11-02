import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRSleepTrace extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();
    Set<String> printedFuncs = new HashSet<>();

    void decompileFunctionAt(Address a) throws Exception {
        Function f = getFunctionContaining(a);
        if (f == null) { println("  (no containing function for " + a + ")"); return; }
        if (!printedFuncs.add(f.getEntryPoint().toString())) return;
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        println("--- " + f.getEntryPoint() + " " + f.getName() + " ---");
        if (r.decompileCompleted() && r.getDecompiledFunction() != null) {
            println(r.getDecompiledFunction().getC());
        } else {
            println("(decompile incomplete)");
        }
    }

    void traceStringRefs(String label, long addr) throws Exception {
        println("\n=== xrefs to string @ " + Long.toHexString(addr) + " (" + label + ") ===");
        Address target = currentProgram.getAddressFactory().getAddress("0x" + Long.toHexString(addr));
        for (Reference ref : getReferencesTo(target)) {
            Function f = getFunctionContaining(ref.getFromAddress());
            println(ref.getFromAddress() + " in " + (f == null ? "???" : f.getEntryPoint() + " " + f.getName()));
            if (f != null) decompileFunctionAt(f.getEntryPoint());
        }
    }

    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);

        // 1. Standby/sleep related strings found earlier
        traceStringRefs("going to sleep.", 0x080c2784L);
        traceStringRefs("Device sleep", 0x080c2824L);
        traceStringRefs("CEC_SW Standby On Request", 0x080bf2b0L);
        traceStringRefs("CEC_SW Standby Off Request", 0x080bf2d4L);
        traceStringRefs("TX : Standby Mode", 0x080c4fd4L);

        // 2. RCC clock-gating registers (STM32F4): AHB1ENR=0x40023830, APB1ENR=0x40023840, APB2ENR=0x40023844
        println("\n=== Constant refs to RCC clock-enable registers ===");
        for (long regAddr : new long[]{0x40023830L, 0x40023840L, 0x40023844L, 0x40023800L}) {
            Address reg = currentProgram.getAddressFactory().getAddress("0x" + Long.toHexString(regAddr));
            int count = 0;
            for (Reference ref : getReferencesTo(reg)) {
                Function f = getFunctionContaining(ref.getFromAddress());
                println(Long.toHexString(regAddr) + " <- " + ref.getFromAddress() + " in " +
                    (f == null ? "???" : f.getEntryPoint() + " " + f.getName()));
                count++;
                if (count > 10) break;
            }
        }

        // 3. PWR_CR / PWR_CSR (STM32F4 PWR base 0x40007000)
        println("\n=== Constant refs to PWR_CR(0x40007000)/PWR_CSR(0x40007004) ===");
        for (long regAddr : new long[]{0x40007000L, 0x40007004L}) {
            Address reg = currentProgram.getAddressFactory().getAddress("0x" + Long.toHexString(regAddr));
            for (Reference ref : getReferencesTo(reg)) {
                Function f = getFunctionContaining(ref.getFromAddress());
                println(Long.toHexString(regAddr) + " <- " + ref.getFromAddress() + " in " +
                    (f == null ? "???" : f.getEntryPoint() + " " + f.getName()));
            }
        }

        // 4. Scan whole program for WFI instructions (opcode 0xBF30 Thumb) via instruction iterator
        println("\n=== WFI instruction occurrences ===");
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        int wfiCount = 0;
        while (it.hasNext() && wfiCount < 30) {
            Instruction insn = it.next();
            if (insn.getMnemonicString().equalsIgnoreCase("wfi") || insn.getMnemonicString().equalsIgnoreCase("wfe")) {
                Function f = getFunctionContaining(insn.getAddress());
                println(insn.getAddress() + " " + insn.toString() + " in " +
                    (f == null ? "???" : f.getEntryPoint() + " " + f.getName()));
                wfiCount++;
            }
        }
        println("total WFI/WFE found (capped 30): " + wfiCount);

        decompiler.dispose();
    }
}
