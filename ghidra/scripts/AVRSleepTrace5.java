import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.mem.Memory;

public class AVRSleepTrace5 extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();

        // Resolve the pointer literal stored at 0x080116e8 (DAT_080116e8) -> RAM address of the counter
        Address litAddr = currentProgram.getAddressFactory().getAddress("0x080116e8");
        int ramPtr = mem.getInt(litAddr);
        println("DAT_080116e8 literal holds RAM pointer: 0x" + Integer.toHexString(ramPtr));
        Address ramAddr = currentProgram.getAddressFactory().getAddress(Integer.toHexString(ramPtr));

        println("\n=== All instructions referencing RAM addr " + ramAddr + " (the countdown counter) ===");
        for (Reference ref : getReferencesTo(ramAddr)) {
            Address from = ref.getFromAddress();
            Function cf = getFunctionContaining(from);
            Instruction insn = getInstructionAt(from);
            println(from + " [" + (insn == null ? "?" : insn.toString()) + "] in " +
                (cf == null ? "???" : cf.getEntryPoint() + " " + cf.getName()));
        }

        // Also try scanning a window of instructions around each reference for immediate MOV values
        // (to catch "mov r3,#N ; str r3,[rX]" patterns setting the countdown)
        println("\n=== Context: 6 instructions before/after each write site ===");
        for (Reference ref : getReferencesTo(ramAddr)) {
            Address from = ref.getFromAddress();
            Instruction center = getInstructionAt(from);
            if (center == null) continue;
            println("--- around " + from + " ---");
            Instruction cur = center;
            for (int i = 0; i < 6 && cur != null; i++) cur = cur.getPrevious();
            Instruction start = (cur != null) ? cur : center;
            Instruction walk = start;
            int count = 0;
            while (walk != null && count < 14) {
                println("  " + walk.getAddress() + ": " + walk.toString());
                if (walk.getAddress().equals(from)) {
                    // print a couple more after
                }
                walk = walk.getNext();
                count++;
            }
        }
        println("\n=== Function containing FUN_0801074c's caller (tick-rate context) ===");
        Address a = currentProgram.getAddressFactory().getAddress("0x0801074c");
        for (Reference ref : getReferencesTo(a)) {
            Function cf = getFunctionContaining(ref.getFromAddress());
            println(ref.getFromAddress() + " in " + (cf == null ? "???" : cf.getEntryPoint() + " " + cf.getName()));
        }
    }
}
