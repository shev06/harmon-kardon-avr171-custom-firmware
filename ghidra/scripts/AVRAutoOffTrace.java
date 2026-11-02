import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

// Trace the "AUTO OFF" menu setting (string table at file offset ~0xc4006,
// flash address ~0x080c4006: OFF/1HOUR/2HOURS.../8HOURS) to find:
//   1. What RAM cell stores the user's actual selected AUTO OFF value (0-8)
//   2. What reads/consumes DAT_08019c70 (RAM 0x2001bfd8, the cell our "safe"
//      branch hardcodes to 0xe10=3600=1 hour) -- does it respect the user's
//      actual AUTO OFF selection, or is 3600 unconditional regardless of
//      what the user has configured (including "OFF")?
public class AVRAutoOffTrace extends ghidra.app.script.GhidraScript {

    void findReaders(String label, long ramTarget, boolean writesOnly) {
        println("\n=== " + (writesOnly ? "Writers" : "Readers/Writers") + " of " + label + " (RAM 0x" + Long.toHexString(ramTarget) + ") ===");
        Address target = toAddr(ramTarget);
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        int count = 0;
        while (it.hasNext()) {
            Instruction insn = it.next();
            String mnem = insn.getMnemonicString();
            boolean isStore = mnem.toUpperCase().startsWith("STR");
            boolean isLoad = mnem.toUpperCase().startsWith("LDR");
            if (!isStore && !isLoad) continue;
            if (writesOnly && !isStore) continue;
            boolean hit = false;
            for (ghidra.program.model.symbol.Reference ref : insn.getReferencesFrom()) {
                if (ref.getToAddress() != null && ref.getToAddress().equals(target)) hit = true;
            }
            if (hit) {
                count++;
                Function fn = getFunctionContaining(insn.getAddress());
                println("  " + insn.getAddress() + " [" + mnem + "] " + insn + "   in " + (fn != null ? fn.getName() : "null"));
            }
        }
        println("total: " + count);
    }

    @Override
    public void run() throws Exception {
        // Locate references to the "AUTO OFF" string table to find the menu render/select function.
        long stringsBase = 0x080c4006L; // approx start of "AUTO OFF:       " header string
        println("=== References to AUTO OFF string table region (0x080c4006 - 0x080c4100) ===");
        for (long a = 0x080c4006L; a < 0x080c4100L; a += 2) {
            Address addr = toAddr(a);
            for (Reference ref : getReferencesTo(addr)) {
                Function fn = getFunctionContaining(ref.getFromAddress());
                println("  string@" + addr + " <- ref from " + ref.getFromAddress() + " in " + (fn != null ? fn.getName() + "@" + fn.getEntryPoint() : "null"));
            }
        }

        findReaders("DAT_08019c70 (0x2001bfd8, the 3600/1hr cell)", 0x2001bfd8L, false);

        println("\nDONE");
    }
}
