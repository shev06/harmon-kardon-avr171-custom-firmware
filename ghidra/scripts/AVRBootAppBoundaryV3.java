import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;

/**
 * Complete LOW<->HIGH cross-reference check using raw instruction iteration
 * (not limited to pre-existing Function boundaries, since large portions of
 * the low region are disassembled but not grouped into Functions).
 */
public class AVRBootAppBoundaryV3 extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        long boundary = 0x08010000L;
        long imageEnd = 0x08600000L;
        Address lowStart = currentProgram.getAddressFactory().getAddress("0x08000000");
        Address lowEnd = currentProgram.getAddressFactory().getAddress("0x0800ffff");
        Address highStart = currentProgram.getAddressFactory().getAddress(String.format("0x%08x", boundary));
        Address highEnd = currentProgram.getAddressFactory().getAddress("0x080cffff");

        println("=== LOW -> HIGH (raw instructions 0x08000000-0x0800ffff -> flash >= 0x08010000) ===");
        int crossLowToHigh = 0;
        InstructionIterator lowIt = currentProgram.getListing().getInstructions(
            new AddressSet(lowStart, lowEnd), true);
        while (lowIt.hasNext()) {
            Instruction ins = lowIt.next();
            for (Reference ref : ins.getReferencesFrom()) {
                long target = ref.getToAddress().getOffset();
                if (target >= boundary && target < imageEnd) {
                    println("  " + ins.getAddress() + ": " + ins + "  -> " + ref.getToAddress() +
                        " (" + ref.getReferenceType() + ")");
                    crossLowToHigh++;
                }
            }
            if (monitor.isCancelled()) {
                break;
            }
        }
        println("Total LOW -> HIGH: " + crossLowToHigh);

        println("\n=== HIGH -> LOW (raw instructions 0x08010000-0x0809ffff -> flash < 0x08010000) ===");
        int crossHighToLow = 0;
        int printed = 0;
        InstructionIterator highIt = currentProgram.getListing().getInstructions(
            new AddressSet(highStart, highEnd), true);
        while (highIt.hasNext()) {
            Instruction ins = highIt.next();
            for (Reference ref : ins.getReferencesFrom()) {
                long target = ref.getToAddress().getOffset();
                if (target < boundary && target >= 0x08000000L) {
                    crossHighToLow++;
                    if (printed < 100) {
                        Function fn = getFunctionContaining(ins.getAddress());
                        println("  " + ins.getAddress() + " (" +
                            (fn == null ? "no fn" : fn.getName()) + "): " + ins + "  -> " +
                            ref.getToAddress());
                        printed++;
                    }
                }
            }
            if (monitor.isCancelled()) {
                break;
            }
        }
        println("Total HIGH -> LOW: " + crossHighToLow + " (printed " + printed + ")");
    }
}
