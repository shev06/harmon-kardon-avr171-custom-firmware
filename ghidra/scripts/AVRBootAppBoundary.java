import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.List;

/**
 * Tests whether 0x08010000 is a real bootloader/application boundary by
 * checking for cross-references in both directions, and lists the
 * low-region (candidate bootloader) functions.
 */
public class AVRBootAppBoundary extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        long boundary = 0x08010000L;

        List<Function> lowFunctions = new ArrayList<>();
        List<Function> highFunctions = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.getEntryPoint().getOffset() < boundary) {
                lowFunctions.add(f);
            } else {
                highFunctions.add(f);
            }
        }
        println("Low-region functions (< 0x08010000): " + lowFunctions.size());
        println("High-region functions (>= 0x08010000): " + highFunctions.size());

        println("\n--- LOW functions (entry, name, byte size) ---");
        for (Function f : lowFunctions) {
            println(String.format("0x%08x %-24s size=%d",
                f.getEntryPoint().getOffset(), f.getName(),
                f.getBody().getNumAddresses()));
        }

        long imageEnd = 0x08600000L;
        println("\n--- LOW -> HIGH references (low-region CODE referencing flash >= 0x08010000, " +
            "RAM/peripheral targets excluded) ---");
        int crossLowToHigh = 0;
        for (Function f : lowFunctions) {
            InstructionIterator insIt = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (insIt.hasNext()) {
                Instruction ins = insIt.next();
                for (Reference ref : ins.getReferencesFrom()) {
                    long target = ref.getToAddress().getOffset();
                    if (target >= boundary && target < imageEnd) {
                        println("  " + f.getEntryPoint() + " " + f.getName() +
                            " @ " + ins.getAddress() + " -> " + ref.getToAddress() +
                            " (" + ref.getReferenceType() + ")");
                        crossLowToHigh++;
                    }
                }
            }
            if (monitor.isCancelled()) {
                break;
            }
        }
        println("Total LOW -> HIGH flash-code references: " + crossLowToHigh);

        println("\n--- HIGH -> LOW references (high-region code referencing < 0x08010000) ---");
        int crossHighToLow = 0;
        int printed = 0;
        for (Function f : highFunctions) {
            InstructionIterator insIt = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (insIt.hasNext()) {
                Instruction ins = insIt.next();
                for (Reference ref : ins.getReferencesFrom()) {
                    long target = ref.getToAddress().getOffset();
                    if (target < boundary && target >= 0x08000000L) {
                        crossHighToLow++;
                        if (printed < 200) {
                            println("  " + f.getEntryPoint() + " " + f.getName() +
                                " @ " + ins.getAddress() + " -> " + ref.getToAddress());
                            printed++;
                        }
                    }
                }
            }
            if (monitor.isCancelled()) {
                break;
            }
        }
        println("Total HIGH -> LOW references: " + crossHighToLow +
            " (printed first " + printed + ")");
    }
}
