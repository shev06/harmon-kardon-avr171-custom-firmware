import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Explores the isolated low-region (< 0x08010000) bootloader-candidate code:
 * decompiles the reset handler, BFS-walks its call graph within the low
 * region, lists any defined strings in range, and dumps raw instruction
 * mnemonics near the end of each reached function (to catch computed
 * branches the decompiler/reference analysis may not resolve).
 */
public class AVRLowRegionTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        long boundary = 0x08010000L;
        Address resetAddr = currentProgram.getAddressFactory().getAddress("0x0800d36c");

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        println("=== Reset handler 0x0800d36c: raw disassembly ===");
        Function resetFn = getFunctionContaining(resetAddr);
        if (resetFn != null) {
            InstructionIterator insIt = currentProgram.getListing().getInstructions(resetFn.getBody(), true);
            while (insIt.hasNext()) {
                Instruction ins = insIt.next();
                println("  " + ins.getAddress() + ": " + ins);
            }
            println("\n=== Reset handler decompiled ===");
            DecompileResults r = decompiler.decompileFunction(resetFn, 60, monitor);
            println(r.decompileCompleted() && r.getDecompiledFunction() != null
                ? r.getDecompiledFunction().getC() : "incomplete: " + r.getErrorMessage());
        } else {
            println("  no function containing 0x0800d36c");
        }

        println("\n=== BFS call graph from reset handler (low region only) ===");
        Set<Address> visited = new LinkedHashSet<>();
        Deque<Function> queue = new ArrayDeque<>();
        if (resetFn != null) {
            queue.add(resetFn);
            visited.add(resetFn.getEntryPoint());
        }
        int count = 0;
        while (!queue.isEmpty() && count < 174) {
            Function f = queue.poll();
            count++;
            println(String.format("0x%08x %-20s size=%d", f.getEntryPoint().getOffset(),
                f.getName(), f.getBody().getNumAddresses()));
            InstructionIterator insIt = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (insIt.hasNext()) {
                Instruction ins = insIt.next();
                for (Reference ref : ins.getReferencesFrom()) {
                    Address to = ref.getToAddress();
                    if (to.getOffset() < boundary && !visited.contains(to)) {
                        Function callee = getFunctionContaining(to);
                        if (callee != null && !visited.contains(callee.getEntryPoint())) {
                            visited.add(callee.getEntryPoint());
                            queue.add(callee);
                        }
                    }
                }
            }
            if (monitor.isCancelled()) {
                break;
            }
        }
        println("Reached " + visited.size() + " of 174 low-region functions from reset handler.");

        println("\n=== Defined strings/data in low region (< 0x08010000) ===");
        DataIterator dataIt = currentProgram.getListing().getDefinedData(true);
        int shown = 0;
        while (dataIt.hasNext() && shown < 200) {
            Data d = dataIt.next();
            if (d.getAddress().getOffset() >= boundary) {
                break;
            }
            if (d.hasStringValue()) {
                println("  " + d.getAddress() + ": " + d.getDefaultValueRepresentation());
                shown++;
            }
        }
        println("Shown " + shown + " strings.");
        decompiler.dispose();
    }
}
