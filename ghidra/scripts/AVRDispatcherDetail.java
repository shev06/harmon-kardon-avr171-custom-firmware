import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRDispatcherDetail extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Function dispatcher = getFunctionAt(
            currentProgram.getAddressFactory().getAddress("0x08049d90"));
        if (dispatcher == null) {
            println("Dispatcher function not found");
            return;
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults result = decompiler.decompileFunction(dispatcher, 60, monitor);
        println("=== DISPATCHER DECOMPILE ===");
        if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
            println(result.getDecompiledFunction().getC());
        } else {
            println("Decompilation incomplete");
        }

        println("=== STRINGS REFERENCED FROM DISPATCHER ===");
        Set<String> seen = new HashSet<>();
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            if (!(data.getValue() instanceof String)) {
                continue;
            }
            for (Reference reference : getReferencesTo(data.getAddress())) {
                if (dispatcher.getBody().contains(reference.getFromAddress())) {
                    String key = data.getAddress().toString();
                    if (seen.add(key)) {
                        println(data.getAddress() + "\t" +
                            ((String)data.getValue()).replace('\n', ' ').replace('\r', ' '));
                    }
                }
            }
        }

        println("=== DIRECT CALLS ===");
        Set<String> calls = new HashSet<>();
        for (Address address : dispatcher.getBody().getAddresses(true)) {
            Instruction instruction = getInstructionAt(address);
            if (instruction == null || !instruction.getFlowType().isCall()) {
                continue;
            }
            for (Reference reference : getReferencesFrom(address)) {
                Function callee = getFunctionAt(reference.getToAddress());
                if (callee != null) {
                    String key = callee.getEntryPoint().toString();
                    if (calls.add(key)) {
                        println(address + "\t" + callee.getEntryPoint() + "\t" +
                            callee.getName());
                    }
                }
            }
        }
        decompiler.dispose();
    }
}
