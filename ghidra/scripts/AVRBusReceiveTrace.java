import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRBusReceiveTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] entries = {
            "0x08062a5c", "0x08062adc", "0x08062b20", "0x08062ba0",
            "0x08047944", "0x0804783c", "0x0806e84c",
            "0x080925bc", "0x080928e0", "0x08092e60", "0x08092a38"
        };
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<String> printed = new HashSet<>();
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionAt(address);
            if (function == null) {
                println("Unresolved function: " + value);
                continue;
            }
            if (printed.add(function.getEntryPoint().toString())) {
                DecompileResults result = decompiler.decompileFunction(function, 45, monitor);
                println("\n=== " + function.getEntryPoint() + " " +
                    function.getName() + " ===");
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    println(result.getDecompiledFunction().getC());
                } else {
                    println("Decompilation incomplete");
                }
            }
            println("--- callers of " + function.getEntryPoint() + " ---");
            for (Reference reference : getReferencesTo(function.getEntryPoint())) {
                Function caller = getFunctionContaining(reference.getFromAddress());
                if (caller != null) {
                    println(reference.getFromAddress() + " <- " +
                        caller.getEntryPoint() + " " + caller.getName());
                }
            }
        }
        println("=== INSTRUCTIONS WITH IMMEDIATE 0x79 ===");
        int count = 0;
        for (Instruction instruction : currentProgram.getListing().getInstructions(true)) {
            boolean match = false;
            for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                for (Object object : instruction.getOpObjects(operand)) {
                    if (object instanceof Scalar &&
                            ((Scalar)object).getUnsignedValue() == 0x79) {
                        match = true;
                        break;
                    }
                }
                if (match) {
                    break;
                }
            }
            if (match) {
                Function function = getFunctionContaining(instruction.getAddress());
                println(instruction.getAddress() + "\t" + instruction + "\t" +
                    (function == null ? "unresolved" :
                        function.getEntryPoint() + " " + function.getName()));
                if (++count >= 300) {
                    println("Stopped at 300 matches");
                    break;
                }
            }
        }
        decompiler.dispose();
    }
}
