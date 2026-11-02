import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class AVRBusOpcodeRefs extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
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
                println(instruction.getAddress() + " " + instruction + " in " +
                    (function == null ? "unresolved" :
                        function.getEntryPoint() + " " + function.getName()));
                if (++count >= 200) {
                    println("Stopped at 200 matching instructions");
                    break;
                }
            }
        }
    }
}
