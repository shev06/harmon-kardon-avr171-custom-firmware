import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class AVREmbeddedImageTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Address table = currentProgram.getAddressFactory().getAddress("0x08010000");
        println("=== candidate vector table " + table + " ===");
        for (int index = 0; index < 24; index++) {
            long value = Integer.toUnsignedLong(getInt(table.add(index * 4)));
            println(String.format("vector[%02d] = 0x%08x", index, value));
        }
        println("\n=== references to candidate table ===");
        for (Reference reference : getReferencesTo(table)) {
            Function function = getFunctionContaining(reference.getFromAddress());
            println(reference.getFromAddress() + " <- " +
                (function == null ? "no function" :
                    function.getEntryPoint() + " " + function.getName()));
        }
        long[] entries = {0x080c6f2cL, 0x080b97c8L, 0x080b97caL};
        for (long offset : entries) {
            Address address = currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(offset);
            println("\n=== handler 0x" + Long.toHexString(offset) + " ===");
            disassemble(address);
            Function function = getFunctionContaining(address);
            println("function: " + (function == null ? "none" :
                function.getEntryPoint() + " " + function.getName()));
            Instruction instruction = getInstructionAt(address);
            for (int count = 0; instruction != null && count < 20; count++) {
                println(instruction.getAddress() + " " + instruction);
                instruction = instruction.getNext();
            }
        }
    }
}
