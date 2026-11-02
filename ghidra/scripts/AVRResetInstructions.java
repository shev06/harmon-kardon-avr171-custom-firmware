import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class AVRResetInstructions extends ghidra.app.script.GhidraScript {
    private void printRange(String startText, int count) throws Exception {
        Address address = currentProgram.getAddressFactory().getAddress(startText);
        println("\n=== instruction walk from " + address + " ===");
        for (int i = 0; i < count; i++) {
            Instruction instruction = getInstructionAt(address);
            if (instruction == null) {
                byte[] bytes = new byte[4];
                int read = currentProgram.getMemory().getBytes(address, bytes);
                StringBuilder hex = new StringBuilder();
                for (int j = 0; j < read; j++) {
                    if (j != 0) {
                        hex.append(' ');
                    }
                    hex.append(String.format("%02x", bytes[j] & 0xff));
                }
                println(address + "\tno instruction\t" + hex);
                address = address.add(2);
            } else {
                println(instruction.getAddress() + "\t" +
                    instruction.getBytes().length + "\t" + instruction);
                address = instruction.getMaxAddress().add(1);
            }
        }
    }

    @Override
    public void run() throws Exception {
        printRange("0x0800d170", 20);
        printRange("0x0800d36c", 40);
        printRange("0x0800d3a4", 32);
    }
}
