import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class AVRStartupDisasm extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[][] ranges = {
            {"0x0800d188", "0x0800d1d0"},
            {"0x08008180", "0x080082c0"},
            {"0x080054c0", "0x08005550"}
        };
        for (String[] range : ranges) {
            Address start = currentProgram.getAddressFactory().getAddress(range[0]);
            Address end = currentProgram.getAddressFactory().getAddress(range[1]);
            println("\n=== " + start + "-" + end + " ===");
            disassemble(start);
            for (Instruction instruction : currentProgram.getListing()
                    .getInstructions(start, true)) {
                if (instruction.getAddress().compareTo(end) > 0) {
                    break;
                }
                println(instruction.getAddress() + " " + instruction);
            }
        }
    }
}
