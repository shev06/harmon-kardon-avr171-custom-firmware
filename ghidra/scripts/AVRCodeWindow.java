import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class AVRCodeWindow extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getAddress("0x0804ad80");
        Address end = currentProgram.getAddressFactory().getAddress("0x0804b050");
        for (Instruction instruction : currentProgram.getListing()
                .getInstructions(start, true)) {
            if (instruction.getAddress().compareTo(end) > 0) {
                break;
            }
            StringBuilder refs = new StringBuilder();
            for (Reference reference : getReferencesFrom(instruction.getAddress())) {
                refs.append(" -> ").append(reference.getToAddress());
            }
            println(instruction.getAddress() + "\t" + instruction + refs);
        }
    }
}
