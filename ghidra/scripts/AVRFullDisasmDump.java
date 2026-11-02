import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class AVRFullDisasmDump extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getAddress("0x08044dc4");
        Address end = currentProgram.getAddressFactory().getAddress("0x08044ed5");
        Instruction insn = getInstructionAt(start);
        while (insn != null && insn.getAddress().compareTo(end) <= 0) {
            byte[] bytes = insn.getBytes();
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) hex.append(String.format("%02x", b));
            println(insn.getAddress() + "|" + hex + "|" + insn.toString());
            insn = insn.getNext();
        }
    }
}
