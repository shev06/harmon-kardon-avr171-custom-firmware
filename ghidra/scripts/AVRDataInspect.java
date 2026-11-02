import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class AVRDataInspect extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] addresses = {
            "0x0804a96c", "0x0804a970", "0x0804a984", "0x0804a994",
            "0x0804ad48", "0x0804ad4c", "0x0804ade4", "0x0804ade8",
            "0x0804a0cc", "0x0804a440", "0x0804a484", "0x0804aea0",
            "0x0804aea4", "0x0804aea8", "0x0804aeb4", "0x0804aebc",
            "0x0804aec0", "0x0804a5d8", "0x0804a5dc", "0x0804a5e0",
            "0x0804b034", "0x0804b040", "0x0804b044", "0x0804b050",
            "0x0804b054", "0x0804b058", "0x0804b05c", "0x0804b060",
            "0x0804b064", "0x0804b06c", "0x0804b078", "0x0804b07c",
            "0x0804b080", "0x0804b084", "0x0804b088", "0x0804b08c",
            "0x0804b094", "0x0804b098", "0x0804b0ac", "0x0804ad44",
            "0x0804b0b4", "0x0804b0b8", "0x0804b104", "0x0804b108",
            "0x0804b10c", "0x0804b110", "0x0804b114", "0x0804b118",
            "0x0804b11c", "0x0804b120", "0x0804b124", "0x0804b128",
            "0x0804b038", "0x0804b03c", "0x0804b048", "0x0804b04c",
            "0x0804b068", "0x0804b070", "0x0804b074"
        };
        for (String value : addresses) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Data data = getDataAt(address);
            Instruction instruction = getInstructionAt(address);
            String decoded = "undefined";
            if (data != null) {
                decoded = data.getValue() + " (" + data.getDataType() + ")";
            } else if (instruction != null) {
                decoded = instruction.toString();
            } else {
                decoded = "bytes=" + currentProgram.getMemory().getByte(address) + "," +
                    currentProgram.getMemory().getByte(address.add(1)) + "," +
                    currentProgram.getMemory().getByte(address.add(2)) + "," +
                    currentProgram.getMemory().getByte(address.add(3));
            }
            println("\n" + address + "\t" + decoded);
            for (Reference reference : getReferencesTo(address)) {
                println("  ref " + reference.getFromAddress() + " type=" +
                    reference.getReferenceType());
            }
        }
    }
}
