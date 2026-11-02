import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class AVRNetTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] dataAddresses = {
            "0x080457f4", "0x080457f8", "0x080457fc", "0x08045800",
            "0x08045804", "0x08045808", "0x0804580c", "0x08045818",
            "0x0804581c", "0x08045a14", "0x0804b064", "0x0804b06c",
            "0x0804b078", "0x0804b07c", "0x0804b080", "0x0804b084",
            "0x0804b100", "0x0804b104", "0x0804b108", "0x0804b10c",
            "0x0804b110", "0x0804b114", "0x0804b118"
        };
        for (String value : dataAddresses) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Data data = getDataAt(address);
            println("\nDATA " + value + " = " +
                (data == null ? "undefined" : data.getValue()));
            if (data != null && data.getValue() != null) {
                Address target = currentProgram.getAddressFactory().getAddress(
                    data.getValue().toString());
                Data pointedData = target == null ? null : getDataAt(target);
                if (pointedData != null) {
                    println("  points to " + target + " data=" + pointedData.getValue());
                }
            }
            for (Reference reference : getReferencesFrom(address)) {
                Data target = getDataAt(reference.getToAddress());
                println("  -> " + reference.getToAddress() + " data=" +
                    (target == null ? "undefined" : target.getValue()));
            }
        }

        String[][] ranges = {
            {"0x08049e20", "0x08049e80"},
            {"0x0804a530", "0x0804a6d0"},
            {"0x0804ad80", "0x0804af40"},
            {"0x0804b000", "0x0804b050"}
        };
        for (String[] range : ranges) {
            Address cursor = currentProgram.getAddressFactory().getAddress(range[0]);
            Address end = currentProgram.getAddressFactory().getAddress(range[1]);
            println("\n=== Instructions " + range[0] + "-" + range[1] + " ===");
            while (cursor != null && cursor.compareTo(end) < 0) {
                Instruction instruction = getInstructionAt(cursor);
                if (instruction == null) {
                    println(cursor + " <no instruction>");
                    cursor = cursor.add(2);
                    continue;
                }
                println(instruction.getAddress() + " " + instruction);
                cursor = instruction.getAddress().add(instruction.getLength());
            }
        }
    }
}
