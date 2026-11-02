import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class AVRFlagPointers extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] entries = {
            "0x08023d54", "0x08023d58", "0x08023d5c", "0x08023a38",
            "0x08023a3c", "0x08023724", "0x0804b090",
            "0x08024f84", "0x080260f8"
        };
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Data data = getDataAt(address);
            println("\n=== " + address + " value=" +
                (data == null ? "undefined" : data.getValue()) + " ===");
            for (Reference reference : getReferencesTo(address)) {
                Function function = getFunctionContaining(reference.getFromAddress());
                println(reference.getFromAddress() + "\t" +
                    reference.getReferenceType() + "\t" +
                    (function == null ? "no function" :
                        function.getEntryPoint() + " " + function.getName()));
            }
            if (data != null && data.getValue() instanceof Address) {
                Address target = (Address)data.getValue();
                println("target " + target);
                for (Reference reference : getReferencesTo(target)) {
                    Function function = getFunctionContaining(reference.getFromAddress());
                    println("target-ref " + reference.getFromAddress() + "\t" +
                        reference.getReferenceType() + "\t" +
                        (function == null ? "no function" :
                            function.getEntryPoint() + " " + function.getName()));
                }
            }
        }
    }
}
