import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class AVRNetworkDataXrefs extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] addresses = {
            "0x08048880", "0x08045a14", "0x080480a4", "0x080480cc",
            "0x08062d50", "0x08062d54", "0x2001afe4", "0x20017034",
            "0x2001b2dc", "0x2001ad94", "0x0804887c", "0x080488f0",
            "0x080488f4", "0x080488f8", "0x08048964"
        };
        for (String value : addresses) {
            var address = currentProgram.getAddressFactory().getAddress(value);
            Data data = getDataAt(address);
            println("\n=== " + address + " ===");
            if (data != null) {
                println("Data: " + data.getDataType() + " = " + data.getValue());
            }
            for (Reference reference : getReferencesTo(address)) {
                Function function = getFunctionContaining(reference.getFromAddress());
                println(reference.getFromAddress() + " " +
                    (function == null ? "no function" :
                        function.getEntryPoint() + " " + function.getName()) +
                    " type=" + reference.getReferenceType());
            }
        }
    }
}
