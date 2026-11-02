import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class AVRStatusStateRefs extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] entries = {
            "0x0805561c", "0x0805584c", "0x08055cc8", "0x08055ccc",
            "0x08055cec", "0x08055cf0", "0x08055646", "0x080556be",
            "0x080585d8", "0x080583b8", "0x080583dc", "0x080585e0"
        };
        Set<String> printed = new HashSet<>();
        for (String value : entries) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Data data = getDataAt(address);
            println("\n=== " + address + " value=" +
                (data == null ? "undefined" : data.getValue()) + " ===");
            if (data != null && data.getValue() instanceof Address) {
                Address target = (Address)data.getValue();
                println("pointer target " + target);
                for (Reference reference : getReferencesTo(target)) {
                    Function function = getFunctionContaining(reference.getFromAddress());
                    if (function != null && printed.add(function.getEntryPoint().toString())) {
                        println("target ref " + reference.getFromAddress() + " <- " +
                            function.getEntryPoint() + " " + function.getName());
                    }
                }
            }
            for (Reference reference : getReferencesTo(address)) {
                Function function = getFunctionContaining(reference.getFromAddress());
                if (function != null && printed.add(function.getEntryPoint().toString())) {
                    println("literal ref " + reference.getFromAddress() + " <- " +
                        function.getEntryPoint() + " " + function.getName());
                }
            }
        }
    }
}
