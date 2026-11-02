import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class AVRNetworkMap extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            if (!(data.getValue() instanceof String)) {
                continue;
            }
            String text = ((String) data.getValue()).replace("\n", " ").replace("\r", " ").trim();
            if (text.isEmpty() || text.length() > 80) {
                continue;
            }
            boolean usedByDispatcher = false;
            for (Reference reference : getReferencesTo(data.getAddress())) {
                Function function = getFunctionContaining(reference.getFromAddress());
                if (function != null && function.getEntryPoint().getOffset() == 0x08049d90L) {
                    usedByDispatcher = true;
                    break;
                }
            }
            if (!usedByDispatcher) {
                continue;
            }
            println("\n" + data.getAddress() + " \"" + text + "\"");
            for (Reference reference : getReferencesTo(data.getAddress())) {
                Function function = getFunctionContaining(reference.getFromAddress());
                if (function != null && function.getEntryPoint().getOffset() == 0x08049d90L) {
                    println("  <- " + reference.getFromAddress() + " " + function.getName());
                }
            }
        }
    }
}
