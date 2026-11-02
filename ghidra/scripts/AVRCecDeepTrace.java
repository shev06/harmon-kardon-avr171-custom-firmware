import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

// Deep dive on the CEC TX-queue handler functions (siblings of the already-known
// report-power-status/report-audio-status functions) plus the key named CEC
// operations (System Audio Mode, Vendor ID, OSD name, Physical Address, Standby)
// to look for the same "computed value silently dropped" bug pattern already
// found and fixed in the XML query-status dispatcher.
public class AVRCecDeepTrace extends ghidra.app.script.GhidraScript {
    DecompInterface decompiler = new DecompInterface();

    void decompileAt(String label, String addrStr) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(addrStr);
        Function f = getFunctionContaining(a);
        println("\n=== " + label + " (" + addrStr + ") ===");
        if (f == null) { println("[no function]"); return; }
        println("function: " + f.getEntryPoint() + " body ends " + f.getBody().getMaxAddress());
        DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
        if (r.decompileCompleted()) println(r.getDecompiledFunction().getC());
        else println("[decompile failed: " + r.getErrorMessage() + "]");
    }

    void findStringAndDecompileCallers(String text) throws Exception {
        println("\n######## STRING: " + text + " ########");
        for (Data d : currentProgram.getListing().getDefinedData(true)) {
            Object val = d.getValue();
            if (val != null && val.toString().contains(text)) {
                Address strAddr = d.getAddress();
                println("found at " + strAddr);
                for (Reference ref : getReferencesTo(strAddr)) {
                    Function caller = getFunctionContaining(ref.getFromAddress());
                    if (caller != null) {
                        decompileAt(text, caller.getEntryPoint().toString());
                    }
                }
                return;
            }
        }
        println("[string not found as defined data]");
    }

    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);

        // Siblings of FUN_0804b304/FUN_0804b56e in the CEC TX dispatcher's bit-drain loop
        String[] handlers = {
            "0x0804b91a", "0x0804b28c", "0x0804b400", "0x0804b452",
            "0x0804b948", "0x0804b2c2", "0x0804b4b2", "0x0804b5ba",
            "0x0804b61a", "0x0804b8a0", "0x0804b75e", "0x0804b7b6",
            "0x0804b6a4", "0x0804b3bc", "0x0804b352", "0x0804b536",
            "0x0804b506", "0x0804b8e8"
        };
        for (String h : handlers) {
            decompileAt("CEC dispatcher handler", h);
        }

        // Named operations via string search
        findStringAndDecompileCallers("CECSendSetSystemAudioModeBroadcast");
        findStringAndDecompileCallers("CECSendSetSystemAudioModeDirectly");
        findStringAndDecompileCallers("Sending Vendor ID");
        findStringAndDecompileCallers("Sending Set OSD name");
        findStringAndDecompileCallers("CEC PA is defaulted");
        findStringAndDecompileCallers("Standby mode On Request");
        findStringAndDecompileCallers("Standby mode Off Request");
        findStringAndDecompileCallers("already in  Standby mode");
        findStringAndDecompileCallers("CEC_VERSION 1.4");

        decompiler.dispose();
    }
}
