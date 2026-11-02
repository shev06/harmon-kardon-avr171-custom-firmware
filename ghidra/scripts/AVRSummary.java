// Ghidra headless post-analysis export for the AVR1710 raw firmware image.
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import java.util.HashSet;
import java.util.Set;

public class AVRSummary extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] offsets = {"0x0800d36c", "0x0800cf3e", "0x080c6f2c",
                            "0x0808bb98", "0x080c7578", "0x080c2078",
                            "0x08048610", "0x0805160c", "0x08051efc",
                            "0x08070f68", "0x08008000", "0x0800d188"};
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (String value : offsets) {
            Address entry = currentProgram.getAddressFactory().getAddress(value);
            if (entry == null) {
                println("No address: " + value);
                continue;
            }
            disassemble(entry);
            Function function = getFunctionAt(entry);
            if (function == null) {
                function = createFunction(entry, null);
            }
            println("\n=== Entry " + entry + " function=" +
                (function == null ? "unresolved" : function.getName()) + " ===");
            Instruction instruction = getInstructionAt(entry);
            for (int i = 0; instruction != null && i < 80; i++) {
                println(instruction.getAddress() + "  " + instruction);
                if (instruction.getFlowType().isTerminal() ||
                    instruction.getFlowType().isJump()) {
                    break;
                }
                instruction = getInstructionAfter(instruction);
            }
            if (function != null) {
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    println("--- decompiled " + function.getName() + " ---");
                    println(result.getDecompiledFunction().getC().substring(
                        0, Math.min(2200, result.getDecompiledFunction().getC().length())));
                }
            }
        }

        println("\n=== Referenced update-related strings ===");
        Set<String> printed = new HashSet<>();
        int stringsShown = 0;
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            Object value = data.getValue();
            if (value == null) {
                continue;
            }
            String text = value.toString().replace("\n", " ").replace("\r", " ");
            if (!text.matches(".*(?i)(FIRMWAREDOWNLOAD|SOFTWARE UPGRADE|USB SOFTWARE|DSP\\s+UPDATE|MCU\\s+UPDATE|OSD\\s+UPDATE|BCO\\s+UPDATE|MCU VERSION|DSP VERSION|MCU IAP VERSION|SYSTEM UPDATE|USB DETECT).*") ||
                text.length() > 100) {
                continue;
            }
            for (Reference reference : getReferencesTo(data.getAddress())) {
                Function caller = getFunctionContaining(reference.getFromAddress());
                if (caller == null) {
                    continue;
                }
                String key = data.getAddress() + "|" + caller.getEntryPoint();
                if (printed.add(key)) {
                    println(data.getAddress() + " \"" + text.trim() + "\" <- " +
                        caller.getEntryPoint() + " " + caller.getName());
                    stringsShown++;
                    if (stringsShown >= 100) {
                        break;
                    }
                }
            }
            if (stringsShown >= 100) {
                break;
            }
        }
        println("\n=== Selected display-label references ===");
        String[] labelAddresses = {"0x080c34a4", "0x080c1340",
            "0x0800d158", "0x0800d1c8", "0x0800d1dc", "0x0800d1f0",
            "0x0800d254", "0x0800d27c", "0x0800d290", "0x0800d2b8",
            "0x0800d318", "0x0800d33c", "0x080c1a60", "0x080c7548",
            "0x080c7554", "0x080c7560", "0x080c27ac", "0x080c27fc",
            "0x080c28c4", "0x080c2b94", "0x080c3fe4"};
        for (String value : labelAddresses) {
            Address labelAddress = currentProgram.getAddressFactory().getAddress(value);
            Data label = getDataAt(labelAddress);
            println(value + " data=" + (label == null ? "undefined" : label.getValue()) +
                " length=" + (label == null ? "unknown" : label.getLength()));
            if (label == null) {
                continue;
            }
            for (Reference reference : getReferencesTo(labelAddress)) {
                Function caller = getFunctionContaining(reference.getFromAddress());
                println("  ref=" + reference.getFromAddress() + " function=" +
                    (caller == null ? "unresolved" : caller.getEntryPoint() + " " + caller.getName()));
                if (caller != null) {
                    DecompileResults result = decompiler.decompileFunction(caller, 20, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        String code = result.getDecompiledFunction().getC();
                        println(code.substring(0, Math.min(1400, code.length())));
                    }
                }
            }
        }
        decompiler.dispose();

        println("\n=== Function inventory by populated firmware region ===");
        long[] starts = {0x08000000L, 0x08010000L, 0x08100000L, 0x08110000L,
                         0x08148f0cL, 0x08500000L};
        long[] ends = {0x0800d514L, 0x080c89b4L, 0x08103b74L, 0x08148e0cL,
                       0x08337f18L, 0x08510cbaL};
        for (int r = 0; r < starts.length; r++) {
            int count = 0;
            println("Region " + Long.toHexString(starts[r]) + "-" +
                Long.toHexString(ends[r]));
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                long offset = f.getEntryPoint().getOffset();
                if (offset >= starts[r] && offset < ends[r] && count < 40) {
                    println("  " + f.getEntryPoint() + " " + f.getName() +
                        " size=" + f.getBody().getNumAddresses());
                    count++;
                }
            }
            println("  displayed=" + count);
        }
    }
}
