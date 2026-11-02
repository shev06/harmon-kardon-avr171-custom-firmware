import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.util.LinkedHashSet;
import java.util.Set;

public class AVRBootVectors extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Address base = currentProgram.getAddressFactory().getAddress("0x08000000");
        Set<String> targets = new LinkedHashSet<>();
        println("=== VECTOR TABLE ===");
        for (int i = 0; i < 64; i++) {
            long value = Integer.toUnsignedLong(
                currentProgram.getMemory().getInt(base.add((long)i * 4)));
            if (i == 0) {
                println("0\tinitial_sp\t0x" + Long.toHexString(value));
                continue;
            }
            if (value == 0) {
                println(i + "\treserved\t0");
                continue;
            }
            long codeAddress = value & ~1L;
            Address target = currentProgram.getAddressFactory().getAddress(
                String.format("0x%08x", codeAddress));
            Function function = getFunctionAt(target);
            if (function == null) {
                function = getFunctionContaining(target);
            }
            println(i + "\t0x" + Long.toHexString(value) + "\t" +
                (function == null ? "unresolved" :
                    function.getEntryPoint() + " " + function.getName()));
            if (i == 1 && function != null) {
                targets.add(function.getEntryPoint().toString());
            }
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (String value : targets) {
            Function function = getFunctionAt(
                currentProgram.getAddressFactory().getAddress(value));
            if (function == null) {
                continue;
            }
            DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
            println("\n=== RESET HANDLER " + function.getEntryPoint() + " ===");
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                println(result.getDecompiledFunction().getC());
            } else {
                println("Decompilation incomplete");
            }
        }
        decompiler.dispose();
    }
}
