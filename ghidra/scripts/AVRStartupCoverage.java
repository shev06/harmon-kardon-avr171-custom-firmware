import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AVRStartupCoverage extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        String[] selected = {
            "0x0800d36c", "0x0800d188", "0x08000184", "0x08000204",
            "0x08000100", "0x08000a74"
        };
        Set<String> seen = new HashSet<>();
        for (String value : selected) {
            Address address = currentProgram.getAddressFactory().getAddress(value);
            Function function = getFunctionAt(address);
            if (function == null) {
                function = getFunctionContaining(address);
            }
            if (function == null || !seen.add(function.getEntryPoint().toString())) {
                continue;
            }
            DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
            println("\n=== FUNCTION " + function.getEntryPoint() + " " +
                function.getName() + " ===");
            if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                println(result.getDecompiledFunction().getC());
            } else {
                println("Decompilation incomplete");
            }
            println("--- references to entry ---");
            for (Reference reference : getReferencesTo(function.getEntryPoint())) {
                println(reference.getFromAddress() + " " + reference.getReferenceType());
            }
        }

        System.out.println("=== CODE/DATA COVERAGE BY 64K ===");
        Address start = currentProgram.getMemory().getBlocks()[0].getStart();
        Address end = currentProgram.getMemory().getBlocks()[0].getEnd();
        AddressSet set = new AddressSet(start, end);
        long segment = start.getOffset() & 0xffff0000L;
        long codeBytes = 0;
        long dataBytes = 0;
        int instructions = 0;
        int dataUnits = 0;
        for (CodeUnit unit : currentProgram.getListing().getCodeUnits(set, true)) {
            long unitStart = unit.getMinAddress().getOffset();
            long unitEnd = unit.getMaxAddress().getOffset();
            long size = unit.getLength();
            long firstSegment = unitStart & 0xffff0000L;
            long lastSegment = unitEnd & 0xffff0000L;
            if (firstSegment != segment || lastSegment != segment) {
                println("coverage\t0x" + Long.toHexString(segment) + "\t" +
                    codeBytes + "\t" + dataBytes + "\t" + instructions + "\t" + dataUnits);
                segment = firstSegment;
                codeBytes = 0;
                dataBytes = 0;
                instructions = 0;
                dataUnits = 0;
            }
            if (unit instanceof Instruction) {
                codeBytes += size;
                instructions++;
            } else {
                dataBytes += size;
                dataUnits++;
            }
            if (lastSegment != segment) {
                println("coverage\t0x" + Long.toHexString(segment) + "\t" +
                    codeBytes + "\t" + dataBytes + "\t" + instructions + "\t" + dataUnits);
                segment = lastSegment;
                codeBytes = 0;
                dataBytes = 0;
                instructions = 0;
                dataUnits = 0;
            }
        }
        println("coverage\t0x" + Long.toHexString(segment) + "\t" +
            codeBytes + "\t" + dataBytes + "\t" + instructions + "\t" + dataUnits);

        List<String> uncalled = new ArrayList<>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            boolean called = false;
            for (Reference reference : getReferencesTo(function.getEntryPoint())) {
                if (reference.getReferenceType().isCall()) {
                    called = true;
                    break;
                }
            }
            if (!called) {
                uncalled.add(function.getEntryPoint() + "\t" +
                    function.getName() + "\t" + function.getBody().getNumAddresses());
            }
        }
        println("=== NO DIRECT CALL XREFS (NOT PROOF OF DEAD CODE) ===");
        for (String entry : uncalled) {
            println(entry);
        }
        decompiler.dispose();
    }
}
