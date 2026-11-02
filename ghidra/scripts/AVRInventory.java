import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AVRInventory extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== IMAGE ===");
        println("name\t" + currentProgram.getName());
        println("language\t" + currentProgram.getLanguageID());
        println("image_base\t" + currentProgram.getImageBase());
        println("memory_size\t" + currentProgram.getMemory().getSize());

        println("\n=== MEMORY BLOCKS ===");
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            println("block\t" + block.getName() + "\t" + block.getStart() + "\t" +
                block.getEnd() + "\t" + block.getSize() + "\t" +
                block.isInitialized() + "\t" + block.isExecute() + "\t" +
                block.isWrite());
        }

        Map<Long, Integer> functionCounts = new HashMap<>();
        List<Function> largest = new ArrayList<>();
        int functionCount = 0;
        long totalFunctionBytes = 0;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            functionCount++;
            totalFunctionBytes += function.getBody().getNumAddresses();
            long segment = function.getEntryPoint().getOffset() & 0xffff0000L;
            functionCounts.put(segment, functionCounts.getOrDefault(segment, 0) + 1);
            largest.add(function);
        }
        Collections.sort(largest, new Comparator<Function>() {
            @Override
            public int compare(Function left, Function right) {
                return Long.compare(right.getBody().getNumAddresses(),
                    left.getBody().getNumAddresses());
            }
        });
        println("\n=== FUNCTION SUMMARY ===");
        println("function_count\t" + functionCount);
        println("total_function_bytes\t" + totalFunctionBytes);
        List<Long> segments = new ArrayList<>(functionCounts.keySet());
        Collections.sort(segments);
        for (Long segment : segments) {
            println("functions_by_64k\t0x" + Long.toHexString(segment) +
                "\t" + functionCounts.get(segment));
        }
        println("largest_functions");
        for (int i = 0; i < Math.min(60, largest.size()); i++) {
            Function function = largest.get(i);
            println("largest\t" + function.getEntryPoint() + "\t" +
                function.getBody().getNumAddresses() + "\t" +
                function.getName().replace('\t', ' '));
        }

        println("\n=== STRING INVENTORY ===");
        int stringCount = 0;
        int referencedStringCount = 0;
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            Object value = data.getValue();
            if (!(value instanceof String)) {
                continue;
            }
            String text = ((String)value).replace("\r", " ").replace("\n", " ")
                .replace("\t", " ");
            if (text.trim().isEmpty()) {
                continue;
            }
            stringCount++;
            List<String> references = new ArrayList<>();
            for (Reference reference : getReferencesTo(data.getAddress())) {
                Function function = getFunctionContaining(reference.getFromAddress());
                references.add(reference.getFromAddress() + "<-" +
                    (function == null ? "?" : function.getEntryPoint().toString()));
            }
            if (!references.isEmpty()) {
                referencedStringCount++;
            }
            String safe = text.length() > 300 ? text.substring(0, 300) : text;
            println("string\t" + data.getAddress() + "\t" + data.getLength() +
                "\t" + references.size() + "\t" + safe);
            for (String reference : references) {
                println("string_ref\t" + reference);
            }
        }
        println("string_count\t" + stringCount);
        println("referenced_string_count\t" + referencedStringCount);

        println("\n=== FUNCTION CALL GRAPH ===");
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            List<String> calls = new ArrayList<>();
            for (Address address : function.getBody().getAddresses(true)) {
                Instruction instruction = getInstructionAt(address);
                if (instruction == null || !instruction.getFlowType().isCall()) {
                    continue;
                }
                for (Reference reference : getReferencesFrom(instruction.getAddress())) {
                    Function callee = getFunctionAt(reference.getToAddress());
                    if (callee != null) {
                        calls.add(callee.getEntryPoint().toString());
                    }
                }
            }
            Collections.sort(calls);
            println("calls\t" + function.getEntryPoint() + "\t" +
                function.getName().replace('\t', ' ') + "\t" +
                function.getBody().getNumAddresses() + "\t" +
                String.join(",", calls));
        }
    }
}
