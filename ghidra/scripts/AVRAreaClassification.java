import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import java.util.HashMap;
import java.util.Map;

public class AVRAreaClassification extends ghidra.app.script.GhidraScript {
    private static long bucket(Address address) {
        return address.getOffset() & 0xffff0000L;
    }

    @Override
    public void run() throws Exception {
        Map<Long, Long> instructionBytes = new HashMap<>();
        Map<Long, Long> dataBytes = new HashMap<>();
        Map<Long, Integer> instructionCounts = new HashMap<>();
        Map<Long, Integer> dataCounts = new HashMap<>();
        Map<Long, Integer> functionCounts = new HashMap<>();
        Map<Long, Long> functionBytes = new HashMap<>();
        AddressSet allMemory = new AddressSet();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            println("block\t" + block.getName() + "\t" + block.getStart() +
                "\t" + block.getEnd() + "\t" + block.getSize());
            allMemory.addRange(block.getStart(), block.getEnd());
        }
        for (Instruction instruction : currentProgram.getListing().getInstructions(allMemory, true)) {
            long key = bucket(instruction.getMinAddress());
            instructionBytes.put(key, instructionBytes.getOrDefault(key, 0L) +
                instruction.getLength());
            instructionCounts.put(key, instructionCounts.getOrDefault(key, 0) + 1);
        }
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            if (!allMemory.contains(data.getAddress())) {
                continue;
            }
            long key = bucket(data.getMinAddress());
            dataBytes.put(key, dataBytes.getOrDefault(key, 0L) + data.getLength());
            dataCounts.put(key, dataCounts.getOrDefault(key, 0) + 1);
        }
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            long key = bucket(function.getEntryPoint());
            functionCounts.put(key, functionCounts.getOrDefault(key, 0) + 1);
            functionBytes.put(key, functionBytes.getOrDefault(key, 0L) +
                function.getBody().getNumAddresses());
        }
        println("area\tstart\tbytes\tinstructions\tdefined_data_bytes\tdefined_data_units\tfunctions\tfunction_body_bytes\tunclassified_estimate");
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            long first = bucket(block.getStart());
            long last = bucket(block.getEnd());
            for (long key = first; key <= last; key += 0x10000) {
                long segmentStart = Math.max(key, block.getStart().getOffset());
                long segmentEnd = Math.min(key + 0xffff, block.getEnd().getOffset());
                long size = segmentEnd - segmentStart + 1;
                long code = instructionBytes.getOrDefault(key, 0L);
                long data = dataBytes.getOrDefault(key, 0L);
                long undefinedEstimate = Math.max(0, size - code - data);
                byte[] raw = new byte[(int)size];
                currentProgram.getMemory().getBytes(
                    currentProgram.getAddressFactory().getAddress(
                        String.format("0x%08x", segmentStart)), raw);
                long zeroBytes = 0;
                long erasedBytes = 0;
                for (byte value : raw) {
                    if (value == 0) {
                        zeroBytes++;
                    } else if ((value & 0xff) == 0xff) {
                        erasedBytes++;
                    }
                }
                println("area\t0x" + Long.toHexString(key) + "\t" + size +
                    "\t" + instructionCounts.getOrDefault(key, 0) +
                    "\t" + data + "\t" + dataCounts.getOrDefault(key, 0) +
                    "\t" + functionCounts.getOrDefault(key, 0) +
                    "\t" + functionBytes.getOrDefault(key, 0L) +
                    "\t" + undefinedEstimate);
                println("byte_mix\t0x" + Long.toHexString(key) + "\t" +
                    zeroBytes + "\t" + erasedBytes + "\t" +
                    (size - zeroBytes - erasedBytes));
            }
        }
    }
}
