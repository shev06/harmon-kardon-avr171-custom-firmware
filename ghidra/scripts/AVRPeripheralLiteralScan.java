import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class AVRPeripheralLiteralScan extends ghidra.app.script.GhidraScript {
    private long le32(byte[] bytes, int offset) {
        return ((long) bytes[offset] & 0xff) |
            (((long) bytes[offset + 1] & 0xff) << 8) |
            (((long) bytes[offset + 2] & 0xff) << 16) |
            (((long) bytes[offset + 3] & 0xff) << 24);
    }

    @Override
    public void run() throws Exception {
        long[] targets = {
            0x40023c00L, 0x40023c04L, 0x40023c08L, 0x40023c0cL,
            0x40023c10L, 0x40023000L, 0x50000000L, 0x40040000L
        };
        MemoryBlock block = currentProgram.getMemory().getBlock("firmware");
        byte[] image = new byte[(int) block.getSize()];
        currentProgram.getMemory().getBytes(block.getStart(), image);
        for (long target : targets) {
            println(String.format("\n=== literal 0x%08x ===", target));
            int matches = 0;
            for (int offset = 0; offset <= image.length - 4; offset++) {
                if (le32(image, offset) != target) {
                    continue;
                }
                Address address = block.getStart().add(offset);
                Function function = getFunctionContaining(address);
                println(address + " in " +
                    (function == null ? "data/no function" :
                        function.getEntryPoint() + " " + function.getName()));
                matches++;
            }
            println("literal matches: " + matches);
            Address peripheral = currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(target);
            println("analysis references to peripheral address:");
            for (Reference reference : getReferencesTo(peripheral)) {
                Function function = getFunctionContaining(reference.getFromAddress());
                println(reference.getFromAddress() + " <- " +
                    (function == null ? "no function" :
                        function.getEntryPoint() + " " + function.getName()));
            }
        }
    }
}
