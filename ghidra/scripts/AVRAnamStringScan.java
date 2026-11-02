import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/** Raw byte scan (not relying on Ghidra's reference manager) for pointers to
 *  the bootloader strings that showed zero cross-references, to check
 *  whether "!!ANAM SOFT!!" and the USBH debug strings are truly unused. */
public class AVRAnamStringScan extends ghidra.app.script.GhidraScript {
    private long le32(byte[] b, int off) {
        return ((long) b[off] & 0xff) | (((long) b[off + 1] & 0xff) << 8) |
            (((long) b[off + 2] & 0xff) << 16) | (((long) b[off + 3] & 0xff) << 24);
    }

    @Override
    public void run() throws Exception {
        MemoryBlock block = currentProgram.getMemory().getBlock("firmware");
        byte[] image = new byte[(int) block.getSize()];
        currentProgram.getMemory().getBytes(block.getStart(), image);
        long imageStart = block.getStart().getOffset();

        long[] targets = { 0x0800d158L, 0x0800d2d8L, 0x0800d348L, 0x0800d378L };
        for (long target : targets) {
            println("\n=== raw pointer scan for 0x" + Long.toHexString(target) + " ===");
            int matches = 0;
            for (int offset = 0; offset <= image.length - 4; offset++) {
                if (le32(image, offset) != target) {
                    continue;
                }
                Address addr = block.getStart().add(offset);
                Function fn = getFunctionContaining(addr);
                println("  " + addr + " (" + (fn == null ? "no fn" : fn.getName()) + ")");
                matches++;
            }
            println("  total matches: " + matches);
        }

        println("\n=== bytes at 0800d2c8-0800d2e8 (context around !!ANAM SOFT!!) ===");
        int off = (int) (0x0800d2c8L - imageStart);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            sb.append(String.format("%02x ", image[off + i]));
        }
        println(sb.toString());
    }
}
