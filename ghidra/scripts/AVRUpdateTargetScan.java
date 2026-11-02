import ghidra.program.model.mem.MemoryBlock;

/** Scans two address windows (candidate MCU-update and BCO-update
 *  orchestrators) for 4-byte-aligned literal pool words that look like
 *  plausible flash addresses, to find the real flash target range. */
public class AVRUpdateTargetScan extends ghidra.app.script.GhidraScript {
    private long le32(byte[] b, int off) {
        return ((long) b[off] & 0xff) | (((long) b[off + 1] & 0xff) << 8) |
            (((long) b[off + 2] & 0xff) << 16) | (((long) b[off + 3] & 0xff) << 24);
    }

    private void scan(byte[] image, long imageStart, long from, long to, String label) {
        println("\n=== " + label + " (0x" + Long.toHexString(from) + "-0x" +
            Long.toHexString(to) + ") candidate address literals ===");
        for (long addr = from; addr < to; addr += 4) {
            int off = (int) (addr - imageStart);
            if (off < 0 || off + 4 > image.length) {
                continue;
            }
            long val = le32(image, off);
            if (val >= 0x08000000L && val < 0x08600000L) {
                println(String.format("  0x%08x : 0x%08x", addr, val));
            } else if (val >= 0x20000000L && val < 0x20080000L) {
                println(String.format("  0x%08x : 0x%08x (RAM)", addr, val));
            }
        }
    }

    @Override
    public void run() throws Exception {
        MemoryBlock block = currentProgram.getMemory().getBlock("firmware");
        byte[] image = new byte[(int) block.getSize()];
        currentProgram.getMemory().getBytes(block.getStart(), image);
        long imageStart = block.getStart().getOffset();

        scan(image, imageStart, 0x08005c00L, 0x08006300L, "MCU-update orchestrator candidate");
        scan(image, imageStart, 0x08007800L, 0x08008100L, "BCO-update orchestrator candidate");
    }
}
