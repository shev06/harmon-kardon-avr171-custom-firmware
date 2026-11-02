import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

/**
 * Reconstructs the OSD message pointer table in the low (bootloader) region
 * by scanning raw words for values that equal known string addresses, then
 * finds what code reads each table slot.
 */
public class AVRBootStringTable extends ghidra.app.script.GhidraScript {
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

        long[] stringAddrs = {
            0x0800d158L, 0x0800d1c8L, 0x0800d1dcL, 0x0800d1f0L, 0x0800d204L,
            0x0800d218L, 0x0800d22cL, 0x0800d240L, 0x0800d254L, 0x0800d268L,
            0x0800d27cL, 0x0800d290L, 0x0800d2b8L, 0x0800d2d8L, 0x0800d318L,
            0x0800d348L
        };

        println("=== scanning 0x08008000-0x08008200 for pointers to known strings ===");
        long scanStart = 0x08008000L;
        long scanEnd = 0x08008200L;
        for (long addr = scanStart; addr < scanEnd; addr += 4) {
            int off = (int) (addr - imageStart);
            long val = le32(image, off);
            for (long sAddr : stringAddrs) {
                if (val == sAddr) {
                    println(String.format("  0x%08x -> 0x%08x", addr, val));
                }
            }
        }

        println("\n=== who reads each table slot (code referencing the slot address) ===");
        for (long addr = scanStart; addr < scanEnd; addr += 4) {
            int off = (int) (addr - imageStart);
            long val = le32(image, off);
            boolean isStringPtr = false;
            for (long sAddr : stringAddrs) {
                if (val == sAddr) {
                    isStringPtr = true;
                    break;
                }
            }
            if (!isStringPtr) {
                continue;
            }
            Address slotAddr = currentProgram.getAddressFactory().getAddress(
                String.format("0x%08x", addr));
            boolean any = false;
            for (Reference ref : getReferencesTo(slotAddr)) {
                any = true;
                Address from = ref.getFromAddress();
                Function fn = getFunctionContaining(from);
                println("  slot 0x" + Long.toHexString(addr) + " read from " + from +
                    " in " + (fn == null ? "no function" : fn.getEntryPoint() + " " + fn.getName()));
            }
            if (!any) {
                println("  slot 0x" + Long.toHexString(addr) + ": no code references found");
            }
        }
    }
}
