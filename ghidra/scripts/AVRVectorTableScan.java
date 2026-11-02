import ghidra.program.model.mem.MemoryBlock;

public class AVRVectorTableScan extends ghidra.app.script.GhidraScript {
    private long le32(byte[] bytes, int offset) {
        return ((long) bytes[offset] & 0xff) |
            (((long) bytes[offset + 1] & 0xff) << 8) |
            (((long) bytes[offset + 2] & 0xff) << 16) |
            (((long) bytes[offset + 3] & 0xff) << 24);
    }

    @Override
    public void run() throws Exception {
        MemoryBlock block = currentProgram.getMemory().getBlock("firmware");
        byte[] image = new byte[(int) block.getSize()];
        currentProgram.getMemory().getBytes(block.getStart(), image);
        long imageStart = block.getStart().getOffset();
        long imageEnd = imageStart + image.length;
        int candidates = 0;
        for (int offset = 0; offset <= image.length - 32; offset += 4) {
            long sp = le32(image, offset);
            long reset = le32(image, offset + 4);
            if (sp < 0x20000000L || sp >= 0x20080000L ||
                    reset < imageStart || reset >= imageEnd || (reset & 1) == 0) {
                continue;
            }
            int validVectors = 0;
            for (int entry = 1; entry < 8; entry++) {
                long vector = le32(image, offset + entry * 4);
                if (vector == 0 || (vector >= imageStart && vector < imageEnd &&
                        (vector & 1) == 1)) {
                    validVectors++;
                }
            }
            if (validVectors >= 5) {
                println(String.format(
                    "candidate 0x%08x: SP=0x%08x reset=0x%08x valid_vectors=%d " +
                    "v2=0x%08x v3=0x%08x",
                    imageStart + offset, sp, reset, validVectors,
                    le32(image, offset + 8), le32(image, offset + 12)));
                candidates++;
            }
        }
        println("candidate count: " + candidates);
    }
}
