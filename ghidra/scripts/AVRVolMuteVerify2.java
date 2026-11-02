import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;

public class AVRVolMuteVerify2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== Full string table dump (no bad masking this time) ===");
        for (int p = 0; p <= 100; p++) {
            long tableEntryAddr = 0x080c8b44L + (p * 4);
            int strAddr = currentProgram.getMemory().getInt(toAddr(tableEntryAddr));
            byte[] buf = new byte[4];
            currentProgram.getMemory().getBytes(toAddr(strAddr & 0xFFFFFFFFL), buf);
            StringBuilder sb = new StringBuilder();
            for (byte b : buf) { if (b == 0) break; sb.append((char) b); }
            String expected = Integer.toString(p);
            String status = sb.toString().equals(expected) ? "OK" : "MISMATCH";
            println("  percent=" + p + " table_entry_addr=0x" + Integer.toHexString(strAddr) + " -> \"" + sb + "\" expected=\"" + expected + "\" [" + status + "]");
        }
        println("DONE");
    }
}
