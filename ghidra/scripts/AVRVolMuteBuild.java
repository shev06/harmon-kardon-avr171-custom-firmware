// Builds byte patterns for:
//  1. A 101-entry (0..100) null-terminated ASCII percentage string table + pointer
//     table in free flash (zero RAM writes at runtime -- consistent with how every
//     other query-status reply in this firmware works: always picks one of a set
//     of pre-existing fixed flash literals, never formats a value dynamically).
//  2. Volume trampoline: reads raw 0-180 byte at 0x2001c290, computes percent via
//     raw*100/180 (udiv), special-cased raw==1 -> 1% (mirrors FUN_0802d174's own
//     special case so our reported number matches what CEC/OSD would show), then
//     indexes the pointer table to get the exact percentage string.
//  3. Mute trampoline: reads mute/mode flag bit4 (0x2001c038) OR standby-like flag
//     (0x2001c1dc) -- the same two conditions FUN_0802d174 itself ORs together --
//     and picks the SAME "on"/"off" flash literals (0x0804b038/0x0804b03c) the
//     existing power branch already uses.
//  4. The two 4-byte patch-site replacements (both just "bl <trampoline>").
// Nothing here is written to the live Ghidra program or the real .fw file --
// this only derives bytes, exactly like every prior patch's *Build.java script.
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import java.io.*;
import java.util.*;

public class AVRVolMuteBuild extends ghidra.app.script.GhidraScript {

    private String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        Assembler asm = Assemblers.getAssembler(currentProgram);
        Memory mem = currentProgram.getMemory();
        List<String> outLines = new ArrayList<>();

        // REBASED: the original 0x080c8a1c base now collides with the new universal
        // power-off fix's trampoline (0x080c8a1a-0x080c8a35, 28 bytes), applied to the
        // real deliverable after this script was first written. New base is the next
        // 4-aligned free address after that trampoline, confirmed free via real-file
        // byte scan (free run 0x080c8a36 onward, >=970 bytes, in the current deliverable).
        long STRINGS_BASE = 0x080c8a38L;

        // --- 1a. Build the 101 percentage strings sequentially, recording addresses ---
        long cursor = STRINGS_BASE;
        long[] strAddr = new long[101];
        ByteArrayOutputStream allStrBytes = new ByteArrayOutputStream();
        for (int pct = 0; pct <= 100; pct++) {
            strAddr[pct] = cursor;
            byte[] s = (Integer.toString(pct) + "\0").getBytes("ASCII");
            allStrBytes.write(s);
            cursor += s.length;
        }
        byte[] stringsBlob = allStrBytes.toByteArray();
        println("Strings blob: base=0x" + Long.toHexString(STRINGS_BASE) + " length=" + stringsBlob.length + " end=0x" + Long.toHexString(cursor));

        // 4-byte align for the pointer table
        long TABLE_BASE = (cursor + 3) & ~3L;
        long padding = TABLE_BASE - cursor;
        println("Padding before table: " + padding + " bytes; TABLE_BASE=0x" + Long.toHexString(TABLE_BASE));

        // --- 1b. Build the 101-entry LE pointer table ---
        ByteArrayOutputStream tableBytes = new ByteArrayOutputStream();
        for (int pct = 0; pct <= 100; pct++) {
            long addr = strAddr[pct];
            tableBytes.write((int) (addr & 0xFF));
            tableBytes.write((int) ((addr >> 8) & 0xFF));
            tableBytes.write((int) ((addr >> 16) & 0xFF));
            tableBytes.write((int) ((addr >> 24) & 0xFF));
        }
        byte[] tableBlob = tableBytes.toByteArray();
        long VOL_CODE = TABLE_BASE + tableBlob.length;
        println("Table blob length=" + tableBlob.length + "; VOL_CODE=0x" + Long.toHexString(VOL_CODE));

        // --- 2. Volume trampoline ---
        List<byte[]> volInsns = new ArrayList<>();
        Address a = toAddr(VOL_CODE);
        Address volStart = a;
        // movw/movt r3 = 0x2001c290 ; ldrb r3,[r3,#0]
        volInsns.add(asm.assembleLine(a, "movw r3,#0xc290")); a = a.add(volInsns.get(volInsns.size()-1).length);
        volInsns.add(asm.assembleLine(a, "movt r3,#0x2001")); a = a.add(volInsns.get(volInsns.size()-1).length);
        volInsns.add(asm.assembleLine(a, "ldrb r3,[r3,#0x0]")); a = a.add(volInsns.get(volInsns.size()-1).length);
        volInsns.add(asm.assembleLine(a, "cmp r3,#0x1"));
        Address cmpAddr = a; a = a.add(volInsns.get(volInsns.size()-1).length);
        Address beqSiteAddr = a; // placeholder, beq comes next
        // we need L_one target resolved after computing the "normal path" length; do a two-pass approach:
        // First assemble normal path with a dummy beq target, discover length, then redo with the real target.
        // Normal path instructions (after the beq slot):
        Address normalPathStart = a.add(2); // beq is 2 bytes
        Address np = normalPathStart;
        byte[] n1 = asm.assembleLine(np, "movs r0,#0x64"); np = np.add(n1.length);
        byte[] n2 = asm.assembleLine(np, "mul r3,r0,r3"); np = np.add(n2.length);
        byte[] n3 = asm.assembleLine(np, "movs r0,#0xb4"); np = np.add(n3.length);
        byte[] n4 = asm.assembleLine(np, "udiv r3,r3,r0"); np = np.add(n4.length);
        Address bAddr = np; // "b L_have_percent" goes here
        Address bTargetGuess = bAddr.add(2); // b is 2 bytes, L_one is right after (1 instruction, 2 bytes) then L_have_percent
        Address lOne = bAddr.add(2);
        byte[] oneInsn = asm.assembleLine(lOne, "movs r3,#0x1");
        Address lHavePercent = lOne.add(oneInsn.length);
        byte[] bInsn = asm.assembleLine(bAddr, "b 0x" + Long.toHexString(lHavePercent.getOffset()));
        byte[] beqInsn = asm.assembleLine(cmpAddr.add(volInsns.get(volInsns.size()-1).length), "beq 0x" + Long.toHexString(lOne.getOffset()));

        // Now assemble the tail starting at lHavePercent
        Address tp = lHavePercent;
        byte[] t1 = asm.assembleLine(tp, "movw r2,#0x" + Long.toHexString(TABLE_BASE & 0xFFFF)); tp = tp.add(t1.length);
        byte[] t2 = asm.assembleLine(tp, "movt r2,#0x" + Long.toHexString((TABLE_BASE >> 16) & 0xFFFF)); tp = tp.add(t2.length);
        byte[] t3 = asm.assembleLine(tp, "lsls r3,r3,#0x2"); tp = tp.add(t3.length);
        byte[] t4 = asm.assembleLine(tp, "ldr r2,[r2,r3]"); tp = tp.add(t4.length);
        byte[] t5 = asm.assembleLine(tp, "movs r1,#0x0"); tp = tp.add(t5.length);
        byte[] t6 = asm.assembleLine(tp, "bx lr"); tp = tp.add(t6.length);
        long VOL_CODE_END = tp.getOffset();

        // Assemble the whole thing in final program order and concatenate:
        ByteArrayOutputStream volOut = new ByteArrayOutputStream();
        volOut.write(volInsns.get(0)); volOut.write(volInsns.get(1)); volOut.write(volInsns.get(2)); volOut.write(volInsns.get(3));
        volOut.write(beqInsn);
        volOut.write(n1); volOut.write(n2); volOut.write(n3); volOut.write(n4);
        volOut.write(bInsn);
        volOut.write(oneInsn);
        volOut.write(t1); volOut.write(t2); volOut.write(t3); volOut.write(t4); volOut.write(t5); volOut.write(t6);
        byte[] volBlob = volOut.toByteArray();
        println("Volume trampoline: start=0x" + Long.toHexString(VOL_CODE) + " length=" + volBlob.length + " end=0x" + Long.toHexString(VOL_CODE_END));
        println("  cmp/beq target(L_one)=0x" + Long.toHexString(lOne.getOffset()) + " b target(L_have_percent)=0x" + Long.toHexString(lHavePercent.getOffset()));

        long MUTE_CODE = (VOL_CODE_END + 1) & ~1L; // 2-byte align is enough for Thumb code

        // --- 3. Mute trampoline ---
        Address m = toAddr(MUTE_CODE);
        ByteArrayOutputStream muteOut = new ByteArrayOutputStream();
        byte[] m1 = asm.assembleLine(m, "movw r3,#0xc038"); m = m.add(m1.length);
        byte[] m2 = asm.assembleLine(m, "movt r3,#0x2001"); m = m.add(m2.length);
        byte[] m3 = asm.assembleLine(m, "ldrb r3,[r3,#0x0]"); m = m.add(m3.length);
        byte[] m4 = asm.assembleLine(m, "and r3,r3,#0x10"); m = m.add(m4.length);
        byte[] m5 = asm.assembleLine(m, "cmp r3,#0x0"); Address afterCmp1 = m.add(m5.length);
        // bne L_muted -- need L_muted address; compute the "not taken" path length first (standby-check block = m6..m9)
        Address notTakenStart = afterCmp1.add(2); // bne is 2 bytes
        Address np2 = notTakenStart;
        byte[] m6 = asm.assembleLine(np2, "movw r3,#0xc1dc"); np2 = np2.add(m6.length);
        byte[] m7 = asm.assembleLine(np2, "movt r3,#0x2001"); np2 = np2.add(m7.length);
        byte[] m8 = asm.assembleLine(np2, "ldrb r3,[r3,#0x0]"); np2 = np2.add(m8.length);
        byte[] m9 = asm.assembleLine(np2, "cmp r3,#0x0"); Address afterCmp2 = np2.add(m9.length);
        // beq L_notmuted -- L_notmuted is right after L_muted block; need L_muted block length first
        Address lMuted = afterCmp2.add(2); // beq is 2 bytes
        byte[] mm1 = asm.assembleLine(lMuted, "movw r2,#0xb038"); Address afterMm1 = lMuted.add(mm1.length);
        byte[] mm2 = asm.assembleLine(afterMm1, "movt r2,#0x0804"); Address afterMm2 = afterMm1.add(mm2.length);
        byte[] mm3 = asm.assembleLine(afterMm2, "b 0x" + Long.toHexString(afterMm2.add(2 + 8).getOffset())); // placeholder, fixed below
        Address lNotMuted = afterMm2.add(2); // b is 2 bytes
        byte[] mn1 = asm.assembleLine(lNotMuted, "movw r2,#0xb03c"); Address afterMn1 = lNotMuted.add(mn1.length);
        byte[] mn2 = asm.assembleLine(afterMn1, "movt r2,#0x0804"); Address lDone = afterMn1.add(mn2.length);
        byte[] md1 = asm.assembleLine(lDone, "movs r1,#0x0"); Address afterMd1 = lDone.add(md1.length);
        byte[] md2 = asm.assembleLine(afterMd1, "bx lr");

        // Now assemble the real bne/beq/b with resolved targets:
        byte[] bneInsn = asm.assembleLine(afterCmp1, "bne 0x" + Long.toHexString(lMuted.getOffset()));
        byte[] beqInsn2 = asm.assembleLine(afterCmp2, "beq 0x" + Long.toHexString(lNotMuted.getOffset()));
        byte[] bInsn2 = asm.assembleLine(afterMm2, "b 0x" + Long.toHexString(lDone.getOffset()));

        muteOut.write(m1); muteOut.write(m2); muteOut.write(m3); muteOut.write(m4); muteOut.write(m5);
        muteOut.write(bneInsn);
        muteOut.write(m6); muteOut.write(m7); muteOut.write(m8); muteOut.write(m9);
        muteOut.write(beqInsn2);
        muteOut.write(mm1); muteOut.write(mm2);
        muteOut.write(bInsn2);
        muteOut.write(mn1); muteOut.write(mn2);
        muteOut.write(md1); muteOut.write(md2);
        byte[] muteBlob = muteOut.toByteArray();
        println("Mute trampoline: start=0x" + Long.toHexString(MUTE_CODE) + " length=" + muteBlob.length + " end=0x" + Long.toHexString(MUTE_CODE + muteBlob.length));
        println("  L_muted=0x" + Long.toHexString(lMuted.getOffset()) + " L_notMuted=0x" + Long.toHexString(lNotMuted.getOffset()) + " L_done=0x" + Long.toHexString(lDone.getOffset()));

        // --- Free-space sanity check against the ACTUALLY LOADED program (should be a
        // fresh import of the CURRENT real deliverable, which already has the universal
        // power-off fix applied) -- confirm the entire new region is still 0xFF. ---
        long regionLen = (MUTE_CODE + muteBlob.length) - STRINGS_BASE;
        byte[] freeCheck = new byte[(int) regionLen];
        mem.getBytes(toAddr(STRINGS_BASE), freeCheck);
        boolean allFF = true;
        for (byte bb : freeCheck) { if ((bb & 0xFF) != 0xFF) { allFF = false; break; } }
        println("Free-space check: region 0x" + Long.toHexString(STRINGS_BASE) + "-0x" + Long.toHexString(STRINGS_BASE + regionLen) + " (" + regionLen + " bytes) all 0xFF: " + allFF);
        if (!allFF) {
            println("!!!! ABORT: region is NOT free, do not proceed with this STRINGS_BASE !!!!");
        }

        // --- 4. Patch-site replacements ---
        byte[] volSite = asm.assembleLine(toAddr(0x0804ae70L), "bl 0x" + Long.toHexString(VOL_CODE));
        byte[] muteSite = asm.assembleLine(toAddr(0x0804ae8eL), "bl 0x" + Long.toHexString(MUTE_CODE));
        println("Volume patch site (0x0804ae70): " + hex(volSite));
        println("Mute patch site   (0x0804ae8e): " + hex(muteSite));

        // --- Dump everything to a file for the Python patcher to consume ---
        try (PrintWriter pw = new PrintWriter(new FileWriter("/tmp/volmute_patch_plan_v2.txt"))) {
            pw.println("STRINGS_BASE=0x" + Long.toHexString(STRINGS_BASE));
            pw.println("STRINGS_HEX=" + hex(stringsBlob));
            pw.println("PADDING=" + padding);
            pw.println("TABLE_BASE=0x" + Long.toHexString(TABLE_BASE));
            pw.println("TABLE_HEX=" + hex(tableBlob));
            pw.println("VOL_CODE=0x" + Long.toHexString(VOL_CODE));
            pw.println("VOL_CODE_HEX=" + hex(volBlob));
            pw.println("MUTE_CODE=0x" + Long.toHexString(MUTE_CODE));
            pw.println("MUTE_CODE_HEX=" + hex(muteBlob));
            pw.println("VOL_SITE_ADDR=0x0804ae70");
            pw.println("VOL_SITE_HEX=" + hex(volSite));
            pw.println("MUTE_SITE_ADDR=0x0804ae8e");
            pw.println("MUTE_SITE_HEX=" + hex(muteSite));
            pw.println("END_OF_PATCH_REGION=0x" + Long.toHexString(MUTE_CODE + muteBlob.length));
        }
        println("\nWrote /tmp/volmute_patch_plan_v2.txt");
        println("DONE");
    }
}
