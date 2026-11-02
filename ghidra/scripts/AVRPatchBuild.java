import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.Address;

import java.util.ArrayList;
import java.util.List;

// Builds the full trampoline (param_2/zone + param_3/para NULL-guarded insertion)
// for FUN_08044dc4's query-status response bug, plus the single 6-byte entry-hook
// replacement at 0x08044e24. Everything is assembled via Ghidra's validated
// Assembler (see AVRAssemblerValidate.java round-trip results) and printed as a
// flat hex blob + addresses. No file is written by this script; that is done by
// a separate, plain Python step against a COPY of the original .fw.
public class AVRPatchBuild extends ghidra.app.script.GhidraScript {

    String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    static class Emitted {
        Address addr;
        String mnemonic;
        byte[] bytes;
    }

    @Override
    public void run() throws Exception {
        Assembler asm = Assemblers.getAssembler(currentProgram);

        // ---- Trampoline body, in exact execution order, at precomputed addresses ----
        // Addresses were hand-derived from known Thumb encoding sizes (2 bytes for
        // add-sp-form/movs/mov-highreg/adds/cbz; 4 bytes for ldr.w/bl/b.w) and
        // cross-checked against AVRAssemblerValidate.java's measured lengths.
        String[][] plan = {
            // {address, mnemonic}
            {"0x080c89b4", "ldr.w r0,[sp,#0x404]"},   // A1: r0 = param_2
            {"0x080c89b8", "cbz r0,0x080c89cc"},        // A2: if (param_2==0) skip to R1 (A_skip)
            {"0x080c89ba", "add r0,sp,#0x0"},            // A3  (reproduces style of orig append idiom)
            {"0x080c89bc", "bl 0x08077bac"},              // A4: r0 = strlen(buf)
            {"0x080c89c0", "ldr.w r1,[sp,#0x404]"},      // A5: r1 = param_2 (reload; r0 was clobbered)
            {"0x080c89c4", "add r2,sp,#0x0"},             // A6: r2 = &buf
            {"0x080c89c6", "adds r0,r0,r2"},                // A7: r0 = buf+len
            {"0x080c89c8", "bl 0x08077c00"},                 // A8: strcpy(buf+len, param_2)  [A_skip lands at next addr]

            {"0x080c89cc", "add r0,sp,#0x0"},             // R1: reproduces original I31
            {"0x080c89ce", "bl 0x08077bac"},                 // R2: reproduces original I32 (len=strlen(buf))
            {"0x080c89d2", "mov r1,r8"},                     // R3: reproduces original I33 (r8="</zone><para>")
            {"0x080c89d4", "add r2,sp,#0x0"},               // R4: reproduces original I34
            {"0x080c89d6", "adds r0,r0,r2"},                  // R5: reproduces original I35
            {"0x080c89d8", "bl 0x08077c00"},                   // R6: reproduces original I36 (buf += "</zone><para>")

            {"0x080c89dc", "ldr.w r0,[sp,#0x408]"},        // B1: r0 = param_3
            {"0x080c89e0", "cbz r0,0x080c89f4"},             // B2: if (param_3==0) skip to FINAL (B_skip)
            {"0x080c89e2", "add r0,sp,#0x0"},                 // B3
            {"0x080c89e4", "bl 0x08077bac"},                   // B4: r0 = strlen(buf)
            {"0x080c89e8", "ldr.w r1,[sp,#0x408]"},          // B5: r1 = param_3 (reload)
            {"0x080c89ec", "add r2,sp,#0x0"},                 // B6: r2 = &buf
            {"0x080c89ee", "adds r0,r0,r2"},                    // B7: r0 = buf+len
            {"0x080c89f0", "bl 0x08077c00"},                     // B8: strcpy(buf+len, param_3)  [B_skip lands at next addr]

            {"0x080c89f4", "b.w 0x08044e34"},                  // FINAL: resume original function at I37
        };

        List<Emitted> emitted = new ArrayList<>();
        println("=== Assembling trampoline, instruction by instruction ===");
        for (String[] row : plan) {
            Address a = currentProgram.getAddressFactory().getAddress(row[0]);
            String mnemonic = row[1];
            byte[] bytes = asm.assembleLine(a, mnemonic);
            Emitted e = new Emitted();
            e.addr = a; e.mnemonic = mnemonic; e.bytes = bytes;
            emitted.add(e);
            println(a + " | " + String.format("%-28s", mnemonic) + " | " + hex(bytes) + " | len=" + bytes.length);
        }

        // Sanity check: verify every instruction's end address == next instruction's start address
        // (confirms no gaps/overlaps in the hand-derived address plan).
        println("\n=== Contiguity check ===");
        boolean allOk = true;
        for (int i = 0; i < emitted.size() - 1; i++) {
            Address expectedNext = emitted.get(i).addr.add(emitted.get(i).bytes.length);
            Address actualNext = emitted.get(i + 1).addr;
            boolean ok = expectedNext.equals(actualNext);
            if (!ok) {
                allOk = false;
                println("MISMATCH after " + emitted.get(i).addr + " (" + emitted.get(i).mnemonic +
                    "): expected next=" + expectedNext + " but plan says " + actualNext);
            }
        }
        println(allOk ? "All instructions contiguous, no gaps/overlaps." : "CONTIGUITY FAILURE - DO NOT PROCEED");

        // Flatten trampoline bytes into one blob
        StringBuilder blob = new StringBuilder();
        for (Emitted e : emitted) blob.append(hex(e.bytes));
        Address trampolineStart = currentProgram.getAddressFactory().getAddress("0x080c89b4");
        Address trampolineEnd = emitted.get(emitted.size() - 1).addr.add(emitted.get(emitted.size() - 1).bytes.length);
        println("\n=== TRAMPOLINE BLOB ===");
        println("start_addr=" + trampolineStart);
        println("end_addr=" + trampolineEnd);
        println("length_bytes=" + (blob.length() / 2));
        println("hex=" + blob.toString());

        // ---- Entry-hook replacement: 6 bytes at 0x08044e24 (overwrites original I31+I32) ----
        println("\n=== ENTRY HOOK REPLACEMENT (6 bytes @ 0x08044e24, was I31+I32) ===");
        Address hookAddr = currentProgram.getAddressFactory().getAddress("0x08044e24");
        byte[] bw = asm.assembleLine(hookAddr, "b.w 0x080c89b4");
        byte[] nop = asm.assembleLine(hookAddr.add(4), "nop");
        println("0x08044e24 | b.w 0x080c89b4 | " + hex(bw) + " | len=" + bw.length);
        println("0x08044e28 | nop            | " + hex(nop) + " | len=" + nop.length);
        println("hook_addr=0x08044e24");
        println("hook_length_bytes=" + (bw.length + nop.length));
        println("hook_hex=" + hex(bw) + hex(nop));

        // Read back and print what the 6 original bytes at the hook site currently are,
        // for the diff report.
        byte[] origHookBytes = new byte[6];
        currentProgram.getMemory().getBytes(hookAddr, origHookBytes);
        println("hook_original_hex=" + hex(origHookBytes));
    }
}
