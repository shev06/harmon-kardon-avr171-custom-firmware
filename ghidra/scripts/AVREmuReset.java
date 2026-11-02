import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.lang.Register;

public class AVREmuReset extends GhidraScript {
    @Override
    public void run() throws Exception {
        SleighLanguage language = (SleighLanguage) currentProgram.getLanguage();
        println("Language: " + language.getLanguageID());
        println("Compiler: " + currentProgram.getCompilerSpec().getCompilerSpecID());
        PcodeEmulator emulator = new PcodeEmulator(language);
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        byte[] chunk = new byte[4096];
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }
            long offset = 0;
            while (offset < block.getSize()) {
                int count = (int) Math.min(chunk.length, block.getSize() - offset);
                currentProgram.getMemory().getBytes(block.getStart().add(offset), chunk, 0, count);
                byte[] bytes = new byte[count];
                System.arraycopy(chunk, 0, bytes, 0, count);
                emulator.getSharedState().setVar(
                    space, block.getStart().add(offset).getOffset(), count, true, bytes);
                offset += count;
            }
        }

        PcodeThread<byte[]> thread = emulator.newThread();
        thread.getState().setVar(
            language.getRegister("sp"), new byte[] { (byte) 0x88, (byte) 0x91, 0x00, 0x20 });
        thread.getState().setVar(
            language.getRegister("pc"), new byte[] { 0x6c, (byte) 0xd3, 0x00, 0x08 });
        thread.overrideContextWithDefault();
        thread.reInitialize();
        thread.setCounter(currentProgram.getAddressFactory().getAddress("0x0800d36c"));

        Register pcRegister = language.getRegister("pc");
        Register[] tracked = {
            language.getRegister("r0"), language.getRegister("r1"),
            language.getRegister("r2"), language.getRegister("r3"),
            language.getRegister("r4"), language.getRegister("sp")
        };
        boolean initCallActive = false;
        boolean initTableDone = false;
        int initCallCount = 0;
        for (int i = 0; i < 100000; i++) {
            long pc = Utils.bytesToLong(
                thread.getState().getVar(pcRegister, Reason.INSPECT),
                pcRegister.getNumBytes(),
                language.isBigEndian());
            if (pc == 0x0800d122L) {
                Register r0 = language.getRegister("r0");
                Register r1 = language.getRegister("r1");
                long descriptor = Utils.bytesToLong(
                    thread.getState().getVar(r0, Reason.INSPECT),
                    r0.getNumBytes(), language.isBigEndian());
                long target = Utils.bytesToLong(
                    thread.getState().getVar(r1, Reason.INSPECT),
                    r1.getNumBytes(), language.isBigEndian());
                println(String.format("Init table call %d at step %d: descriptor=0x%08x target=0x%08x",
                    ++initCallCount, i, descriptor, target & ~1L));
                initCallActive = true;
            }
            if (initCallActive && pc == 0x0800d124L) {
                println(String.format("Init table call %d returned at step %d",
                    initCallCount, i));
                initCallActive = false;
                if (initCallCount == 2) {
                    byte[] copied = thread.getState().getVar(
                        space, 0x20000000L, 8, true, Reason.INSPECT);
                    println(String.format("Initialized RAM words: 0x%08x 0x%08x",
                        Utils.bytesToLong(
                            java.util.Arrays.copyOfRange(copied, 0, 4), 4,
                            language.isBigEndian()),
                        Utils.bytesToLong(
                            java.util.Arrays.copyOfRange(copied, 4, 8), 4,
                            language.isBigEndian())));
                }
            }
            if (!initTableDone && initCallCount > 0 && !initCallActive &&
                    pc == 0x0800d12aL) {
                println("Initialization table walk completed at step " + i);
                initTableDone = true;
                byte[] firstWord = thread.getState().getVar(
                    space, 0x20000008L, 4, true, Reason.INSPECT);
                byte[] lastWord = thread.getState().getVar(
                    space, 0x20007184L, 4, true, Reason.INSPECT);
                println(String.format("RAM clear boundary words: first=0x%08x last=0x%08x",
                    Utils.bytesToLong(firstWord, 4, language.isBigEndian()),
                    Utils.bytesToLong(lastWord, 4, language.isBigEndian())));
            }
            if (initTableDone && pc == 0x080082a0L) {
                println(String.format(
                    "Stopped at step %d: clock setup entered the non-returning " +
                    "RCC-ready failure loop at 0x080082a0", i));
                break;
            }
            Address address = currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(pc);
            if (i < 40 || (initCallActive && i % 10000 == 0) ||
                    (initTableDone && i % 10000 == 0)) {
                StringBuilder state = new StringBuilder();
                for (Register register : tracked) {
                    long value = Utils.bytesToLong(
                        thread.getState().getVar(register, Reason.INSPECT),
                        register.getNumBytes(),
                        language.isBigEndian());
                    state.append(String.format(" %s=%08x", register.getName(), value));
                }
                Instruction instruction = getInstructionAt(address);
                println(String.format("%05d PC=0x%08x%s %s", i, pc, state,
                    instruction == null ? "<unlisted>" : instruction.toString()));
            }
            try {
                thread.stepInstruction();
            }
            catch (Exception e) {
                printerr("Stopped at step " + i + ": " + e);
                break;
            }
        }
    }
}
