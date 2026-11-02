import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

/**
 * Force-disassembles a raw address range that existing analysis left
 * undefined (no Function, no Instructions), so we can read the real
 * instructions instead of a "no containing function" gap.
 */
public class AVRForceDisasm extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getAddress("0x08007700");
        Address end = currentProgram.getAddressFactory().getAddress("0x08007a00");
        AddressSet set = new AddressSet(start, end);

        DisassembleCommand cmd = new DisassembleCommand(set, null, true);
        boolean ok = cmd.applyTo(currentProgram, monitor);
        println("Disassemble applyTo result: " + ok + " status: " + cmd.getStatusMsg());

        InstructionIterator insIt = currentProgram.getListing().getInstructions(start, true);
        while (insIt.hasNext()) {
            Instruction ins = insIt.next();
            if (ins.getAddress().getOffset() >= end.getOffset()) {
                break;
            }
            println(ins.getAddress() + ": " + ins);
        }
    }
}
