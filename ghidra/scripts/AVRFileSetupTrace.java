// Raw instruction dump of two still-unexplored gaps, both left un-Function'd by
// existing analysis (consistent with every other gap found in this project):
//
//  1) 0x08005d0a - 0x08005e6c : the real dispatcher entry (tail-called from the
//     thin stub FUN_08005c00) up to the already-traced state-machine switch at
//     0x08005e72. This is the one untraced window between "orchestrator starts"
//     and "state switch reads state byte" -- the natural place for any one-time
//     fopen()/fseek() setup on the update file to live (open-work items 1 & 2).
//
//  2) 0x08007800 - 0x08008100 : the BCO update orchestrator window (open-work
//     item 4) -- CreateFunctionCmd only produced one trivial getter function
//     here (FUN_08007802), so dump it raw instead.
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;

public class AVRFileSetupTrace extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        dumpRange("0x08005d0a", "0x08005e72");
        dumpRange("0x08007800", "0x08008100");
    }

    private void dumpRange(String startStr, String endStr) throws Exception {
        Address start = currentProgram.getAddressFactory().getAddress(startStr);
        Address end = currentProgram.getAddressFactory().getAddress(endStr);
        println("##### RANGE " + start + " - " + end + " #####");

        // Make sure it's disassembled as code even if existing analysis left it undefined.
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
