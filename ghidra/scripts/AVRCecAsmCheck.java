import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Function;

// Dump raw disassembly of FUN_0809b3fc to verify the 0x82 (Active Source) branch
// truly falls through to FUN_0808cde0 regardless of the length check, i.e. confirm
// this is a real asymmetry in the compiled code and not a decompiler rendering artifact.
public class AVRCecAsmCheck extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory().getAddress("0x0809b3fc");
        Function f = getFunctionContaining(start);
        println("Function: " + f.getEntryPoint() + " - " + f.getBody().getMaxAddress());
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            println(insn.getAddress() + "  " + insn.toString());
        }
    }
}
