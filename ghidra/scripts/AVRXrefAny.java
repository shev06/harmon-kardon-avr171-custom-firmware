import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

// Generic: for every address passed as a script argument (hex), print each reference TO it
// (type, source address, containing function, source instruction). Used to find who loads a
// literal-pool slot or calls a function. Usage: -postScript AVRXrefAny.java 080521a0 08019638 ...
public class AVRXrefAny extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            long addr = Long.parseLong(a.replace("0x", ""), 16);
            Address target = toAddr(addr);
            println("\n#### refs to " + a);
            int n = 0;
            for (Reference r : currentProgram.getReferenceManager().getReferencesTo(target)) {
                Address from = r.getFromAddress();
                Function f = getFunctionContaining(from);
                Instruction ins = getInstructionAt(from);
                println(String.format("  %s  %-14s  in %s  | %s", from, r.getReferenceType(),
                    f == null ? "(no function)" : f.getName() + "@" + f.getEntryPoint(),
                    ins == null ? "(no insn)" : ins.toString()));
                n++;
            }
            println("  total " + n);
        }
        println("\nDONE_XREF_ANY");
    }
}
