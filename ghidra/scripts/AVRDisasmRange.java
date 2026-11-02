import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

// Generic: print instructions (with outgoing refs) in [start, end]. Usage:
//   -postScript AVRDisasmRange.java <startHex> <endHex> [<startHex> <endHex> ...]
public class AVRDisasmRange extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        for (int i = 0; i + 1 < args.length; i += 2) {
            Address start = toAddr(Long.parseLong(args[i].replace("0x", ""), 16));
            Address end = toAddr(Long.parseLong(args[i + 1].replace("0x", ""), 16));
            println("\n==== " + start + " .. " + end + " ====");
            for (Instruction ins : currentProgram.getListing().getInstructions(start, true)) {
                if (ins.getAddress().compareTo(end) > 0) break;
                StringBuilder refs = new StringBuilder();
                for (Reference r : getReferencesFrom(ins.getAddress())) {
                    refs.append("  -> ").append(r.getToAddress());
                }
                println(ins.getAddress() + "\t" + ins + refs);
            }
        }
        println("\nDONE_DISASM_RANGE");
    }
}
