import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Function;

public class AVRLayout extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        println("Program: " + currentProgram.getName());
        println("Language: " + currentProgram.getLanguageID());
        println("Compiler: " + currentProgram.getCompilerSpec().getCompilerSpecID());
        println("Image base: " + currentProgram.getImageBase());
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            println("BLOCK " + block.getName() + " " + block.getStart() + "-" +
                block.getEnd() + " size=0x" + Long.toHexString(block.getSize()) +
                " execute=" + block.isExecute() + " write=" + block.isWrite());
        }
        println("Entry points:");
        for (ghidra.program.model.symbol.Symbol symbol :
                currentProgram.getSymbolTable().getExternalSymbols()) {
            println(symbol.getName() + " " + symbol.getAddress());
        }
        Function entry = currentProgram.getFunctionManager().getFunctionAt(
            currentProgram.getImageBase());
        println("Image-base function: " + (entry == null ? "none" : entry.getName()));
    }
}
