import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;

public class AVRCodeUnitProbe extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        String[] addrs = {
            "0x08007700", "0x08007750", "0x080077c0", "0x08007800", "0x08007810",
            "0x08007818", "0x0800781c", "0x08007820", "0x0800783c", "0x08007852",
            "0x0800785a", "0x08007880", "0x0800788a", "0x080078d4", "0x080078e8",
            "0x080078f2", "0x08007900", "0x08007950", "0x080079a0", "0x080079f0"
        };
        for (String a : addrs) {
            Address addr = currentProgram.getAddressFactory().getAddress(a);
            CodeUnit cu = currentProgram.getListing().getCodeUnitContaining(addr);
            println(a + " -> " + (cu == null ? "null" :
                cu.getClass().getSimpleName() + " at " + cu.getAddress() +
                " len=" + cu.getLength() + " : " + cu));
        }
    }
}
