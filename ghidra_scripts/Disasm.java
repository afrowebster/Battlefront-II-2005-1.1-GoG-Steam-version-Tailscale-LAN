// Prints instructions starting at each address. Args: <addr>[:count]...  (default 40)
// Useful where Ghidra has no function defined (e.g. Lua callback tables).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class Disasm extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String argument : getScriptArgs()) {
            String[] parts = argument.split(":");
            Address address = toAddr(parts[0]);
            int count = parts.length > 1 ? Integer.parseInt(parts[1]) : 40;
            println("==== " + address);
            Instruction instruction = getInstructionAt(address);
            if (instruction == null) {
                disassemble(address);
                instruction = getInstructionAt(address);
            }
            for (int index = 0; index < count && instruction != null; ++index) {
                println(instruction.getAddress() + "  " + instruction);
                instruction = instruction.getNext();
            }
        }
    }
}
