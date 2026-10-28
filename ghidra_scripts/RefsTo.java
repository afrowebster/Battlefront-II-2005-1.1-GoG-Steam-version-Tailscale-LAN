// Lists references to the given data addresses and decompiles each referencing function once.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class RefsTo extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<Function> functions = new LinkedHashSet<>();
        for (String argument : getScriptArgs()) {
            for (Reference ref : getReferencesTo(toAddr(argument))) {
                Function function = getFunctionContaining(ref.getFromAddress());
                println("REF " + argument + " from " + ref.getFromAddress() + " " + ref.getReferenceType() + " in " + (function == null ? "?" : function.getName()));
                if (function != null) functions.add(function);
            }
        }
        for (Function function : functions) {
            DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
            println("==== " + function.getName() + " @ " + function.getEntryPoint());
            println(results.decompileCompleted() ? results.getDecompiledFunction().getC() : "decompile failed");
        }
    }
}
