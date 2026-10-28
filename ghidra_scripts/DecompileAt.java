// Decompiles the functions containing the given addresses, plus their direct callers.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class DecompileAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Set<Function> done = new HashSet<>();
        boolean callers = true;
        for (String argument : getScriptArgs()) {
            if (argument.equals("nocallers")) { callers = false; continue; }
            Address address = toAddr(argument);
            Function function = getFunctionContaining(address);
            if (function == null) { println("NO FUNCTION at " + argument); continue; }
            dump(decompiler, function, "TARGET " + argument, done);
            if (!callers) continue;
            for (Reference ref : getReferencesTo(function.getEntryPoint())) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    dump(decompiler, caller, "CALLER of " + function.getName() + " at " + ref.getFromAddress(), done);
                }
            }
        }
    }

    private void dump(DecompInterface decompiler, Function function, String label, Set<Function> done) {
        if (!done.add(function)) { println("==== " + label + " (already shown: " + function.getName() + ")"); return; }
        DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
        println("==== " + label + " -> " + function.getName() + " @ " + function.getEntryPoint());
        println(results.decompileCompleted() ? results.getDecompiledFunction().getC() : "decompile failed: " + results.getErrorMessage());
    }
}
