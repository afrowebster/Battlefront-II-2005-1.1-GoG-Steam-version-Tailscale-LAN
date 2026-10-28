// Lists every call site of the external functions of one DLL (default WS2_32.DLL) and
// decompiles each calling function once. Works for ordinal imports (Ordinal_23 etc.).
// Args: [dll] [nodecompile]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class ImportCallers extends GhidraScript {
    @Override
    public void run() throws Exception {
        String dll = "WS2_32.DLL";
        boolean decompile = true;
        for (String argument : getScriptArgs()) {
            if (argument.equals("nodecompile")) decompile = false; else dll = argument;
        }
        Set<Function> functions = new LinkedHashSet<>();
        for (Function external : currentProgram.getFunctionManager().getExternalFunctions()) {
            ExternalLocation location = external.getExternalLocation();
            if (!location.getLibraryName().equalsIgnoreCase(dll)) continue;
            println("IMPORT " + external.getName() + " ordinal/label=" + location.getLabel());
            for (Reference pointer : getReferencesTo(external.getEntryPoint())) {
                Address slot = pointer.getFromAddress();
                println("  IAT slot " + slot);
                List<Address> sites = new ArrayList<>();
                for (Reference ref : getReferencesTo(slot)) sites.add(ref.getFromAddress());
                // Thunk functions (jmp [IAT]) are called in turn.
                Function thunk = getFunctionContaining(slot);
                for (Address site : sites) {
                    Function caller = getFunctionContaining(site);
                    if (caller != null && caller.isThunk()) {
                        for (Reference ref : getReferencesTo(caller.getEntryPoint())) {
                            Function outer = getFunctionContaining(ref.getFromAddress());
                            println("    call " + ref.getFromAddress() + " via thunk in " + (outer == null ? "?" : outer.getName()));
                            if (outer != null) functions.add(outer);
                        }
                        continue;
                    }
                    println("    call " + site + " in " + (caller == null ? "?" : caller.getName()));
                    if (caller != null) functions.add(caller);
                }
            }
        }
        if (!decompile) return;
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (Function function : functions) {
            DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
            println("==== " + function.getName() + " @ " + function.getEntryPoint());
            println(results.decompileCompleted() ? results.getDecompiledFunction().getC() : "decompile failed");
        }
    }
}
