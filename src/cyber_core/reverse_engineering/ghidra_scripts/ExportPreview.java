// Trusted static exporter. Evidence never supplies scripts or arguments.
// @category CyberCore
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Application;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportPreview extends HeadlessScript {
    private String bounded(String text, int length) {
        if (text == null) return "";
        return text.length() > length ? text.substring(0, length) : text;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || currentProgram == null)
            throw new IllegalArgumentException("Expected output path and imported program");
        JsonObject root = new JsonObject();
        root.addProperty("backend_version", Application.getApplicationVersion());
        root.addProperty("language_id", currentProgram.getLanguageID().toString());
        root.addProperty("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        root.addProperty("image_base", currentProgram.getImageBase().toString());
        root.addProperty("analysis_timed_out", getHeadlessAnalysisTimeoutStatus());
        JsonArray functions = new JsonArray();
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram))
                throw new IllegalStateException("Decompiler could not open program");
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            int count = 0;
            while (iterator.hasNext() && count < 8 && !monitor.isCancelled()) {
                Function function = iterator.next();
                if (function.isExternal()) continue;
                count++;
                JsonObject record = new JsonObject();
                record.addProperty("address", bounded(function.getEntryPoint().toString(), 64));
                record.addProperty("name", bounded(function.getName(), 256));
                DecompileResults result = decompiler.decompileFunction(function, 3, monitor);
                boolean complete = result != null && result.decompileCompleted() && result.getDecompiledFunction() != null;
                String code = complete ? result.getDecompiledFunction().getC() : "";
                record.addProperty("status", complete ? "decompiled" : "failed");
                record.addProperty("pseudocode", bounded(code, 8192));
                record.addProperty("pseudocode_truncated", code.length() > 8192);
                record.addProperty("error", complete ? "" : bounded(result == null ? "No result" : result.getErrorMessage(), 512));
                functions.add(record);
            }
            root.addProperty("functions_truncated", iterator.hasNext());
        } finally {
            decompiler.dispose();
        }
        root.add("functions", functions);
        Files.writeString(Path.of(args[0]), new Gson().toJson(root), StandardCharsets.UTF_8);
    }
}
