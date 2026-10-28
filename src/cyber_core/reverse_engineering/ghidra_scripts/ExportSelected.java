// Trusted exporter: static model only. No evidence-supplied scripts.
// @category CyberCore
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import com.google.gson.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class ExportSelected extends HeadlessScript {
    private JsonObject options;
    private String cut(String s,int n){return s==null?"":s.substring(0,Math.min(n,s.length()));}
    private int budget(String name){return options.get(name).getAsInt();}
    private boolean selected(Function f){
        String name=f.getName(), qualified=f.getName(true);
        for(JsonElement q:options.getAsJsonArray("names"))
            if(q.getAsString().equals(name)||q.getAsString().equals(qualified)) return true;
        long at=f.getEntryPoint().getOffset();
        for(JsonElement q:options.getAsJsonArray("addresses"))
            if(at==q.getAsLong()) return true;
        for(JsonElement q:options.getAsJsonArray("ranges")){
            JsonArray range=q.getAsJsonArray();
            if(Long.compareUnsigned(at,range.get(0).getAsLong())>=0 &&
               Long.compareUnsigned(at,range.get(1).getAsLong())<0) return true;
        }
        return false;
    }
    private void reference(JsonArray refs,Reference ref,String direction){
        JsonObject r=new JsonObject();
        r.addProperty("from",cut(ref.getFromAddress().toString(),64));
        r.addProperty("to",cut(ref.getToAddress().toString(),64));
        r.addProperty("type",cut(ref.getReferenceType().toString(),64));
        r.addProperty("direction",direction);
        r.addProperty("call",ref.getReferenceType().isCall());
        Symbol symbol=currentProgram.getSymbolTable().getPrimarySymbol(ref.getToAddress());
        r.addProperty("symbol",symbol==null?"":cut(symbol.getName(true),256));
        refs.add(r);
    }
    private JsonObject export(Function f,DecompInterface decompiler) throws Exception {
        JsonObject record=new JsonObject();
        record.addProperty("address",cut(f.getEntryPoint().toString(),64));
        record.addProperty("name",cut(f.getName(true),256));
        DecompileResults result=decompiler.decompileFunction(f,budget("decompile_seconds"),monitor);
        boolean complete=result!=null&&result.decompileCompleted()&&result.getDecompiledFunction()!=null;
        String code=complete?result.getDecompiledFunction().getC():"";
        record.addProperty("status",complete?"decompiled":"failed");
        record.addProperty("pseudocode",cut(code,budget("pseudocode_chars")));
        record.addProperty("pseudocode_truncated",code.length()>budget("pseudocode_chars"));
        record.addProperty("error",complete?"":cut(result==null?"No result":result.getErrorMessage(),512));
        JsonArray refs=new JsonArray();
        ReferenceIterator incoming=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        while(incoming.hasNext()&&refs.size()<budget("max_references")&&!monitor.isCancelled())
            reference(refs,incoming.next(),"incoming");
        boolean truncated=incoming.hasNext();
        InstructionIterator instructions=currentProgram.getListing().getInstructions(f.getBody(),true);
        int scanned=0;
        while(instructions.hasNext()&&scanned<budget("max_scan_instructions")&&
              refs.size()<budget("max_references")&&!monitor.isCancelled()){
            Instruction instruction=instructions.next();
            scanned++;
            for(Reference ref:instruction.getReferencesFrom()){
                if(refs.size()>=budget("max_references")){truncated=true;break;}
                reference(refs,ref,"outgoing");
            }
        }
        truncated|=instructions.hasNext();
        record.add("references",refs);
        record.addProperty("references_truncated",truncated);
        return record;
    }
    @Override protected void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2||currentProgram==null) throw new IllegalArgumentException("Expected output and trusted selection");
        options=JsonParser.parseString(Files.readString(Path.of(args[1]),StandardCharsets.UTF_8)).getAsJsonObject();
        JsonObject root=new JsonObject();
        root.addProperty("backend_version",Application.getApplicationVersion());
        root.addProperty("language_id",currentProgram.getLanguageID().toString());
        root.addProperty("compiler_spec",currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        root.addProperty("image_base",currentProgram.getImageBase().toString());
        root.addProperty("analysis_timed_out",analysisTimeoutOccurred());
        JsonArray functions=new JsonArray();
        JsonObject matches=new JsonObject();
        for(JsonElement name:options.getAsJsonArray("names")) matches.addProperty(name.getAsString(),0);
        DecompInterface decompiler=new DecompInterface();
        FunctionIterator iterator=currentProgram.getFunctionManager().getFunctions(true);
        int visited=0,total=0;
        try {
            if(!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Cannot open decompiler");
            while(iterator.hasNext()&&visited<100000&&!monitor.isCancelled()){
                Function f=iterator.next();visited++;
                if(f.isExternal()||!selected(f)) continue;
                total++;
                for(String name:matches.keySet())
                    if(name.equals(f.getName())||name.equals(f.getName(true)))
                        matches.addProperty(name,matches.get(name).getAsInt()+1);
                if(functions.size()<budget("max_functions")) functions.add(export(f,decompiler));
            }
        } finally {decompiler.dispose();}
        root.addProperty("functions_truncated",total>functions.size());
        root.addProperty("selection_scan_truncated",iterator.hasNext()||monitor.isCancelled());
        root.addProperty("visited_functions",visited);
        root.addProperty("matched_functions",total);
        root.add("name_matches",matches);
        root.add("functions",functions);
        Files.writeString(Path.of(args[0]),new Gson().toJson(root),StandardCharsets.UTF_8);
    }
}
