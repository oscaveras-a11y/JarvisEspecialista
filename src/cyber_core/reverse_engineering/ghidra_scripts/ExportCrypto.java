// Fixed trusted exporter. Exports addresses and allowlisted rule IDs only.
// @category CyberCore
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import com.google.gson.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;

public class ExportCrypto extends HeadlessScript {
    private JsonArray output=new JsonArray();
    private boolean truncated=false;
    private Set<String> seen=new HashSet<>();
    private void incoming(Address target,String rule) throws Exception {
        ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(target);
        int visited=0;
        while(it.hasNext()&&!monitor.isCancelled()){
            if(++visited>100000){truncated=true;break;}
            Reference ref=it.next();
            Function function=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if(function==null||function.isExternal())continue;
            String key=ref.getFromAddress().toString()+":"+rule+":"+target.toString();
            if(!seen.add(key))continue;
            if(output.size()>=256){truncated=true;break;}
            JsonObject record=new JsonObject();
            record.addProperty("from",ref.getFromAddress().toString());
            record.addProperty("target",target.toString());
            record.addProperty("function",function.getEntryPoint().toString());
            record.addProperty("rule",rule);
            output.add(record);
        }
        if(monitor.isCancelled())truncated=true;
    }
    @Override protected void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2||currentProgram==null)throw new IllegalArgumentException("Expected trusted options");
        JsonObject options=JsonParser.parseString(Files.readString(Path.of(args[1]),StandardCharsets.UTF_8)).getAsJsonObject();
        for(JsonElement item:options.getAsJsonArray("targets")){
            JsonObject target=item.getAsJsonObject();
            long offset=Long.parseUnsignedLong(target.get("address").getAsString());
            incoming(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset),target.get("rule").getAsString());
        }
        Set<String> apis=new HashSet<>();
        for(JsonElement name:options.getAsJsonArray("apis"))apis.add(name.getAsString());
        SymbolIterator symbols=currentProgram.getSymbolTable().getAllSymbols(true);
        int visited=0;
        while(symbols.hasNext()&&!monitor.isCancelled()){
            if(++visited>100000){truncated=true;break;}
            Symbol symbol=symbols.next();
            String name=symbol.getName();
            if(apis.contains(name))incoming(symbol.getAddress(),"api."+name+".v1");
        }
        JsonObject root=new JsonObject();
        root.addProperty("backend_version",Application.getApplicationVersion());
        root.addProperty("analysis_timed_out",analysisTimeoutOccurred());
        root.addProperty("truncated",truncated||monitor.isCancelled());
        root.add("references",output);
        Files.writeString(Path.of(args[0]),new Gson().toJson(root),StandardCharsets.UTF_8);
    }
}
