package binsync;

import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.server.*;
import org.apache.xmlrpc.webserver.WebServer;

import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.table.mapper.ProgramLocationToAddressTableRowMapper;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.flatapi.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.GoToService;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.database.function.LocalVariableDB;

import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.util.data.DataTypeParser; 
import ghidra.util.data.DataTypeParser.AllowedDataTypes; 
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.util.Msg;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.label.RenameLabelCmd;

import binsync.BSGhidraServer;

public class BSGhidraServerAPI {
    private BSGhidraServer server;
	
	public BSGhidraServerAPI(BSGhidraServer server) {
		this.server = server;
	}
	
	/*
	 * Server Manipulation API 
	 */
	
	public Boolean ping() {
		return true;
	}
	
	public Boolean stop() {
		this.server.stop_server();
		return true;
	}
	
	public Boolean alertUIConfigured(Boolean config) {
		this.server.uiConfiguredCorrectly = config;
		return true;
	}
	
	/*
	 * Utils
	 */
	
	private Function getNearestFunction(Address addr) {
		if(addr == null) {
			Msg.warn(this, "Failed to parse Addr string earlier, got null addr.");
			return null;
		}
		
		var program = this.server.plugin.getCurrentProgram();
		var funcManager = program.getFunctionManager();
		var func =  funcManager.getFunctionContaining(addr);
		
		return func;
	}
	
	private Address strToAddr(String addrStr) {
		return this.server.plugin.getCurrentProgram().getAddressFactory().getAddress(addrStr);
	}
	
	private DecompileResults decompileFunction(Function func) {
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(new DecompileOptions());
		ifc.openProgram(this.server.plugin.getCurrentProgram());
		DecompileResults res = ifc.decompileFunction(func, 60, new ConsoleTaskMonitor());
		return res;
	}
	
	private LocalVariableDB getStackVariable(Function func, int offset) {
		for (Variable v : func.getAllVariables()) {
			if(!v.isStackVariable())
				continue;
			
			if(v.getStackOffset() == offset) {
				return (LocalVariableDB) v;
			}
		}
		
		return null;
	}
	
	private DataType parseTypeString(String typeStr)
	{
		var dtService = this.server.plugin.getTool().getService(DataTypeManagerService.class);
		//var anan = AutoAnalysisManager.getAnalysisManager(this.server.plugin.getCurrentProgram()).getDataTypeManagerService();
		var dtParser = new DataTypeParser(dtService, AllowedDataTypes.ALL);
		
		DataType parsedType;
		try {
			parsedType = dtParser.parse(typeStr);
		} catch (Exception ex) {
			parsedType = null;
		}
		
		return parsedType;
	}
	
	private FunctionDefinitionDataType parsePrototypeStr(String protoStr) 
	{
		// string must look something like:
		// 'void function1(int p1, int p2)' 
		var program = this.server.plugin.getCurrentProgram();
		var funcDefn = CParserUtils.parseSignature((ServiceProvider) null, program, protoStr);
		return funcDefn;
	}

	private Address rebaseAddr(Integer addr, Boolean rebaseDown) {
		var program = this.server.plugin.getCurrentProgram();
		var base = (int) program.getImageBase().getOffset();
		Integer rebasedAddr = addr;
		if(rebaseDown) {
			rebasedAddr -= base;
		}
		else if(addr < base) {
			rebasedAddr += base;
		}

		return this.strToAddr(Integer.toHexString(rebasedAddr));
	}

	/*
	 * 
	 * Decompiler API
	 *
	 */
	
	public Map<String, String> context() {
		Map<String, String> retVal = new HashMap<>();
		retVal.put("addr", "0x0");
		retVal.put("name", "");
		
		var currAddr = this.server.plugin.getProgramLocation().getAddress();
		var func = this.getNearestFunction(currAddr);
		if(func != null) {
			retVal.put("name", func.getName());
			currAddr = func.getEntryPoint();
		}

		retVal.put("addr", currAddr.toString());
		return retVal;
	}

	public String baseAddr() {
		return this.server.plugin.getCurrentProgram().getImageBase().toString();
	}

	public String binaryHash() {
		return this.server.plugin.getCurrentProgram().getExecutableMD5();
	}

	public String binaryPath() {
		return this.server.plugin.getCurrentProgram().getExecutablePath();
	}

	public Boolean gotoAddress(String addr) {
		GoToService goToService = this.server.plugin.getTool().getService(GoToService.class);
		goToService.goTo(this.strToAddr(addr));
		return true;
	}

	/*
	 * Functions
	 * useful for function header parsing: https://github.com/extremecoders-re/ghidra-jni
	 */


	public Boolean setFunctionName(String addr, String name) {
		var program = this.server.plugin.getCurrentProgram();
		var func = this.getNearestFunction(this.strToAddr(addr));
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);;
			return false;
		}


		var transID = program.startTransaction("bs-set-func-name");
		try {
			func.setName(name, SourceType.ANALYSIS);
		} catch (DuplicateNameException | InvalidInputException e) {
			System.out.println("Failed in setname: " + e.toString());
			return false;
		} finally {
			program.endTransaction(transID, true);
		}

		return true;
	}

	public Boolean setFunctionRetType(String addr, String typeStr) {
		var parsedType = parseTypeString(typeStr);
		if(parsedType == null) {
			Msg.warn(server, "Failed to parse type string!");;
			return false;
		}

		var program = this.server.plugin.getCurrentProgram();
		var func = this.getNearestFunction(this.strToAddr(addr));
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);;
			return false;
		}


		var transID = program.startTransaction("bs-set-func-ret");
		try {
			func.setReturnType(parsedType, SourceType.ANALYSIS);
		} catch (Exception e) {
			Msg.warn(this, "Failed to do transaction on function settype: " + e.toString());
			return false;
		} finally {
			program.endTransaction(transID, true);
		}
		
		return true;	
	}
	
	public Boolean setFunctionPrototype(String addr, String proto) {
		// Useful code refrences:
		// - https://github.com/NationalSecurityAgency/ghidra/blob/aa299897c6b84e16ecf228d82cf8957a9529b819/Ghidra/Features/Decompiler/src/main/java/ghidra/app/plugin/core/decompile/actions/OverridePrototypeAction.java#L271
		// - https://github.com/NationalSecurityAgency/ghidra/blob/aa299897c6b84e16ecf228d82cf8957a9529b819/Ghidra/Features/Decompiler/src/main/java/ghidra/app/plugin/core/decompile/actions/RetypeLocalAction.java
		//
		// It may actually be impossible to rename or retype just a single param and get propogation without moidifying the signature
		// directly... which sucks. The correct way to do this will be calling getFunctionPrototype(), replacing strings, and setting it back
		// TODO: finish this function!
		
		var parsedProto = parsePrototypeStr(proto);
		if(parsedProto == null) {
			Msg.warn(server, "Failed to parse prototype string!");;
			return false;
		}
		
		var program = this.server.plugin.getCurrentProgram();
		var parsedAddr = this.strToAddr(addr);
		var func = this.getNearestFunction(parsedAddr);
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);;
			return false;
		}
		
		var transID = program.startTransaction("bs-set-func-proto");
		try {
			HighFunctionDBUtil.writeOverride(func, parsedAddr, parsedProto);
		} catch (Exception e) {
			Msg.warn(this, "Failed to do transaction on function settype: " + e.toString());
			return false;
		} finally {
			program.endTransaction(transID, true);
		}
		
		return true;
	}
	
	
	/*
	 * Comments
	 * useful: https://github.com/HackOvert/GhidraSnippets
	 */
	
	public Boolean setComment(String addr, String cmt, Boolean isDecompiled) {
		var program = this.server.plugin.getCurrentProgram();
		var address = this.strToAddr(addr);
		if(address == null) {
			Msg.warn(server, "Failed to parse address!");
			return false;
		}
		
		var cmtType = CodeUnit.EOL_COMMENT;
		if(isDecompiled) {
			cmtType = CodeUnit.PRE_COMMENT;
		}
		
		Boolean success = false;
		var transID = program.startTransaction("bs-set-cmt");
		try {
			var cmd = new SetCommentCmd(address, cmtType, cmt);
			success = cmd.applyTo(program);
		} catch (Exception e) {
			Msg.warn(this, "Failed to do transaction on comment: " + e.toString());
			return success;
		} finally {
			program.endTransaction(transID, true);
		}
		
		return success;
	}
	
	
	/*
	 * Stack Variables
	 */
	
	public Boolean setStackVarType(String addr, String offset, String typeStr) {
		var parsedType = parseTypeString(typeStr);
		if(parsedType == null) {
			Msg.warn(server, "Failed to parse type string!");;
			return false;
		}
		
		var program = this.server.plugin.getCurrentProgram();
		var func = this.getNearestFunction(this.strToAddr(addr));
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);;
			return false;
		}
		
		var v = getStackVariable(func, Integer.decode(offset));
		if(v == null) {
			Msg.warn(server, "Failed to find a stack var by the offset " + offset);
			return false;
		}
		
		
		var transID = program.startTransaction("bs-set-stackvar-type");
		try {
			v.setDataType(parsedType, false, true, SourceType.ANALYSIS);
		} catch (Exception e) {
			Msg.warn(this, "Failed to do transaction on stackvar settype: " + e.toString());
			return false;
		} finally {
			program.endTransaction(transID, true);
		}
		
		return true;	
	}
	
	public Boolean setStackVarName(String addr, String offset, String name) {
		var program = this.server.plugin.getCurrentProgram();
		var func = this.getNearestFunction(this.strToAddr(addr));
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);;
			return false;
		}
		
		var v = getStackVariable(func, Integer.decode(offset));
		if(v == null) {
			Msg.warn(server, "Failed to find a stack var by the offset " + offset);
			return false;
		}
		
		var transID = program.startTransaction("bs-set-stackvar-name");
		try {
			v.setName(name, SourceType.ANALYSIS);
		} catch (DuplicateNameException | InvalidInputException e) {
			Msg.warn(this, "Failed in stackvar setname: " + e.toString());
			return false;
		} finally {
			program.endTransaction(transID, true);
		}
		
		return true;
	}
	

	/*
	 * Global Vars
	 */
	public Boolean setGlobalVarName(String addr, String name) {
		Msg.debug(this, "Attempting to rename global at " + addr + " to " + name);
		var program = this.server.plugin.getCurrentProgram();	
		var symTab = program.getSymbolTable();
		Boolean success = false;
		
		// Loop through symTab to find globals that match addr
		for (Symbol sym: symTab.getAllSymbols(true)) {
			if (sym.getSymbolType() != SymbolType.LABEL) {
				Msg.debug(this, sym.getName(true) + " found: Not a global");
				continue;
			}
			
			Msg.debug(this, "Global " + sym.getName(true) + " found at 0x" + sym.getAddress().toString());
			if (sym.getAddress().equals(this.strToAddr(addr)))
			{
				var transID = program.startTransaction("bs-set-global");
				try {
					var cmd = new RenameLabelCmd(sym, name, SourceType.USER_DEFINED); // SrcType DEFAULT or USER_DEFINED?
					success = cmd.applyTo(program);
				} catch (Exception e) {
					Msg.warn(this, "Failed to rename global var at " + addr + " : " + e.toString());
					return success;
				} finally {
					program.endTransaction(transID, true);
				}
			}
		}
		
		if (!success)
			Msg.warn(this, "Failed to find global var at " + addr);
		
		return success;
	}
	/*
	 * TODO:
	 * Read this to recap on the progress of global vars:
	 * - we have the dict for storing the cache, which we can get all symbols and their addrs
	 * - FOR BINSYNC:
	 * 	- we still need to get the type for each global var, as well as the size if possible
	 * 	- currently we can get a reference to the global_label, but that gets us something 'undefined8' and such 
	 * 	- need to find if we can convert those to the correct type 
	var dm = this.server.plugin.getCurrentProgram().getDataTypeManager();
	var lst = this.server.plugin.getCurrentProgram().getListing();
	var data = lst.getDataAt(this.rebaseAddr(0xdead, false));
	var dType = data.getDataType();
	 */
	// this code is for getting the type of a global variable ^^^
		
	
	/*
	 * Structs
	 */
	
	/*
	 * Enums
	 */
	
	public Map<String, Object> getFunction(String addr) {
		var func = this.getNearestFunction(this.strToAddr(addr));

		// Collect header data from function
		Map<String, Object> header = new HashMap<>();
		header.put("name", func.getName());
		header.put("addr", Integer.decode(addr));
		header.put("type", func.getReturnType().toString());

		// Collect metadata from function
		Map<String, Object> metadata = new HashMap<>();
		metadata.put("addr", Integer.decode(addr));
		metadata.put("size", 0);

		// Add data to the final map
		Map<String, Object> func_data = new HashMap<>();
		func_data.put("metadata", metadata);
		func_data.put("header", header);

		return func_data;
	}

	public Map<String, Map<String, Object>> getFunctions() {
		var program = this.server.plugin.getCurrentProgram();
		var fm = program.getFunctionManager();

		// Iterate through functions and pack data
		Map<String, Map<String, Object>> funcs = new HashMap<>();
		for (Function func: fm.getFunctions(true)) {
			Map<String, Object> func_data = new HashMap<>();
			String addr = "0x"+func.getEntryPoint().toString(false, 0);
			String name = func.getName();
			int size = (int) func.getBody().getNumAddresses();
			func_data.put("name", name);
			func_data.put("size", size);
			funcs.put(addr, func_data);
		}

		return funcs;
	}
	
}
