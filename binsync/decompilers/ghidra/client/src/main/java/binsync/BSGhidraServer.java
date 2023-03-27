package binsync;

import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.server.*;
import org.apache.xmlrpc.webserver.WebServer;

import ghidra.Ghidra;

import binsync.BinSyncPlugin;
import binsync.BSGhidraServerAPI;
import binsync.BSGhidraProcessorFactoryFactory;


public class BSGhidraServer {
    public BinSyncPlugin plugin;
    public BSGhidraServerAPI api;
    private WebServer server;
    public Boolean uiConfiguredCorrectly;
    
    public int port;
    
    public BSGhidraServer(int port, BinSyncPlugin plugin)
    {
        this.server = new WebServer(port);
    	this.plugin = plugin;
    	this.uiConfiguredCorrectly = null;
    	this.port = port;
    	
        PropertyHandlerMapping phm = new PropertyHandlerMapping();
        api = new BSGhidraServerAPI(this);
        phm.setRequestProcessorFactoryFactory(new BSGhidraProcessorFactoryFactory(api));
        phm.setVoidMethodEnabled(true);
        
        try {
			phm.addHandler("bs", BSGhidraServerAPI.class);
			this.server.getXmlRpcServer().setHandlerMapping(phm);
		} catch (XmlRpcException e) {
    		System.out.println("Error in phm config: " + e);
			this.server = null;
		}
    }
    
    public Boolean start_server() {
    	if(this.server == null) {
    		System.out.println("Null server man");
    		return false;
    	}
    	
    	try {
    		this.server.start();
    		return true;
    	} catch (Exception exception){
    		System.out.println("Error starting Server: " + exception);
    		return false;
       }
    }
    
    public Boolean stop_server() {
    	if(this.server == null)
    		return false;
    	
    	this.server.shutdown();
    	return true;
    }
}
