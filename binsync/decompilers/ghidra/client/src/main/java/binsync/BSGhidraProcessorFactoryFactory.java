package binsync;

import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.server.*;
import org.apache.xmlrpc.XmlRpcRequest;
import org.apache.xmlrpc.webserver.WebServer;
import org.python.bouncycastle.crypto.util.CipherKeyGeneratorFactory;

import binsync.BSGhidraServerAPI;

public class BSGhidraProcessorFactoryFactory implements RequestProcessorFactoryFactory {
	private final RequestProcessorFactory factory = new BSGhidraProcessorFactory();
	private final BSGhidraServerAPI api;

	public BSGhidraProcessorFactoryFactory(BSGhidraServerAPI api) {
		this.api = api;
	}

	public RequestProcessorFactory getRequestProcessorFactory(Class aClass) 
			throws XmlRpcException {
		return factory;
	}

	private class BSGhidraProcessorFactory implements RequestProcessorFactory {
		public Object getRequestProcessor(XmlRpcRequest xmlRpcRequest)
				throws XmlRpcException {
			return api;
		}
	}

}
