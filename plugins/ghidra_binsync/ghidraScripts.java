/*
 * LICENSE
 */
// Description
//@author Tristan B
//@category Skeleton
//@keybinding
//@menupath Skeleton
//@toolbar Skeleton

import java.awt.event.*;
import java.awt.event.WindowAdapter.*;
import java.awt.event.WindowListener;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import javax.swing.*;
import java.io.*;
import java.net.http.*;
import java.net.URI;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;

import ghidra.util.task.ConsoleTaskMonitor;

import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.flatapi.*;

import java.io.*;
import java.util.*;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.net.http.*;
import java.util.HashMap;


// ==================== MAHALOZ ADDED CODE ======================= //
class ReturnMsg
{
    public static final String BAD_ARGS = "There were not enough args in this request";
    public static final String NO_SYNC_REPO = "Not connected to a sync repo";
    public static final String CONNECTED_NO_USER = "Connected, but not initialized to a user yet";
    public static final String CONNECTED = "Connected: ";
    public static final String PULL_SUCCESS = "Successfully pulled: ";
    public static final String SERVER_STOPPED = "Server Stopped";
}

class BinsyncController
{
    final String REQ_URL = "http://127.0.0.1:5000";
    String masterUsername;
    String repoPath;
	String serverPath;
    Process client;
    HttpClient httpClient;

    public BinsyncController(String masterUsername, String repoPath, String serverPath)
    {
        this.masterUsername = masterUsername;
        this.repoPath = repoPath;
		this.serverPath = serverPath;
        this.client = null;
        this.httpClient = HttpClient.newHttpClient();
    }

    public void connect()
    {
        System.out.println("[+] Connecting to BinSync Server..."); 
        Process exec = null;
        try {
            String[] args = {"python3", this.serverPath, this.masterUsername, this.repoPath};
            this.client = Runtime.getRuntime().exec(args);
        } catch(IOException e) {
            e.printStackTrace();
            this.client = exec;
        }
        
        try {
            Thread.sleep(3 * 1000);
        } catch(InterruptedException e) {
            System.out.println("Interrupted");
        }
        
        System.out.println("[+] Connected!"); 
    }

    public List<String> users()
    {
        HttpResponse<String> response = null;
        List<String> userList = null;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(this.REQ_URL + "/users"))
            .build();
        try {
            response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());    
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed");
            return null; 
        }
        
        String out = response.body().toString().replace("\"", "").replace("\n", "");
        switch(out)
        {
            case ReturnMsg.CONNECTED_NO_USER:   
                System.out.println("NO USER CONNECTED"); 
                return null;
            case ReturnMsg.NO_SYNC_REPO:
                System.out.println("NO SYNC CONNECTED"); 
                return null;
        }

        userList = new ArrayList<String>(Arrays.asList(out.split(",")));
        return userList;
    }

    public boolean pull(String username)
    {
        HttpResponse<String> response = null;

        // send the request
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(this.REQ_URL + "/pull"))
            .POST(HttpRequest.BodyPublishers.ofString("user="+username))
            .setHeader("User-Agent", "BinSync Bot")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .build();
        try {
            response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());    
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed");
            return false; 
        }
        
        String out = response.body().toString().replace("\"", "").replace("\n", "");
        switch(out)
        {
            case ReturnMsg.CONNECTED_NO_USER:   
                System.out.println("NO USER CONNECTED"); 
                return false;
            case ReturnMsg.NO_SYNC_REPO:
                System.out.println("NO SYNC CONNECTED"); 
                return false;
        }
        System.out.println(out);
        return true;
    }

    private boolean stopServer()
    {
        HttpResponse<String> response = null;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(this.REQ_URL + "/stop"))
            .build();
        try {
            response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());    
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed");
            return false;
        }
        
        String out = response.body().toString().replace("\"", "").replace("\n", "");
        switch(out)
        {
            case ReturnMsg.CONNECTED_NO_USER:   
                System.out.println("NO USER CONNECTED"); 
                return false;
            case ReturnMsg.NO_SYNC_REPO:
                System.out.println("NO SYNC CONNECTED"); 
                return false;
        }
        return true;
    }

    public void kill()
    {
        this.stopServer();
        this.client.destroy();        
    }

    private static HttpRequest.BodyPublisher buildFormDataFromMap(Map<Object, Object> data) {
        var builder = new StringBuilder();
        for (Map.Entry<Object, Object> entry : data.entrySet()) {
            if (builder.length() > 0) {
                builder.append("&");
            }
            builder.append(URLEncoder.encode(entry.getKey().toString(), StandardCharsets.UTF_8));
            builder.append("=");
            builder.append(URLEncoder.encode(entry.getValue().toString(), StandardCharsets.UTF_8));
        }
        System.out.println(builder.toString());
        return HttpRequest.BodyPublishers.ofString(builder.toString());
    }
}

// ==================== MAHALOZ ADDED CODE END ======================= //


public class ghidraScripts extends GhidraScript {

	public JFrame frame;
	private javax.swing.JList<String> ListOfConnectedPeople;
    private javax.swing.JButton PushButton;
    private javax.swing.JButton SyncButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JScrollPane jScrollPane1;

	// ---- PUT CONFIG HERE ---- //
	public String syncRepoPath = "/Users/tristanbrigham/GithubProjects/ASUInternship/sync_test";
	public String syncServerPath = "/Users/tristanbrigham/GithubProjects/ASUInternship/binsync/plugins/ghidra_binsync/binsync_server.py";
	public String masterUser = "tristan";

	// defaults
	public String tempAddr = "001011b0";
	public String [] connectedUsers = {"default_display"};
	public String selectedUser = "";

	BinsyncController controller = null;

	@Override
	protected void run() {
		// connect to binsync
		System.out.println("[+] Starting plugin...");
        this.controller = new BinsyncController(masterUser, syncRepoPath, syncServerPath);
        this.controller.connect();
		List<String> userList = this.controller.users();
		if(userList != null)
			this.connectedUsers = userList.toArray(new String[0]);


		// new PluginWindow().setVisible(true);
		initComponents();

	}
	

	private void SyncButtonMouseClicked() {
		if(this.selectedUser.equals("") || this.controller == null)
			return;
		
		this.controller.pull(this.selectedUser);
		rename_functions_from_file();
		// TODO:
		// 1. simply read a file from /this.repoPath/functions/<func_addr>.toml
		// 2. get the new function name from the file
		// 3. rename it!
		
		// rename_stack_var(toAddr(tempAddr), -0x10, "LOCAL_VAR");
		// println(get_all_func_names().toString());
		// rename_func(toAddr(tempAddr), "ENTRY_FUNCTION");
		// find_pointer(-0x10);
		// get_comments(toAddr(tempAddr), false);
	}

	private void rename_functions_from_file() {
		HashMap<Address, String> functions_map = get_functions_file();
		Iterator it = functions_map.entrySet().iterator();
		
		for(Address addr : functions_map.keySet()) {
			String name = functions_map.get(addr);
			rename_func(addr, name);
		}
	}

	public HashMap<Address, String> get_functions_file() {
		HashMap<Address, String> ret = new HashMap<>();

		try{
			FileReader file = new FileReader(syncRepoPath + "/functions.toml");

			int i;
			String information = "";
			Address addr = toAddr("");
			String name = "";
			Scanner scan = new Scanner(file);
			boolean waitingName = false;

			while (scan.hasNextLine()) {
				String line = scan.nextLine();
				// println(line);
				information += line;
				if(line.length() > 4) {
					if (line.substring(0, 4).contains("addr") && !waitingName) {
						addr = toAddr(line.substring(7));
						println("ADDRESS: " + addr);
						waitingName = true;
					}
					else if (line.substring(0, 4).contains("name") && waitingName) {
						name = line.substring(line.indexOf("\"") + 1, line.lastIndexOf("\""));
						println("NAME: " + name);
						ret.put(addr, name);
						println("");
						waitingName = false;
					}
				}
			}
		} catch (Exception e) {
			println(e.getMessage());
			e.printStackTrace();
		} 
		return ret;
	}

	private void PushButtonActionPerformed() {
		println("Pushing!");
	}

	private void LOCPMouseClicked(MouseEvent e) {
		int row = ListOfConnectedPeople.locationToIndex(e.getPoint());
		ListOfConnectedPeople.setSelectedIndex(row);
		selectedUser = ListOfConnectedPeople.getSelectedValue();
		println("CLICKED: " + selectedUser);
	}

	public  void rename_stack_var(Address func_addr, int stack_offset, String new_name) {

		try {
			boolean found = false;
			FunctionManager functionManager = currentProgram.getFunctionManager();
			FunctionIterator functions = functionManager.getFunctions(true);
			for (Function function : functions) {
				if(!function.getEntryPoint().equals(func_addr)) continue;
				DecompInterface ifc = new DecompInterface();
				ifc.setOptions(new DecompileOptions());
				ifc.openProgram(function.getProgram());
				DecompileResults res = ifc.decompileFunction(function, 60, new ConsoleTaskMonitor());
				for (Variable v : res.getFunction().getAllVariables()) {
					if(v.getStackOffset() == stack_offset) {
						v.setName(new_name, SourceType.ANALYSIS);
						println("FOUND THE OFFSET VARIABLE!");
						found = true;
						break;
					}
				}
			}
			if (!found) {
				println("Didn't find variable with specified stack offset");
			}
		} catch(Exception e) {
			e.printStackTrace();
		} 
	}


	public List get_all_func_names() {
		List<String> ret = new ArrayList<String>();
		try {
			FunctionManager functionManager = currentProgram.getFunctionManager();
			FunctionIterator functions = functionManager.getFunctions(true);
			for (Function function : functions) {
				ret.add(function.getName());
			}
		} catch(Exception e) {
			e.printStackTrace();
		} finally{
			return ret;
		}
	}


	private void rename_func(Address func_addr, String new_name) {
		try {
			FunctionManager functionManager = currentProgram.getFunctionManager();
			FunctionIterator functions = functionManager.getFunctions(true);
			for (Function function : functions) {
				if (function.getEntryPoint().equals(func_addr)) {
					function.setName(new_name, SourceType.ANALYSIS);
				}
			}
		} catch(Exception e) {
			e.printStackTrace();
		} 
	}



	private void find_pointer(int offset) {
		boolean found = false;

		try{
			FunctionManager functionManager = currentProgram.getFunctionManager();
			FunctionIterator functions = functionManager.getFunctions(true);
			for (Function function : functions) {
				function.setName(function.getName().substring(5), SourceType.ANALYSIS);
				DecompInterface ifc = new DecompInterface();
				ifc.setOptions(new DecompileOptions());
				ifc.openProgram(function.getProgram());
				DecompileResults res = ifc.decompileFunction(function, 60, new ConsoleTaskMonitor());
				for (Variable v : res.getFunction().getAllVariables()) {
					if(v.getStackOffset() == offset) {
						println("\n\nFOUND IN FUNCTION: " + function.getName() + " @ 0x" + function.getEntryPoint());
						println("Symbol: " + v.getName() + " offset " + v.getStackOffset());
						found = true;
						break;
					}
				}
			}
			if (!found) {
				println("Didn't find variable with specified stack offset");
			}
		} catch(Exception e) {
			e.printStackTrace();
		} 
	}

	public HashMap<Address, String> get_comments(Address func_addr, boolean decompiler) {
		HashMap<Address, String> ret = new HashMap<>();

		try {

			FunctionManagerDB functionManagerDB = (FunctionManagerDB) currentProgram.getFunctionManager();
			Function function = functionManagerDB.getFunctionAt(func_addr);
			AddressSetView set = function.getBody();
			AddressIterator iterator = set.getAddresses(true);

			FlatProgramAPI api = new FlatProgramAPI(currentProgram);

			for (Address address : iterator) {
				String fullComments = "";
				if (api.getEOLComment(address) != null && !decompiler) {
					fullComments += "\nEOL COMMENT: " + api.getEOLComment(address);
				}
				if (api.getPlateComment(address) != null) {
					fullComments += "\nPLATE COMMENT: " + api.getPlateComment(address);
				}
				if (api.getPreComment(address) != null) {
					fullComments += "\nPRE COMMENT: " + api.getPreComment(address);
				}
				if (api.getPostComment(address) != null && !decompiler) {
					fullComments += "\nPOST COMMENT: " + api.getPostComment(address);
				}
				/*
				if (api.getRepeatableComment(address) != null && !decompiler) {
					fullComments += "\nREPEATABLE COMMENT: " + api.getRepeatableComment(address);
				}
				*/

				ret.put(address, fullComments);
			}

		} catch(Exception e) {
			e.printStackTrace();
		} finally {
			return ret;
		}

	}
	//___________________________________________________________________________________________
	//___________________________________________________________________________________________
	// _______________________________INITIALIZING THE COMPONENTS OF THE BOX_____________________
	//___________________________________________________________________________________________
	//___________________________________________________________________________________________

	private void initComponents () {

		frame = new JFrame();
		jLabel1 = new javax.swing.JLabel();
        SyncButton = new javax.swing.JButton();
        PushButton = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        ListOfConnectedPeople = new javax.swing.JList<>();
        jLabel2 = new javax.swing.JLabel();

        frame.setBackground(new java.awt.Color(255, 102, 102));
		frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

        jLabel1.setForeground(new java.awt.Color(0, 153, 0));
        jLabel1.setText("Status: CONNECTED");

        SyncButton.setText("Sync");
        SyncButton.addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                SyncButtonMouseClicked();
            }
        });

        PushButton.setText("Push");
        PushButton.addActionListener(new java.awt.event.ActionListener() {
			@Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PushButtonActionPerformed();
            }
        });

        ListOfConnectedPeople.setModel(new javax.swing.AbstractListModel<String>() {
            String[] strings = connectedUsers;
            public int getSize() { return strings.length; }
            public String getElementAt(int i) { return strings[i]; }
        });
        ListOfConnectedPeople.addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                LOCPMouseClicked(evt);
            }
        });
        jScrollPane1.setViewportView(ListOfConnectedPeople);

        jLabel2.setFont(new java.awt.Font("Lucida Grande", 0, 20)); // NOI18N
        jLabel2.setText("TEAM:");

		javax.swing.GroupLayout layout = new javax.swing.GroupLayout(frame.getContentPane());
        frame.getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(SyncButton, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(PushButton, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(137, 137, 137)
                        .addComponent(jLabel1))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(50, 50, 50)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel2)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 300, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 39, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(13, 13, 13)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 174, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 31, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(SyncButton)
                    .addComponent(PushButton))
                .addGap(34, 34, 34))
        );

		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		WindowListener exitListener = new WindowAdapter() {

			@Override
			public void windowClosing(WindowEvent e) {
				controller.kill();
			}
		};

		frame.addWindowListener(exitListener);


        frame.pack();

		frame.setVisible(true);
	}

	//___________________________________________________________________________________________
	//___________________________________________________________________________________________
	//______________________________ANCILLARY FUNCTIONS FOR TESTING______________________________
	//___________________________________________________________________________________________
	//___________________________________________________________________________________________


	public void renameAllFunctions() {
		int id = currentProgram.startTransaction("Set string translated value");
		try {
			FunctionManager functionManager = currentProgram.getFunctionManager();
			FunctionIterator functions = functionManager.getFunctions(true);
			for (Function function : functions) {
				function.setName("FAKE_" + function.getName(), SourceType.DEFAULT);
				println("Function: " + function.getName());
			}
		} catch(Exception e) {
			println(e.getMessage().toString());
			println("AN ERROR OCCURRED");
		} finally {
			println("FUNCTIONS RENAMED");
			currentProgram.endTransaction(id, true);
		}
	}


	public void resetAllFunctions() {
		int id = currentProgram.startTransaction("Set string translated value");
		try {
			FunctionManager functionManager = currentProgram.getFunctionManager();
			FunctionIterator functions = functionManager.getFunctions(true);
			for (Function function : functions) {
				function.setName(function.getName().substring(5), SourceType.DEFAULT);
				println("Function: " + function.getName());
			}
		} catch(Exception e) {
			println(e.getMessage().toString());
			println("AN ERROR OCCURRED");
		} finally {
			println("FUNCTIONS RENAMED");
			currentProgram.endTransaction(id, true);
		}
	}
}