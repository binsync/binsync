package binsync;

import binsync.BSGhidraServer;

import java.awt.Event;
import javax.swing.KeyStroke;

import docking.action.DockingAction;
import docking.ActionContext;
import docking.action.*;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.Msg;
import resources.ResourceManager;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "BinSync Starter",
	description = "Collab"
)
public class BinSyncPlugin extends ProgramPlugin implements DomainObjectListener {
	private DockingAction configBinSyncAction;
	private String binSyncUIPath;
	private BSGhidraServer server;
	
	public BinSyncPlugin(PluginTool tool) {
		super(tool, true, true);
		
		// API Server
		server = new BSGhidraServer(6683, this);
		
		// Add a BinSync button to 'Tools' in GUI menu
		configBinSyncAction = this.createBinSyncMenuAction();
		tool.addAction(configBinSyncAction);
	}
	
	@Override
	public void init() {
		super.init();
	}

	@Override
	public void dispose() {
		super.dispose();
	}
	
	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
	}
	
	private DockingAction createBinSyncMenuAction() {
		BinSyncPlugin plugin = this;
		configBinSyncAction = new DockingAction("BinSync", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.configureBinSync();
			}
		};
		
		configBinSyncAction.setEnabled(true);
		configBinSyncAction.setMenuBarData(new MenuData(new String[] {"Tools", "Configure BinSync..." }));
		configBinSyncAction.setKeyBindingData(new KeyBindingData(KeyStroke.getKeyStroke('B', Event.CTRL_MASK + Event.SHIFT_MASK)));
		configBinSyncAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/binsync.png")));
		return configBinSyncAction;
	}
	
	/*
	 * BinSync Callers
	 */
	
	private Boolean awaitBinSyncUIConfiguration(int waitTimeMins) {
		// wait a max of 5 mins from now
		long endTime = System.currentTimeMillis() + waitTimeMins*60*1000;
		
		while (System.currentTimeMillis() < endTime) {
			if(this.server.uiConfiguredCorrectly != null)
				return this.server.uiConfiguredCorrectly;
			
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				break;
			}
		} 
		
		return false;
	}
	
	
	private void killServerAfterWait(int waitTimeMins)
	{
		// await 5 minutes for a configuration before quitting
		if(!this.awaitBinSyncUIConfiguration(waitTimeMins))
		{
			Msg.info(this, "bad connection");
			this.server.stop_server();
			return;
		}
		Msg.info(this, "good connection");
	}
	
	private Boolean startBinSyncUI() {
		Msg.info(this, "Starting on binsync --run-plugin ghidra now!");
		try {
			Process process = new ProcessBuilder(
					"binsync", "--run-plugin", "ghidra"
			).start();
		}
		catch (Exception e) {
			Msg.info(this, "Failed to start" + e.toString());
			return false;
		}
		
		Msg.info(this, "Started UI");
		
		return true;
	}
	
	private void configureBinSync() {
		Msg.info(this, "Configuring BinSync...");
		// start the BSGhidraServer
		this.server.start_server();
		
		Msg.info(this, "Server started, now starting UI");
		// start the Python3 UI
		if(!startBinSyncUI())
			return;
		Msg.info(this, "awaiting a connection...");
		new Thread(() -> {
			this.killServerAfterWait(5);
		}).start();
		
	}
	
	/*
	 * Change Event Handler
	 */
	
	
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		int[] program_undo_redo_events = new int[] {
			DomainObject.DO_OBJECT_RESTORED, 
			ChangeManager.DOCR_CODE_REMOVED
		};
		
		int[] cmt_events = new int[] {
			ChangeManager.DOCR_PRE_COMMENT_CHANGED,
			ChangeManager.DOCR_POST_COMMENT_CHANGED,
			ChangeManager.DOCR_EOL_COMMENT_CHANGED,
			ChangeManager.DOCR_PLATE_COMMENT_CHANGED,
			ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED,
			ChangeManager.DOCR_REPEATABLE_COMMENT_REMOVED,
			ChangeManager.DOCR_REPEATABLE_COMMENT_CREATED,
			ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED,
			ChangeManager.DOCR_REPEATABLE_COMMENT_DELETED,
		};
		
		int[] func_events = new int[] {
			ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.DOCR_FUNCTION_BODY_CHANGED,
			ChangeManager.DOCR_VARIABLE_REFERENCE_ADDED,
			ChangeManager.DOCR_VARIABLE_REFERENCE_REMOVED
		};
		
		
		System.out.println("Change detected");
		if (this.eventContains(ev, program_undo_redo_events))
		{
			// reload or undo event has happend
			return;
		}
		
		// check for and handle commend added, comment deleted, and comment changed events
		if (this.eventContains(ev, cmt_events))
		{
			this.handleCmtChanged(ev);
		}
		else if(this.eventContains(ev, func_events))
		{
			System.out.println("Function changed!");
		}
	}
	
	private Boolean eventContains(DomainObjectChangedEvent ev, int[] events) {
		for (int event: events) {
			if (ev.containsEvent(event)) {
				return true;
			}
		}
		return false; 
	}
	
	/*
	 * Comments
	 */
	
	private int getCommentType(int type) {
		if (type == ChangeManager.DOCR_PRE_COMMENT_CHANGED) {
			return CodeUnit.PRE_COMMENT;
		}
		if (type == ChangeManager.DOCR_POST_COMMENT_CHANGED) {
			return CodeUnit.POST_COMMENT;
		}
		if (type == ChangeManager.DOCR_EOL_COMMENT_CHANGED) {
			return CodeUnit.EOL_COMMENT;
		}
		if (type == ChangeManager.DOCR_PLATE_COMMENT_CHANGED) {
			return CodeUnit.PLATE_COMMENT;
		}
		if ((type == ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_REMOVED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_CREATED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_DELETED)) {
			return CodeUnit.REPEATABLE_COMMENT;
		}
		return -1;
	}
	
	private void handleCmtChanged(DomainObjectChangedEvent ev)
	{
		for (DomainObjectChangeRecord record : ev) {
			System.out.println("Comment changed called!");
			
			int type = record.getEventType();
			int commentType = getCommentType(type);
			if (commentType == -1) {
				continue;
			}

			ProgramChangeRecord pRec = (ProgramChangeRecord) record;

			String oldComment = (String) pRec.getOldValue();
			String newComment = (String) pRec.getNewValue();
			Address commentAddress = pRec.getStart();

			// if old comment is null then the change is an add comment so add the comment to the table
			if (oldComment == null) {
				//todo
				assert true;
			}

			// if the new comment is null then the change is a delete comment so remove the comment from the table
			else if (newComment == null) {
				//todo
				assert true;
			}
			// otherwise, the comment is changed so repaint the table
			else {
				//todo
				assert true;
			}
		}
		
	}

	
}
