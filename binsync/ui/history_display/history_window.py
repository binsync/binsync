import logging
from binsync.controller import BSController
from datetime import datetime, timezone, timedelta
from libbs.ui.qt_objects import (
    # QtWidgets
    QDialog,
    QHBoxLayout,
    QVBoxLayout,
    QLabel
)
l = logging.getLogger(__name__)

class HistoryDisplayWidget(QDialog):
    def __init__(self,controller:BSController=None,parent=None):
        super().__init__(parent)
        self.controller = controller
        self._init_widgets()
        self._calculate_diff()
        
    def _init_widgets(self):
        self.setWindowTitle("History")
        
        main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        bottom_layout = QVBoxLayout()
        
        top_layout.addWidget(QLabel("top"))
        bottom_layout.addWidget(QLabel("bottom"))
        
        
        main_layout.addLayout(top_layout)
        main_layout.addLayout(bottom_layout)
        
        self.setLayout(main_layout)
        self.resize(1000, 800)
        
    def _calculate_diff(self):
        changed_functions = []
        client = self.controller.client
        previous_time =  (datetime.now(timezone.utc)-timedelta(days=1)).timestamp()
        old_commit = client.find_commit_before_ts(client.repo, previous_time,user_name=client.master_user)
        old_state = client.parse_state_from_commit(client.repo,commit_hash=old_commit)
        curr_state = self.controller.get_state()
        for addr, new_function in curr_state.functions.items():
            if addr not in old_state.functions:
                # Is this case possible?
                changed_functions.append(new_function)
            else:
                diffs = self._get_function_diffs(curr_state,old_state,addr)
                for diff_dict in diffs.values():
                    if diff_dict["master"] != diff_dict["target"]:
                        changed_functions.append(new_function)
                        l.info(diffs)
                        break
        for function in changed_functions:
            l.info(function)
    
    def _get_function_diffs(self,state1, state2, addr)->dict[str,dict[str,any]]:
        '''
        Copied from BSController.preview_function_changes
        
        Returns the diffs between a function at an address given two different states.
        
        @returns A Dict containing name, args, type, stack_vars, and comments that each map to a dict.
        Each mapped dict contains an entry for the first function "master" and the second function "target".
        '''
        get_comments = lambda state_obj: {addr: cmt.comment for addr, cmt in state_obj.get_func_comments(addr).items()}
        func1 = state1.functions[addr]
        func2 = state2.functions[addr]
        def get_header_attr(func, attr):
            return getattr(func.header, attr, None) if func and func.header else None
        diffs = {
            'name': {
                'master': func1.name if func1 else None,
                'target': func2.name if func2 else None
            },
            'args': {
                'master': get_header_attr(func1, 'args') or {},
                'target': get_header_attr(func2, 'args') or {}
            },
            'type': {
                'master': get_header_attr(func1, 'type'),
                'target': get_header_attr(func2, 'type')
            },
            'stack_vars': {
                'master': func1.stack_vars if func1 else {},
                'target': func2.stack_vars if func2 else {}
            },
            'comments': {
                'master': get_comments(state1),
                'target': get_comments(state2)
            }
        }
        return diffs
                