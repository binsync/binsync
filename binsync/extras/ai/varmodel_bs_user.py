import logging

from binsync.extras.ai.ai_bs_user import AIBSUser
from binsync.data import Function, State


_l = logging.getLogger(__name__)


class VARModelBSUser(AIBSUser):
    DEFAULT_USERNAME = "varmodel_user"

    """
    Variable Annotation Recovery (VAR) Model
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            from varmodel import VariableRenamingAPI
        except ImportError:
            _l.error("VARModel is not installed and is still closed source. You will be unable to use this BinSync user.")
            return

        self._renaming_api = VariableRenamingAPI()
    
    def run_all_ai_commands_for_dec(self, decompilation: str, func: Function, state: State):
        try:
            updated_func: Function = self._renaming_api.predict_variable_names(decompilation, func)
        except Exception as e:
            _l.warning(f"Skipping {func} due to exception {e}")
            return 0

        if updated_func is not None and (updated_func.args or updated_func.stack_vars):
            # count changes
            changes = len(updated_func.args) + len(updated_func.stack_vars)
            state.set_function(updated_func)
            return changes

        return 0
