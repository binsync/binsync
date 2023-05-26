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
            _l.error("VARModel is not installed, you will be unable to use this BinSync user.")
            return

        self._renaming_api = VariableRenamingAPI()
    
    def run_all_ai_commands_for_dec(self, decompilation: str, func: Function, state: State):
        try:
            updated_func: Function = self._renaming_api.predict_variable_names(decompilation, func)
        except Exception as e:
            _l.warning(f"Skipping {func} due to exception {e}")
            return 0

        if updated_func is not None:
            # check for at least one change
            for off, new_sv in updated_func.stack_vars.items():
                if new_sv.name != func.stack_vars[off]:
                    break
            else:
                return 0

            for off, new_arg in updated_func.args.items():
                if new_arg.name != func.args[off]:
                    break
            else:
                return 0

            _l.info(f"Updating variables in {func}...")
            state.set_function(updated_func)
            return 1

        return 0