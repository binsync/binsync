import logging

from binsync.extras.ai.ai_bs_user import AIBSUser
from binsync.data import Function


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
    
    def run_all_ai_commands_for_dec(self, decompilation: str, func: Function):
        updated_func = self._renaming_api.predict_variable_names(decompilation, func)
        self.controller.push_artifact(updated_func)
        return 1
        #self.controller.schedule_job(
        #    self.controller.push_artifact,
        #    updated_func,
        #    blocking=True
        #)