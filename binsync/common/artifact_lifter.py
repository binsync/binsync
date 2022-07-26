import logging

from binsync.data.artifact import Artifact
from binsync.data.type_parser import BSTypeParser, BSType

_l = logging.getLogger(name=__name__)


class ArtifactLifter:
    def __init__(self, controller, types=None):
        self.controller = controller
        self.type_parser = BSTypeParser(extra_types=types)

    #
    # Public API
    #

    def lift(self, artifact: Artifact):
        return self._lift_or_lower_artifact(artifact, "lift")

    def lower(self, artifact: Artifact):
        return self._lift_or_lower_artifact(artifact, "lower")

    #
    # TODO: deprecate these and standardize property names
    #

    def lift_ret_type(self, type_str):
        return self.lift_type(type_str)

    def lower_ret_type(self, type_str):
        return self.lower_type(type_str)

    def lift_type_str(self, type_str):
        return self.lift_type(type_str)

    def lower_type_str(self, type_str):
        return self.lower_type_str(type_str)

    #
    # Override Mandatory Funcs
    #

    def lift_type(self, type_str: str) -> str:
        #raise NotImplementedError
        print("lift type called")

    def lift_addr(self, addr: int) -> int:
        #raise NotImplementedError
        print("lift addr called")

    def lift_stack_offset(self, offset: int) -> int:
        #raise NotImplementedError
        print("lift stack off called")

    def lower_type(self, type_str: str) -> str:
        #raise NotImplementedError
        print("lower type called")

    def lower_addr(self, addr: int) -> int:
        #raise NotImplementedError
        print("lower addr called")

    def lower_stack_offset(self, offset: int) -> int:
        #raise NotImplementedError
        print("lower stack off called")

    #
    # Private
    #

    def _lift_or_lower_artifact(self, artifact, mode):
        target_attrs = ("ret_type", "type_str", "type", "stack_offset", "addr")
        if mode not in ("lower", "lift"):
            return None

        lifted_art = artifact.copy()

        # correct simple properties in the artifact
        for attr in target_attrs:
            if hasattr(lifted_art, attr):
                curr_val = getattr(lifted_art, attr)
                if not curr_val:
                    continue

                lifting_func = getattr(self, f"{mode}_{attr}")
                setattr(lifted_art, attr, lifting_func(curr_val))

        # recursively correct nested artifacts
        for attr in lifted_art.__slots__:
            attr_val = getattr(lifted_art, attr)
            if not attr_val:
                continue

            # nested function headers
            if attr == "header":
                setattr(lifted_art, attr, self._lift_or_lower_artifact(attr_val, mode))
            # nested args, stack_vars, or struct_members
            elif isinstance(attr_val, dict):
                nested_arts = {
                    k: self._lift_or_lower_artifact(v, mode) for k, v in attr_val.items()
                }
                setattr(lifted_art, attr, nested_arts)

        return lifted_art

