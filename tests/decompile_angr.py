import angr
from collections import defaultdict
import json
import sys


def parse_binary(binary_path, output_path):
    p = angr.Project(binary_path, load_options={"auto_load_libs": False})
    cfg = p.analyses.CFG(data_references=True, normalize=True)
    p.analyses[angr.analyses.CompleteCallingConventionsAnalysis].prep()(recover_variables=True, analyze_callsites=True)
    
    func_addrs_variables = defaultdict(dict)
    for addr, func in cfg.functions.items():
        try:
            if func.is_plt or func.is_simprocedure or func.alignment:
                continue
            func_addrs_variables[addr]['name'] = func.name
            func_addrs_variables[addr]['variables'] = []
            func_addrs_variables[addr]['arguments'] = []
            decomp = p.analyses.Decompiler(func, cfg=cfg.model)
            if not decomp.codegen:
                continue
            func_addrs_variables[addr]['return_type'] = decomp.codegen.cfunc.functy.returnty.c_repr()
            for idx, (arg_type, arg_cvar) in enumerate(zip(decomp.codegen.cfunc.functy.args, decomp.codegen.cfunc.arg_list)):
                func_addrs_variables[addr]['arguments'].append({"idx": idx, "name": arg_cvar.c_repr(), "type": arg_type.c_repr(), "size": arg_type.size // 8})
            for i in decomp.codegen.cfunc.variables_in_use:
                var = decomp.codegen.cfunc.variable_manager.unified_variable(i)
                var_info = {}
                if hasattr(var, 'name'):
                    var_info['name'] = var.name
                if hasattr(var, 'offset'):
                    var_info['offset'] = var.offset
                if var_info:
                    func_addrs_variables[addr]['variables'].append(var_info)
        except Exception as e:
            print(f"Error! in {hex(addr)}: {e}")
            continue

    with open(output_path, 'w') as f:
        json.dump(dict(func_addrs_variables), f)

if __name__ == "__main__":
    binary_path = sys.argv[1]
    output_path = sys.argv[2]
    parse_binary(binary_path, output_path)
