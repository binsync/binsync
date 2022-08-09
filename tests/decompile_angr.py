import angr
import os
import time
import signal
from multiprocessing import Manager
import logging
import nose.tools
from collections import defaultdict
import re
import json
import sys


def signal_handler(signum, frame):
    raise Exception("Timed out!")


def parse_binary(binary_path, output_path):
    
    func_addr = defaultdict(dict)

    bin_path = os.path.join(os.path.realpath(binary_path))
    p = angr.Project(bin_path, load_options={
        "load_debug_info":True,
        "auto_load_libs": False,
        })
    cfg = p.analyses.CFG(data_references=True, normalize=True)
    
    tmp_kb = angr.KnowledgeBase(p)   
    
    func_addrs_variables = defaultdict(list)
    for k ,v in cfg.functions.items():
        tmp_var = []

        try:
            # import ipdb; ipdb.set_trace()

            # timeout
            signal.signal(signal.SIGALRM, signal_handler)
            signal.alarm(40)
            dec = p.analyses.Decompiler(v, cfg=cfg.model, variable_kb=tmp_kb)
            code_g = dec.codegen
            if code_g:
                tmp_code = code_g.text
               
                # get variables
                var_list = tmp_kb.variables[k].get_variables()
                if var_list and v.is_plt is False:
                    for var in var_list:
                        var_name = tmp_kb.variables[k].unified_variable(var).name
                        tmp_var.append(var_name)
                    func_addrs_variables[k] = tmp_var
        
        except Exception as e:
            print(f"Error! in {k} {e}")
            continue

    dump(output_path, func_addrs_variables)


def dump(output_path, func_addrs_variables):

    for k, v in func_addrs_variables.items():
        print(f"func addr: {k} | variables: {v}") 
    with open(output_path, 'w') as w:
        w.write(json.dumps(dict(func_addrs_variables)))


if __name__ == "__main__":

    binary_path = sys.argv[1]
    output_path = sys.argv[2]
    manager = Manager()
    parse_binary(binary_path, output_path)
    
  
