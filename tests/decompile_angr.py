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

def main(binary):
    
    func_addr = defaultdict(dict)

    bin_path = os.path.join(os.path.realpath(binary))
    p = angr.Project(bin_path, load_options={
        "load_debug_info":True,
        "auto_load_libs": False,
        })
    cfg = p.analyses.CFG(data_references=True, normalize=True)
    
    tmp_kb = angr.KnowledgeBase(p)   
    
    func_addrs_variables = defaultdict(list)
    for k ,v in cfg.functions.items():
        tmp_var = []
        # timeout
        signal.signal(signal.SIGALRM, signal_handler)
        signal.alarm(40)

        try:
            # import ipdb; ipdb.set_trace()
            dec = p.analyses.Decompiler(v, cfg=cfg.model, variable_kb = tmp_kb)  
            code_g = dec.codegen
            if code_g:
                tmp_code = code_g.text
               
                # get variables
                var_list = tmp_kb.variables[k].get_variables()
                if var_list and v.is_plt == False:
                    for var in var_list:
                        var_name = tmp_kb.variables[k].unified_variable(var).name
                        tmp_var.append(var_name)
                    func_addrs_variables[k] = tmp_var
        
        except Exception as e:
            print(f"Error! in {k} {e}")
            continue

    pp(func_addrs_variables)

def pp(func_addrs_variables):
    
    for k, v in func_addrs_variables.items():
        print(f"func addr: {k} | variables: {v}") 
    with open('addrs_vars.json', 'w') as w:
        w.write(json.dumps(dict(func_addrs_variables)))

if __name__ == "__main__":

    binary = sys.argv[1]
    manager = Manager()
    main(binary)
    
  
