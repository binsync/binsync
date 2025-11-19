import logging
import typing
import threading


import networkx as nx

if typing.TYPE_CHECKING:
    from binsync.controller import BSController

_l = logging.getLogger(__name__)

PRE_TEXT = """
You are a summarizing assistant that summarizes the work of other reverse engineers in understanding software.
A series of experts have reversed engineered a program and have identified a subset of those functions to be 
important. They are all included below. Additionally, the experts have identified a series of changes to the
program, and sorted them by how connected they are to other functions.

Note, that by default all variables in code have no names or types, but the experts have identified them
and written them directly into the code.

Your job is the following, concisely:
- summarize any important comments left behind, like those about control or exploitation
- summarize how these functions may all relate to each other 
- summarize the changes in the program, and how they may affect the overall program understanding
- format all of the text meant for a .txt file, so that it is easy to read

Here is all the code of the functions that the experts have identified as important:

```
"""

POST_TEXT = """
```

Using that information, summarize the changes and what conclusions the reverses have made.
Prettyify your response with HTML so that it can be rendered and is easy to read. If you need, copy some code
snippets from the above code to help explain your points.
"""
def model_type(model_name):
    model = ["gpt-5"] #Decided on only using gpt-5
    if model_name in model:
        return model_name

def summarize_changes(controller: "BSController", graph: nx.DiGraph, save_location: str):
    """
    Summarize the changes in the graph and display them in a table.
    """
    # collect all the changed funcs with edges
    funcs = {}
    for node in graph.nodes():
        funcs[node] = len(graph.edges(node))

    # sort by number of edges
    funcs = sorted(funcs.items(), key=lambda x: x[1], reverse=True)

    # grab the decompilation for each function
    decompilations = {}
    for func, _ in funcs:
        decompilations[func] = controller.deci.decompile(func.addr)

    # put all the decompilations in a long string
    decompilation_text = ""
    for func, _ in funcs:
        decompilation_text += decompilations[func].text + "\n\n"

    total_text = PRE_TEXT + decompilation_text + POST_TEXT
    thread = threading.Thread(target=query_model, args=("gpt-5", total_text, save_location), daemon=True)
    thread.start()


def query_model(model, text, save_location):
    from dailalib.api import LiteLLMAIAPI
    _l.info("Summarizing with LLM API...")

    llm_api = LiteLLMAIAPI(model=model, delay_init=True)
    resp, cost = llm_api.query_model(text)
    with open(save_location, "w") as f:
        f.write(resp)

    _l.info("Summary completed and saved to %s", save_location)

