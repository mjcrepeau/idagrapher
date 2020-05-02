import idautils
import idc
import idaapi
import ida_kernwin
import random
from pyvis.network import Network

# Global Function dictionary
funcs = {}

# Global options structure
options = {
    "layout": "physics",
    "outfile": "output.html"
}


def check_str_xrefs(ea, s, depth):
    '''
    Find references to strings and add them to the functions dict.
    '''
    # Hacky way to stop infinite recursion bug
    if depth > 10:
        return
    fnames = funcs.keys()
    # Look for xrefs to the string's addr
    for xref in idautils.XrefsTo(ea):
        name = idc.get_func_name(xref.frm)
        # If xref is in a function, that function uses the str
        if name and (name in fnames):
            funcs[name]["strings"].append(s)
        else:
            # It's possible the str xrefs to another data location,
            # and that data location xrefs to code, so keep trying
            check_str_xrefs(xref.frm, s, depth + 1)


def enum_imports(ea, name, ord):
    '''
    Callback function for idaapi.enum_import_names() that will enumerate 
    all of the imported functions and set a flag in the global funcs dict.
    '''
    if name:
        if name in funcs.keys():
            funcs[name]["is_import"] = True
        # Return True to keep iterating through imports in the current 
        # module. Will stop when we have no more imports.
        return True
    return False


def assign_levels(func_list, level):
    '''
    Given a list of functions (usually the entry point), find all "call"
    instructions in each of the functions. If the funcs called have never
    been called before, assign their level. Essentially, this helps the 
    hierarchical graph spread the functions out over the y-axis starting 
    with the first-called (or never-called) functions moving down to the 
    ones that are called later. The function is called recursively until 
    all levels are enumerated.
    '''
    new_list = []
    fnames = funcs.keys()
    for name in func_list:
        # If the func exists and has yet to be assigned a level
        if name in fnames and funcs[name]["level"] == 1:
            funcs[name]["level"] = level
            for f in funcs[name]["func_calls"]:
                new_list.append(f)
    if new_list:
        assign_levels(new_list, level + 1)


def analyze_functions():
    '''
    Iterate through all IDA-identified functions. Assign attributes like
    comments, strings, other function calls, etc. to each function.
    '''
    ds_funcs = []
    # Enumerate all functions and init the funcs dict.
    for ea in idautils.Functions():
        fname = idc.get_func_name(ea)
        funcs[fname] = {
            "func_comments": [idc.get_func_cmt(ea, 0), idc.get_func_cmt(ea, 1)],
            "start_addr": idc.get_func_attr(ea, idc.FUNCATTR_START),
            "end_addr": idc.get_func_attr(ea, idc.FUNCATTR_END),
            "repeatable_comments": [],
            "comments": [],
            "func_calls": [],
            "strings": [],
            "is_import": False,
            "level": 1 # Used for hierarchical layout; level 1 == never called directly
            }
        # Heads() returns list of instructions in this function
        for insn in idautils.Heads(funcs[fname]["start_addr"], funcs[fname]["end_addr"]):
            # Look for function calls
            if idaapi.is_call_insn(insn):
                # Get the name of the called function
                f = idc.print_operand(insn, 0)
                if f.startswith("ds:"):
                    ds_funcs.append(f)
                funcs[fname]["func_calls"].append(f)

            # Look for normal comments
            comment = idc.GetCommentEx(insn, 0)
            if comment:
                funcs[fname]["comments"].append(comment)

            # Looking for repeatable comments
            rcomment = idc.GetCommentEx(insn, 1)
            if rcomment:
                funcs[fname]["repeatable_comments"].append(rcomment)

    # Add data segment functions to function dict
    for f in ds_funcs:
        funcs[f] = {
            "func_comments": [],
            "repeatable_comments": [],
            "comments": [],
            "func_calls": [],
            "strings": [],
            "is_import": False,
            "level": 1 # Used for hierarchical layout; level 1 == never called directly
            }
    
    # For each import module/library, find all of its functions and 
    # set a flag in the global functions dict.
    num_imports = idaapi.get_import_module_qty()
    for i in range(0, num_imports):
        idaapi.enum_import_names(i, enum_imports)

    # Enumerate all strings 
    for i in idautils.Strings():
        ea = i.ea
        s = str(i)
        check_str_xrefs(ea, s, 0)

    if options["layout"] == "hierarchical":
        # Assign hierarchical levels
        func_list = []
        for (index, ordinal, ea, name) in idautils.Entries():
            func_list.append(name)
        assign_levels(func_list, 2)


def create_graph():
    '''
    Generate nodes and edges based on functions and their calls.
    Graph can be hierarchical (based on call order) or physics (based 
    on random layout).
    '''
    net = Network(height="100%", width="100%", bgcolor="#222222", font_color="white", directed=True, layout=False)
    if options["layout"] == "physics":
        net.barnes_hut(central_gravity=1, overlap=1)

    # Find entry points
    entries = []
    for (index, ordinal, ea, name) in idautils.Entries():
            entries.append(name)

    for fname in funcs.keys():
        # Imported functions
        if funcs[fname]["is_import"]:
            node_shape = "diamond"
            color = "#cf5615" # orange
        # Data segement functions
        elif fname.startswith("ds:"):
            node_shape = "triangle"
            color = "#7900d6" # purple
        # Entry points
        elif fname in entries:
            node_shape = "star"
            color = "#03fc73" # mint
        else:
            node_shape = "dot"
            color = "#3abae0" # blue

        content = []
        total_strs = 0

        for s in funcs[fname]["repeatable_comments"]:
            total_strs += 1
            if s not in content:
                content.append(s)
        
        for s in funcs[fname]["comments"]:
            total_strs += 1
            if s not in content:
                content.append(s)
        
        for s in funcs[fname]["strings"]:
            total_strs += 1
            if s not in content:
                content.append(s)

        if total_strs > 5:
            size = total_strs * 4
            if size > 400:
                size = 400
            mass = 0.01 * size
        else:
            size = 20
            mass = 0.5

        content_str = ""
        for s in content:
            content_str = content_str + s + "<br>"

        if options["layout"] == "hierarchical":
            scalar = 50 * funcs[fname]["level"]
            y_pos = random.uniform(1*scalar, 100*scalar)
            size = size * 2
            net.add_node(fname, shape=node_shape, title=content_str, size=size, physics=False, x=random.uniform(-20000,20000), y=y_pos, color=color)
        else:
            net.add_node(fname, shape=node_shape, title=content_str, physics=True, size=size, mass=mass, color=color)

    for fname in funcs.keys():
        calls = []
        for s in funcs[fname]["func_calls"]:
            if s not in calls:
                calls.append(s)

        for call in calls:
            if call in funcs.keys():
                # Imported functions
                if funcs[call]["is_import"]:
                    color = "#cf5615" # orange
                # Data segement functions
                elif call.startswith("ds:"):
                    color = "#7900d6" # purple
                else:
                    color = "#3abae0" # blue

                net.add_edge(fname, call, title=fname + " --> " + call, physics=False, arrowStrikethrough=False, color=color)
    
    # Graph gets broken if there are no physics objects for some reason (e.g. in the case of hierarchical layout)
    # Add a dummy node to fix this bug
    net.add_node("dummy_node", shape="dot", physics=True, hidden=True)
    # Write the output
    net.write_html(options["outfile"])

if __name__ == "__main__":
    s = ida_kernwin.ask_str("physics", 0, "Please select a layout type. Supported types are 'physics' and 'hierarchical'")

    if str(s) != "hierarchical" and str(s) != "physics":
        print("Error! Type must be 'hierarchical' or 'physics'")
        exit(1)
    
    options["layout"] = str(s)

    s = ida_kernwin.ask_str("output.html", 1, "Type the name of the output file")
    if not s:
        print("Please enter an output file")
        exit(1)
    
    options["outfile"] = str(s)

    analyze_functions()
    create_graph()