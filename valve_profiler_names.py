# Valve Profiled Function Namer
# By Syn

# This script names functions in valve applications and source games which use their code profiling library
# Targetted functions pass an identifying string to the library and this string is used to name each of them
# Please note that some identifiers arent suitable function names and some identifiers are used multiple times
# The names generated are only for aiding reversing and may not be their real names in the original code

from idautils import *
from idc import *
from idaapi import *
import string

ENTER_SCOPE = 0
NAME_CACHE = {}

def import_seach_callback(ea, name, ord):
    """
    Callback for enum_import_names, tries to find the valve profiler
    EnterScope function for later use. Stops searching when its found
    """
    global ENTER_SCOPE
    
    if name:
        if "EnterScope@CVProfile" in name:
            print(name)
            ENTER_SCOPE = ea
            return False
        
    return True

def get_last_push(ea):
    """
    Given the starting instruction address ea, walks backwards to find the last push
    instruction
    """
    current_ea = ea

    while idc.GetMnem(current_ea) != "push":
        current_ea = idc.PrevHead(current_ea)

    return current_ea

def get_string(addr):
    """
    Attempts to retrieve a string given an ea for data to read from
    Cleans the string and removes any characters that IDA won't like used for a name
    Returns an empty string on failure
    """
    
    out = ""
    while True:
        if Byte(addr) != 0:
            out += chr(Byte(addr))
        else:
            break
        
        addr += 1
        if len(out) > 50:
            break
    # Non-printable characters? Bad string
    if all(c in string.printable for c in out) == False:
        return ""

    # Strip shit that we cant have in the string
    out = re.sub(r"\s+", '_', out)
    out = out.replace("-", "")
    out = out.replace(">", "")
        
    return out

def process_profiler_xref(ea):
    """
    Given an address of a call to CProfNode::EnterScope, will grab the name used to identify the function
    from the first parameter used to make the call, and uses this to name the function making the call
    """
    global NAME_CACHE

    # The last push will be the first arg
    last_push = get_last_push(ea)

    # Get the string from the operand of this push instruction
    func_name = get_string(idc.GetOperandValue(last_push, 0))

    # Try get the function we are currently inside of
    func = idaapi.get_func(ea)
    if func is None:
        return
    
    # Check if the name we are about to use is valid
    if len(func_name) <= 0:
        return
    
    # Handles duplicate names, which does seem to happen quite a lot (inlined code, templated funcs etc)
    is_unique = True
    if func_name in NAME_CACHE:
        (fea, fcount) = NAME_CACHE[func_name]

        if func.startEA not in list(fea):
            fea.append(func.startEA)
            fcount += 1
            NAME_CACHE[func_name] = (fea, fcount)
        else:
            is_unique = False
 
        func_name += str(fcount)
        
    else:
        NAME_CACHE[func_name] = ([func.startEA], 1)

    # If we havent already named this function, do so
    if is_unique:
        idc.MakeName(func.startEA, func_name)

def main():
    global ENTER_SCOPE
    global NAME_CACHE
    
    NAME_CACHE = {}
    nimps = idaapi.get_import_module_qty()

    # Search imports for our EnterScope function
    for i in xrange(0, nimps):
        idaapi.enum_import_names(i, import_seach_callback)

        if ENTER_SCOPE != 0:
            break
        
    # If we found it, process every call to it
    if ENTER_SCOPE != 0:
        for xref in XrefsTo(ENTER_SCOPE, 0):
            if xref.type != 3: # ignore the duplicate "Read" xrefs for each of the calls
                process_profiler_xref(xref.frm)

        print("Finished naming profiled functions!")
    else :
        print("Could not locate EnterScope export!")

if __name__ == "__main__":
    main()
