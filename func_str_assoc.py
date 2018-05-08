# Function String Associate for IDAPython
# By Syn

from idautils import *
from idc import *
from idaapi import *

MAX_STRING_PREVIEW_LENGTH = 35

def long_string_preview(text):
    """
    Returns a shortened preview of a long string
    Also cleans the string, removing any bad characters
    """

    clean_text = text.replace("\n", " ")
    
    if len(clean_text) > MAX_STRING_PREVIEW_LENGTH:
        return clean_text[0:MAX_STRING_PREVIEW_LENGTH] + "..."
    else:
        return clean_text

def append_unique_comment(ea, text):
    """
    Appends a new string to the end of the comments at this address
    Will only append it if the string is not already commented there
    """

    # filter bad strings
    if text is None:
        return

    c = GetCommentEx(ea, 0)

    new_comment = "\""+long_string_preview(str(text))+"\""

    # The string we are about to append is already commented
    if new_comment in str(c):
        return

    # Seperate each one by commas
    if c is not None:
        new_comment = str(c) + "," + new_comment

    MakeComm(ea, new_comment)

def process_string_xref(s, ea):
    """
    Everywhere the function containing the given reference is used,
    a comment is placed there indicating the string is referenced inside
    """

    # What function is this code inside of?
    func = idaapi.get_func(ea)
    if func is None:
        return

    # Process everywhere this function gets called / reference
    for fxref in XrefsTo(func.startEA, 0):
        append_unique_comment(fxref.frm, s)

def main():
    sc = Strings()

    # For all strings ...
    for s in sc:

        # Find all the references to the string
        for xref in XrefsTo(s.ea, 0):
            process_string_xref(s, xref.frm)

    print "function string associate has finished!"

if __name__ == "__main__":
    main()
