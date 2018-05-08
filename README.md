# ida_scripts
This repo is just a place for my to dump some of my IDA python scripts that I think people might find usefull.

## func_str_assoc.py
A python implementation of the old Function String Associate plugin.
Will comment a list of strings used within a function everywhere that it is called or referenced.

## valve_profiler_names.py
This script is written for Valve games and software which uses their profiler library. 
Functions will be named by the identifiers used by the profiler. It works pretty well on the targets I've tested but keep in mind
that the names given may not necessarily be 1 to 1 with the source as the devs are free to type what they wish as an identifier.
Only tested on CS:GO and L4D2 but should be robust enough for other games.
