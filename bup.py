"""
BUP unpacker
==============================
Alt script to unpack *.bup files.
This script save the unpacked folder as"{orignal name}_out".

Sample: FJNB2C6.bup (V1.24.0.0, 2024-10-18)

Construct:
    BupInfo2.xml
    FJNB2C6.UPD
"""

import shutil

def decomp(path:str) -> str:
    """decomp a bup as zip"""

    if not path is None:
        # in, out, format
        path_out = "{}_out".format(path[:-4])
        shutil.unpack_archive(path, path_out, "zip")
        
        return path_out