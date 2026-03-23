"""
Fuji bupy
==============================
Script to extract raw BIOS image as *.bin
from Fujitsu (InsydeH2O)'s BIOS updater excutable file.

Sample: URSV124All.exe (V1.24.0.0, 2024-10-18)

Usage:
    First, unzip exe file with 7z. This software can
    extract raw bios file from a file in the updater.
    python main.py
"""

import sys
import os
import shutil
import gui
import bup
import udp

# init
APPNAME = "image2pdf"
VERSION = 1.6
DEVELOPER = "wakanameko"
currentDir = os.path.dirname(__file__)
print("{}/setting.ini".format(currentDir))
ENVIRONMENT = os.name

# ---------------------------------------------------------------------------
# CLI エントリーポイント
# ---------------------------------------------------------------------------

def main() -> any:
    gui.init()
    path_bup = gui.ask_path("bup")
    path_upd_dir = bup.decomp(path_bup)
    udp.main(path_upd_dir)
    
if __name__ == '__main__':
    print("####################\n" + APPNAME, "version:", VERSION, "by", DEVELOPER, "\nPlatform:", ENVIRONMENT,"\n####################")
    sys.exit(main())