import tkinter as tk
from tkinter import filedialog

def init():    
    root = tk.Tk()
    root.withdraw()

def ask_path(extension:str) -> str:
    """Display chooser window"""
    
    if extension is None:
        return None
    else:
        file_path = filedialog.askopenfilename(
            title="Choose the {} file.".format(extension),
            filetypes=[("Archive files", "*.{}".format(extension)), ("All files", "*.*")]
        )
        return file_path
