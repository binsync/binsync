import sys

try:
    from binsync.decompilers.ghidra.server import start
except ImportError as e:
    print(f"[!] BinSync failed to import something: {e}")
    print(f"[!] BinSync is probably not installed, please `pip install binsync` for THIS "
          f"python interpreter: {sys.executable}")
