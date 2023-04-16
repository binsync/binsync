try:
    from binsync.decompilers.ghidra.server import start
except ImportError:
    print("[!] BinSync is not installed, please `pip install binsync` for THIS python interpreter")
