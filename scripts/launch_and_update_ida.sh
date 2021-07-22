#!/usr/bin/env bash

install_and_run() {
  echo "[!] Installing BinSync core..."
  python3.8 -m pip install --no-deps -e .

  echo "[!] Installing BinSync IDA Plugin..."
  cp -r plugins/ida_binsync/* "$IDA_HOME"/plugins/

  echo "[!] Launching IDA..."
  PYTHONBREAKPOINT=remote_pdb.set_trace REMOTE_PDB_HOST=127.0.0.1 REMOTE_PDB_PORT=4444 /"$IDA_HOME"/ida64
}

if test -d "./binsync"; then
  install_and_run
  exit 0
fi

echo "[X] ERROR: running in the wrong directory. Please run this in the root of the binsync repo."
exit 1