#!/usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BINSYNC_DIR="$( realpath "$SCRIPT_DIR/..")"


install() {

  # install the IDA Plugin Version
  if [[ -z "${IDA_HOME}" ]]; then
    echo "[!] IDA_HOME not defined, skipping..."
  else
    echo "[!] Installing BinSync IDA Plugin to $IDA_HOME..."
    if test -f "$IDA_HOME"/ida.key; then
      # install the core
      echo "[!] Installing BinSync core..."
      python3.8 -m pip install -e ./
      echo "[!] Done!"

      # placing IDA files
      ln -s "$BINSYNC_DIR/plugins/ida_binsync/ida_binsync/" "$IDA_HOME"/plugins/
      ln -s "$BINSYNC_DIR/plugins/ida_binsync/ida_binsync.py" "$IDA_HOME"/plugins/
      echo "[!] Done!"
    else
      echo "[X] Error, IDA_HOME appears to not be the home of an ida install."
      echo "If you believe this is incorrect, manually run:"
      echo "cp -r plugins/ida_binsync/* $IDA_HOME/plugins/"
      exit 1
    fi
  fi

  # install the Binja Plugin Version
  if [[ -z "${BINJA_HOME}" ]]; then
    echo "[!] BINJA_HOME not defined, skipping..."
  else
    echo "[!] Installing BinSync Binja Plugin to $BINJA_HOME..."
    if test -f "$BINJA_HOME"/license.dat; then
      # install the core
      echo "[!] Installing BinSync core..."
      python3 -m pip install -e ./
      echo "[!] Done!"

      # placing Binja files
      ln -s "$BINSYNC_DIR/plugins/binja_binsync/" "$BINJA_HOME"/plugins/
      echo "[!] Done!"
    else
      echo "[X] Error, BINJA_HOME appears to not be the home of an Binja install."
      echo "If you believe this is incorrect, manually run:"
      echo "cp -r plugins/binja_binsync/ $BINJA_HOME/plugins/"
      exit 1
    fi
  fi

  # install the Ghidra Plugin Version
}

if test -d "./binsync"; then
  install
  echo "[!] Finished installing BinSync, ready to roll!"
  exit 0
fi

echo "[X] ERROR: running in the wrong directory. Please run this in the root of the binsync repo."
exit 1
