#!/usr/bin/env bash


install() {
  # install the core
  echo "[!] Installing BinSync core..."
  python3.8 -m pip install -e ./
  echo "[!] Done!"

  # install the IDA Plugin Version
  if [[ -z "${IDA_HOME}" ]]; then
    echo "[!] IDA_HOME not defined, skipping..."
  else
    echo "[!] Installing BinSync IDA Plugin to $IDA_HOME..."
    if test -f "$IDA_HOME"/ida.key; then
      cp -r plugins/ida_binsync/* "$IDA_HOME"/plugins/
      echo "[!] Done!"
    else
      echo "[X] Error, IDA_HOME appears to not be the home of an ida install."
      echo "If you believe this is incorrect, manually run:"
      echo "cp -r plugins/ida_binsync/* "$IDA_HOME"/plugins/"
      exit 1
    fi
  fi

  # install the Binja Plugin Version
  # install the Ghidra Plugin Version
}

if test -d "./binsync"; then
  install
  echo "[!] Finished installing BinSync, ready to roll!"
  exit 0
fi

echo "[X] ERROR: running in the wrong directory. Please run this in the root of the binsync repo."
exit 1
