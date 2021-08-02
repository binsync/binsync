if [ "$#" -ne 2 ]; then
    echo "[!] Error: not enough args. Usage: ./scripts/setup_repo_for_binsync.sh /path/to/repo /path/to/binary"
    exit 1
fi

REPO_PATH=$1
BINARY_PATH=$2

(
  cd "$REPO_PATH" || exit 1
  git checkout -b binsync/__root__
  echo "[!] Pushing a new branch for BinSync upstream"
  git push --set-upstream origin binsync/__root__
  echo "[!] Getting md5sum for the binary"
  md5sum "$BINARY_PATH" | awk '{ print $1 }' > binary_hash
  git add binary_hash
  git commit -m "added binary hash"
  echo "[!] Pushing the md5sum"
  git push
  echo "[!] BinSync repo ready to roll"
)