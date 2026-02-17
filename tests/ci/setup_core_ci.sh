#!/bin/bash
# install X11 required packages for spawning non-monitored windows (copied from setup_gui_ci.sh)
sudo apt-get update && sudo apt-get install -y \
  libegl1 libxkbcommon-x11-0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
  libxcb-randr0 libxcb-render-util0 libxcb-xinerama0 libxcb-xfixes0 x11-utils

python -m pip install --upgrade pip
pip install .[test]
(git clone https://github.com/binsync/libbs.git /tmp/libbs && cd /tmp/libbs && git checkout $BRANCH_NAME || true && pip install .)
pip install .[extras]