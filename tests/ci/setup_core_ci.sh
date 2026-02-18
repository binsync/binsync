#!/bin/bash
# install X11 required packages for spawning non-monitored windows
sudo apt-get update && sudo apt-get install -y \
  libegl1 libxkbcommon-x11-0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
  libxcb-randr0 libxcb-render-util0 libxcb-xinerama0 libxcb-xfixes0 x11-utils
# update pip
python -m pip install --upgrade pip
# install the parallel branch of libbs that matches the current branch
(git clone https://github.com/binsync/libbs.git /tmp/libbs && cd /tmp/libbs && git checkout $BRANCH_NAME || true && pip install .)
# attempt an install of angr-management first since version of binsync will conflict
pip install .[test]
pip install .[extras]
