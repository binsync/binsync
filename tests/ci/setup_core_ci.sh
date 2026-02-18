#!/bin/bash
# Not sure if both these commands are necessary for core ci
# install X11 required packages for spawning non-monitored windows (copied from setup_gui_ci.sh)
sudo apt-get update && sudo apt-get install -y \
  libegl1 libxkbcommon-x11-0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
  libxcb-randr0 libxcb-render-util0 libxcb-xinerama0 libxcb-xfixes0 x11-utils
# start Xvfb daemon
/sbin/start-stop-daemon --start --quiet --pidfile /tmp/custom_xvfb_99.pid --make-pidfile --background \
  --exec /usr/bin/Xvfb -- :99 -screen 0 1920x1200x24 -ac +extension GLX

python -m pip install --upgrade pip
pip install .[test]
(git clone https://github.com/binsync/libbs.git /tmp/libbs && cd /tmp/libbs && git checkout $BRANCH_NAME || true && pip install .)
pip install .[extras]