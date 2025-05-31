#!/bin/bash
# install X11 required packages for spawning non-monitored windows
sudo apt-get update && sudo apt-get install -y \
  libegl1 libxkbcommon-x11-0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
  libxcb-randr0 libxcb-render-util0 libxcb-xinerama0 libxcb-xfixes0 x11-utils
# start Xvfb daemon
/sbin/start-stop-daemon --start --quiet --pidfile /tmp/custom_xvfb_99.pid --make-pidfile --background \
  --exec /usr/bin/Xvfb -- :99 -screen 0 1920x1200x24 -ac +extension GLX
# update pip
python -m pip install --upgrade pip
# install the parallel branch of libbs that matches the current branch
(git clone https://github.com/binsync/libbs.git /tmp/libbs && cd /tmp/libbs && git checkout $BRANCH_NAME || true && pip install .)
# attempt an install of angr-management first since version of binsync will conflict
pip install angr-management>=9.2.139
pip install .[test]
AM_INSTALL=$(dirname $(python3 -c "import angrmanagement; print(angrmanagement.__file__)"))/plugins/
binsync --cli-install angr --install-path $AM_INSTALL
