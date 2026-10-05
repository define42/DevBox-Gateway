#!/bin/sh
if [ -r /etc/profile ]; then
  # shellcheck source=/dev/null
  . /etc/profile
fi
if [ -r ~/.profile ]; then
  # shellcheck source=/dev/null
  . ~/.profile
fi
# Xsession imports these into the D-Bus and systemd user environments.
unset SESSION_MANAGER
export XDG_SESSION_TYPE=x11
export XDG_CURRENT_DESKTOP=GNOME
export XDG_SESSION_DESKTOP=gnome
export DESKTOP_SESSION=gnome
export GNOME_SHELL_SESSION_MODE=user
exec /etc/X11/Xsession /usr/local/bin/devbox-gnome-session
