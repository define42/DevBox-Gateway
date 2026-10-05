#!/bin/sh
# XRDP provides an Xorg display; select the matching GNOME session explicitly.
unset SESSION_MANAGER
export XDG_SESSION_TYPE=x11
export XDG_CURRENT_DESKTOP=GNOME
export XDG_SESSION_DESKTOP=gnome
export DESKTOP_SESSION=gnome
export GNOME_SHELL_SESSION_MODE=user
exec gnome-session --session=gnome
