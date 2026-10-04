#!/bin/sh
if [ -r /etc/profile ]; then
  . /etc/profile
fi
if [ -r ~/.profile ]; then
  . ~/.profile
fi
if command -v xfconf-query >/dev/null 2>&1; then
  xfconf-query -c xfwm4 -p /general/use_compositing -n -t bool -s false || true
  xfconf-query -c xsettings -p /Net/ThemeName -s "Adwaita-dark" || true
fi
exec startxfce4
