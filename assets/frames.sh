#!/bin/sh
# The README's screenshots: real frames of the terminal view, light and dark.
# Run from the repository: sh assets/frames.sh. CHROME is a headless Chrome.
set -e
CHROME=${CHROME:-$(find ~/Library/Caches/ms-playwright -name chrome-headless-shell -type f | head -1)}
tmp=$(mktemp -d)
shot() { # name size tab focus
  for theme in dark light; do
    flag=""; [ $theme = light ] && flag="--light"
    bon view --frame $2 --tab $3 --focus $4 $flag > "$tmp/$1-$theme.html"
    w=$(( ${2%x*} * 84 / 10 + 40 )); h=$(( ${2#*x} * 21 + 30 ))
    "$CHROME" --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
      --window-size=$w,$h --screenshot="assets/$1-$theme.png" "file://$tmp/$1-$theme.html" 2>/dev/null
  done
}
shot traces 120x26 4 1
shot spec 120x34 2 26
