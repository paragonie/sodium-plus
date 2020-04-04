#!/usr/bin/env bash

basedir=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
path="${basedir}/build/remove-sodium-native.sh"

bash "${path}"
ret=$?
if [[ $ret -ne 0 ]]; then
  echo "Exiting..."
  exit "${ret}"
fi

echo "Building..."
browserify browser.js > dist/sodium-plus.js
echo "Minifying..."
browserify browser.js -p tinyify > dist/sodium-plus.min.js
echo "Build complete! Resetting..."

# Once browserify finishes, rollback changes that removed sodium-native.
git checkout -- lib/*
git checkout -- lib/*/*
echo "Done!"
