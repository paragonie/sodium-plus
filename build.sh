#!/usr/bin/env bash

basedir=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
path="${basedir}/build/remove-sodium-native.sh"

bash "${path}"
ret=$?
if [[ $ret -ne 0 ]]; then
  echo "Exiting..."
  exit "${ret}"
fi
echo "Return ${ret}"

browserify index.js > dist/sodium-plus.js
browserify index.js -p tinyify > dist/sodium-plus.min.js
