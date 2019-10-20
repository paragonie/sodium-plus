#!/usr/bin/env bash

basedir=$(dirname $(readlink -f ${BASH_SOURCE[0]}))

$basedir/build/remove-sodium-native.sh

browserify index.js > dist/sodium-plus.js
browserify index.js -p tinyify > dist/sodium-plus.min.js
