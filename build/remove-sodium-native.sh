#!/usr/bin/env bash

git apply --check pre-build.patch
ret=$?
if [[ $ret -ne 0 ]]; then
  echo "Patch is unsafe."
  exit 1
fi
git apply pre-build.patch
ret=$?
exit $ret
