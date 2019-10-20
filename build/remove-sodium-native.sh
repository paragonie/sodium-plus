#!/usr/bin/env bash
basedir=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
path="${basedir}/pre-build.patch"

git apply --check "${path}"
ret=$?
if [[ $ret -ne 0 ]]; then
  exit "${ret}"
fi
git apply "${path}"
ret=$?
exit $ret
