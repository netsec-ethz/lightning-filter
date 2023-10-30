#!/usr/bin/env bash
set -Eeuo pipefail

SCIONPATH=$1

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

pushd $SCRIPTPATH > /dev/null

mkdir -p logs gen gen-eh gen-cache gen-certs tmp
find gen gen-eh gen-cache gen-certs tmp -mindepth 1 -maxdepth 1 -exec rm -r -f {} +


pushd $SCIONPATH > /dev/null
export PYTHONPATH=.
printf '#!/bin/bash\necho "0.0.0.0"' > tools/docker-ip

echo "Create topology, configuration, and execution files."
tools/topogen.py -c $SCRIPTPATH/tiny.topo -o $SCRIPTPATH/tmp

export PYTHONPATH=.
$SCRIPTPATH/scion-topo-add-drkey.py

popd > /dev/null

#cp -R ./template6/* ./gen/
#cp -R ./template6_eh/* ./gen-eh/
cp -R ./template/* ./gen/
cp -R ./template_eh/* ./gen-eh/

cp -r $SCRIPTPATH/tmp/ASff00_0_110/certs ./gen/ASff00_0_110/
cp -r $SCRIPTPATH/tmp/ASff00_0_110/crypto ./gen/ASff00_0_110/
cp -r $SCRIPTPATH/tmp/ASff00_0_110/keys ./gen/ASff00_0_110/

cp -r $SCRIPTPATH/tmp/ASff00_0_111/certs ./gen/ASff00_0_111/
cp -r $SCRIPTPATH/tmp/ASff00_0_111/crypto ./gen/ASff00_0_111/
cp -r $SCRIPTPATH/tmp/ASff00_0_111/keys ./gen/ASff00_0_111/

cp -r $SCRIPTPATH/tmp/ASff00_0_112/certs ./gen/ASff00_0_112/
cp -r $SCRIPTPATH/tmp/ASff00_0_112/crypto ./gen/ASff00_0_112/
cp -r $SCRIPTPATH/tmp/ASff00_0_112/keys ./gen/ASff00_0_112/

cp -r $SCRIPTPATH/tmp/ISD1/trcs ./gen/ISD1/
cp -r $SCRIPTPATH/tmp/certs ./gen/
cp -r $SCRIPTPATH/tmp/trcs ./gen/

cp -r $SCRIPTPATH/tmp/ASff00_0_111/certs ./gen-eh/ASff00_0_111/
cp -r $SCRIPTPATH/tmp/ASff00_0_111/crypto ./gen-eh/ASff00_0_111/
cp -r $SCRIPTPATH/tmp/ASff00_0_111/keys ./gen-eh/ASff00_0_111/

cp -r $SCRIPTPATH/tmp/ASff00_0_112/certs ./gen-eh/ASff00_0_112/
cp -r $SCRIPTPATH/tmp/ASff00_0_112/crypto ./gen-eh/ASff00_0_112/
cp -r $SCRIPTPATH/tmp/ASff00_0_112/keys ./gen-eh/ASff00_0_112/

rm -r $SCRIPTPATH/tmp


# set paths in supervisord.conf
sed -i "s@%(ENV_SCION_BIN)s/@$SCIONPATH/bin/@" gen/supervisord.conf

sed -i "s@%(ENV_SCION_USER)s@${USER}@" gen/supervisord.conf

popd > /dev/null