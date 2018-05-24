#!/bin/bash

set -ex -o xtrace

git config --global core.abbrev 8

BUILDPATH=${PWD}
BRANCH="`git log --date=short --pretty=format:"%cd_%h" -n 1`"

git clone https://${GH_TOKEN}@github.com/OpenSC/Nightly.git > /dev/null 2>&1
cd Nightly
git checkout -b "${BRANCH}"

for file in ${BUILDPATH}/win32/Output/OpenSC*.exe ${BUILDPATH}/opensc*.tar.gz ${BUILDPATH}/OpenSC*.dmg ${BUILDPATH}/OpenSC*.msi ${BUILDPATH}/OpenSC*.zip
do
    if [ -f ${file} ]
    then
        cp ${file} .
        git add `basename ${file}`
    fi
done

git commit --message "$1"
if ! git push --quiet --set-upstream origin "${BRANCH}"
then
    sleep $[ ( $RANDOM % 32 )  + 1 ]s
    git pull --rebase origin "${BRANCH}"
    git push --quiet --set-upstream origin "${BRANCH}"
fi
