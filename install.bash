#!/bin/bash
CWD=$(pwd);
chmod +x $CWD/cutebind
rm /usr/local/bin/cutebind > /dev/null;
ln -s $CWD/cutebind /usr/local/bin/cutebind
rm /usr/bin/cutebind  > /dev/null;
ln -s $CWD/cutebind /usr/bin/cutebind
mkdir logs 2> /dev/null;
mkdir ipc  2> /dev/null;
echo "Installed. Executing cutebind...

";
cutebind;