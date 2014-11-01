#!/bin/bash
CWD=$(pwd);
chmod +x $CWD/cutebind
rm /usr/local/bin/cutebind > /dev/null;
ln -s $CWD/cutebind /usr/local/bin/cutebind
rm /usr/bin/cutebind  > /dev/null;
ln -s $CWD/cutebind /usr/bin/cutebind
echo "Installed. Executing cutebind...

";
cutebind;