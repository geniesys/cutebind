#!/bin/bash

if [[ $(id -u) -ne 0 ]] ; then
   echo "Please run as root";
   exit 1;
fi

CWD=$(pwd);

chmod +x $CWD/cutebind;

#rm /usr/local/bin/cutebind 2> /dev/null;
ln -sf $CWD/cutebind /usr/local/bin/cutebind;

#rm /usr/bin/cutebind  2> /dev/null;
ln -sf $CWD/cutebind /usr/bin/cutebind;

#rm $HOME/Desktop/cutebind 2> /dev/null;
ln -sf $CWD/cutebind $HOME/Desktop/cutebind;


mkdir logs 2> /dev/null;
mkdir ipc  2> /dev/null;

if [ -f /etc/init.d/mysql* ]; then
    echo '';
    echo 'This script can initialize `cuteresolve` database schema and create a user account.';
    echo 'Default user name and password are specified in cuteresolve.sql at the end of file.';
    echo 'If you wish to change it, edit cuteresolve.sql and config.php before pressing "Y".';
    echo 'If you already have `cuteresolve` database, the existing tables will not be touched,';
    echo 'but password will be reset.';
    read -n1 -r -p "Do you want to initialize database now? (Y/N) " key;
    echo '';
fi;

if [ "$key" = 'y' ] || [ "$key" = 'Y' ]; then
    echo '---------------------------------------------------------------------------------';
    mysql -u root -p < cuteresolve.sql;
    echo '---------------------------------------------------------------------------------';
else
    echo '';
    echo 'To initialize database at a later time execute:';
    echo '$ mysql [-h <host>] -u root -p < cuteresolve.sql';
fi;

echo '';
echo 'Installed.';
echo '';

if [ ! -f ./config.my.php ]; then
    echo 'We are still using default configuration file config.php. Please edit it now. Set all';
    echo 'settings according to your environment and save as config.my.php';
fi;

read -n1 -r -p "Start cutebind now to see if it works? (Y/N) " key;
echo '';
if [ "$key" = 'y' ] || [ "$key" = 'Y' ]; then
    echo 'Executing cutebind in console mode. Ctrl+C to exit ...

';

    cutebind master;

else
    echo '$ ./cutebind           - deamon mode';
    echo '$ ./cutebind master    - console mode';
    echo '$ ./cutebind help      - for more help';
fi;
