#!/bin/sh

# Author: Thierry Khamphousone @Yulypso
# Date: 03/02/2022


if [ $# == 0 ]; then
    echo '[-]: Deleting keys . . .'
    rm rsa-1-priv.pem
    rm rsa-1-pub.pem
    rm rsa-2-priv.pem
    rm rsa-2-pub.pem

    echo '[+]: Generating keys . . .'
    openssl genrsa 2048 > rsa-1-priv.pem
    echo '[+]: rsa-1-priv.pem'
    openssl rsa -pubout -in rsa-1-priv.pem > rsa-1-pub.pem
    echo '[+]: rsa-1-pub.pem'
    openssl genrsa 2048 > rsa-2-priv.pem
    echo '[+]: rsa-2-priv.pem'
    openssl rsa -pubout -in rsa-2-priv.pem > rsa-2-pub.pem
    echo '[+]: rsa-2-pub.pem'

elif [ $1 == 'clear' ] || [ $1 == 'cl' ]; then
    echo "[-]: Deleting keys for key-pair-*"
    rm -rf key-pair-*
    rm -rf *.pem

elif [ $# == 1 ]; then
    for i_name in $(seq 1 $1)
    do
        echo "[+]: Generating keys for key-pair-$i_name"
        directory="key-pair-$i_name"
        mkdir $directory
        openssl genrsa 2048 > $directory/"cipher-$i_name-priv.pem"
        openssl rsa -pubout -in $directory/"cipher-$i_name-priv.pem" > $directory/"cipher-$i_name-pub.pem"
        openssl genrsa 2048 > $directory/"signature-$i_name-priv.pem"
        openssl rsa -pubout -in $directory/"signature-$i_name-priv.pem" > $directory/"signature-$i_name-pub.pem"
    done

else
    echo '[!]: generate-keys.sh error'
    echo '[!]: Usage: ./generate-keys.sh [nb_key-pairs]'
fi

