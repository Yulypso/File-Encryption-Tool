#!/bin/sh

echo '[-]: Deleting keys . . .'
rm rsa-1-priv.pem
rm rsa-1-pub.pem
rm rsa-2-priv.pem
rm rsa-2-pub.pem

echo '[+]: Generating keys . . .'
openssl genrsa 2122 > rsa-1-priv.pem
echo '[+]: rsa-1-priv.pem'
openssl rsa -pubout -in rsa-1-priv.pem > rsa-1-pub.pem
echo '[+]: rsa-1-pub.pem'
openssl genrsa 2122 > rsa-2-priv.pem
echo '[+]: rsa-2-priv.pem'
openssl rsa -pubout -in rsa-2-priv.pem > rsa-2-pub.pem
echo '[+]: rsa-2-pub.pem'

