#!/bin/sh
if [ ! -f /acme.sh/account.conf ]; then
    echo 'First startup'
    acme.sh --update-account --accountemail ${ACME_SH_EMAIL}
    echo 'Asking for certificates'
    acme.sh --issue -d "${DOMAIN}" --dns "${DNS_API}" --server letsencrypt --log 
fi
if [ ! -f /cert/fullchain.pem ]; then 
    acme.sh --install-cert -d "${DOMAIN}" --cert-file /cert/cert.pem --key-file  /cert/key.pem --fullchain-file /cert/fullchain.pem
fi
echo 'Listing certs'
acme.sh --upgrade  --auto-upgrade
acme.sh --list
# Make the container keep running
/entry.sh daemon