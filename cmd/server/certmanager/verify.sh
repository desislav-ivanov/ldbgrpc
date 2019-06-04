#!/bin/bash
openssl verify -verbose -CAfile certs/CA/CA.pem certs/CA/CA.pem
(openssl x509 -pubkey -in certs/CA/CA.pem -noout | openssl md5 ;\
   openssl pkey -pubout -in certs/CA/CA.key | openssl md5) | uniq
openssl verify -verbose -CAfile certs/CA/CA.pem certs/SERVER/default/Server.pem
(openssl x509 -pubkey -in certs/SERVER/default/Server.pem -noout | openssl md5 ;\
   openssl pkey -pubout -in certs/SERVER/default/Server.key | openssl md5) | uniq
openssl verify -verbose -CAfile certs/CA/CA.pem certs/CLIENT/default/Client.pem
(openssl x509 -pubkey -in certs/CLIENT/default/Client.pem -noout | openssl md5 ;\
   openssl pkey -pubout -in certs/CLIENT/default/Client.key| openssl md5) | uniq

openssl x509 -in certs/CA/CA.pem -text -noout
openssl x509 -in certs/SERVER/default/Server.pem -text -noout
openssl x509 -in certs/CLIENT/default/Client.pem -text -noout