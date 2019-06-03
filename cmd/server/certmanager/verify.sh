#!/bin/bash
openssl verify -verbose -CAfile certs/CA/CA.pem certs/CA/CA.pem
(openssl x509 -pubkey -in certs/CA/CA.pem -noout | openssl md5 ;\
   openssl pkey -pubout -in certs/CA/CA.key | openssl md5) | uniq
openssl verify -verbose -CAfile certs/CA/CA.pem certs/SERVER/Server.pem
(openssl x509 -pubkey -in certs/SERVER/Server.pem -noout | openssl md5 ;\
   openssl pkey -pubout -in certs/SERVER/Server.key | openssl md5) | uniq
openssl verify -verbose -CAfile certs/CA/CA.pem certs/CLIENT/Client.pem
(openssl x509 -pubkey -in certs/CLIENT/Client.pem -noout | openssl md5 ;\
   openssl pkey -pubout -in certs/CLIENT/Client.key| openssl md5) | uniq

openssl x509 -in certs/CA/CA.pem -text -noout
openssl x509 -in certs/SERVER/Server.pem -text -noout
openssl x509 -in certs/CLIENT/Client.pem -text -noout