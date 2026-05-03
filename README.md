# CS463-final-project

This program was created for my final project in CS463, Spring 2026 at ODU. The program implements a simple message passing system between a client and a server. Each side generates an RSA keypair, then exchanges public keys. The client generates an 8-byte DES key and encrypts it with the server's public key, and sends it to the server. The server decrypts the DES key and then uses said key to encrypt a known string which it then sends back to the client. After the client decrypts and verifies this known string, message passing begins.

# Dependencies
You will have to install pycryptodome and pyyaml for this program to work. Here are the commands for various systems:

## FreeBSD
```sh
pkg install py311-pycryptodome py311-pyyaml
```

## RHEL
```bash
dnf install python3-pycryptodome python3-pyyaml
```

## Ubuntu
```bash
apt install python3-pycryptodome python3-pyyaml
```
