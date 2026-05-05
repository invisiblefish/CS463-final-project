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

# Usage
On the server:
```bash
./463-chat.py -S
```

On the client:
```bash
./463-chat.py -C
```

The server will bind to the host it is run from (default to port 30000). Port binding can be changed via the "port" parameter in config.yaml.

The client will connect to the host specified in config.yaml (default to localhost). Modify the "server" parameter in config.yaml to change.

Be aware that if you run client and server on different hosts you will need to allow port 30000 (or custom port) through your firewall on whatever host the server runs from.
