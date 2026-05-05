#!/usr/bin/env python


# Author: Scott King
# Subject: CS463
# 
# this program implements a simple, turn-based message passing mechanism.
# the client and server each generate an RSA keypair and exchange public keys.
# the client generates a random 8-byte DES key, encrypts it with the server's
# public key, then sends to the server. the server decrypts it, then uses a
# pre-programmed string to validate to the client that it received the key correctly.
# once this keying handshake process is complete, the client and server take turns sending
# DES-encrypted messages to each other.
#
# There are several different message types that exist in this program. Below is a short
# description of them
#
# Type	Description
# ####	###########
#   01	client send public key
#   02	server send public key
#   03	client send DES key - client encrypts DES key with server pub key and sends to server
#   04	server verify DES key - server decrypts DES key, encrypts control_message with DES key and sends type 04 to client
#   05	client verify DES key - client decrypts with DES key, verifies that it matches control_message, sends type 05 to server
#   06	client message/ready - client sends to server signifying a message and client is ready for server message
#   07	server message/ready - same as type 06 but for server
#   08	disconnect

import socket
import yaml
import argparse
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes


config_keywords = ['server', 'port']

def main():

  parser = parseArgs()
  args = vars(parser.parse_args())

  try:
    with open(args['config_file'], 'r') as f:
      config_data = yaml.safe_load(f)
  except (FileNotFoundError, PermissionError):
    fail('failed to read config file! check permissions')

  for key in config_keywords:
    if key not in config_data.keys():
      fail(f'"{key}" parameter not found in config file. exiting')
  
  if args['client']:
    client(config_data['server'], config_data['port'])
  elif args['server']:
    server(config_data['port'])

def server(port):
  control_message = 'this is a test'	# used to validate DES key with client

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.bind(('', port))
  s.listen(5)
  print(f"Server is listening on {port}")

  s_priv = genRSAKeyPair()
  s_pub = RSA.import_key(s_priv.public_key().export_key()).export_key()	# make sure no private key exists with the s_pub object
  print('my public key is')
  print(s_pub.decode())

  rsa_cipher = PKCS1_OAEP.new(s_priv)	# server creates the rsa_cipher first, it will need this to decrypt the DES key

  try:
    while True:	# outer loop allows clients to reconnect
      c, addr = s.accept()
      c_pub = None
      print(f"Got connection from {addr}")
      msg_type = None

      des_cipher = None
      des_key = None

      # first inner loop represents the key exchange handshake phase, after we receive
      # type 05, we break the loop and move to messaging phase
      while True:
        msg = c.recv(1024)
        msg_type = bytes.hex(msg[0:1])
        msg = msg[1:]

        if msg_type == '08':
          print('received disconnect from client. closing connection')
          c.close()
          break

        elif msg_type == '01':
          print('received client public key')
          c_pub = RSA.import_key(RSA.import_key(msg.decode()).export_key())
          print(c_pub.export_key().decode())
          print('sending public key to client')
          s_snd_pub_key = bytes.fromhex('02')
          c.send(s_snd_pub_key + s_pub)

        elif msg_type == '03':
          print('received des key from client')
          des_key = rsa_cipher.decrypt(msg)
          print('DES key is: ' + des_key.hex())

          des_cipher = DES.new(des_key, DES.MODE_ECB)

          print('sending encrypted control message to client')
          c.send(bytes.fromhex('04') + des_cipher.encrypt(pad(control_message)))

        elif msg_type == '05':
          print('successfully completed handshake with client, beginning encrypted messaging')
          break

      text = 'server ready for messages'
      ciphertext = des_cipher.encrypt(pad(text))
      c.send(bytes.fromhex('07') + ciphertext)

      # second inner loop is the encrypted messaging phase with the DES key.
      # continue until client disconnects
      while True:
        msg = c.recv(1024)
        msg_type = bytes.hex(msg[0:1])
        msg = msg[1:]

        if msg_type == '08':
          print('received disconnect from client. closing connection')
          c.close()
          break

        elif msg_type == '06':
          text = des_cipher.decrypt(msg)
          print(f'client says: {text.decode()}')
          text = input('type message to client: ')
          ciphertext = des_cipher.encrypt(pad(text))
          c.send(bytes.fromhex('07') + ciphertext)

  except KeyboardInterrupt:
    print('Exiting on keyboard interrupt')
    c.send(bytes.fromhex('07') + bytes('disconnect', 'utf-8'))
    c.close()
    s.close()
    sys.exit(1)


def client(server, port):
  control_message = 'this is a test'

  c_priv = genRSAKeyPair()
  c_pub = RSA.import_key(c_priv.public_key().export_key())
  print('my public key is')
  print(c_pub.export_key().decode())
  s_pub = None

  des_key = get_random_bytes(8)
  print(f'generated DES key: {des_key.hex()}')
  des_cipher = DES.new(des_key, DES.MODE_ECB)

  s = socket.socket()
  try:
    s.connect((server, port))
  except ConnectionRefusedError:
    fail('Could not connect to server. Is the server running? Check your firewall')

  c_snd_pub_key = bytes.fromhex('01')
  s.send(c_snd_pub_key + c_pub.export_key())

  try:
    rsa_cipher = None	# can't build this until we receive server's public key

    # no outer loop for client, as soon as it disconnects it exits
    # first loop handles client-side key exchange handshake, breaking
    # after we receive type 04 and validate the control_message
    while True:
      msg_type = None
      msg = s.recv(1024)
      msg_type = bytes.hex(msg[0:1])
      msg = msg[1:]

      if msg_type == '02':
        s_pub = RSA.import_key(msg.decode())
        print(f'received server public key')
        print(s_pub.export_key().decode())
        print('encrypting DES key and sending to server')
        rsa_cipher = PKCS1_OAEP.new(s_pub)
        s.send(bytes.fromhex('03') + rsa_cipher.encrypt(des_key))

      elif msg_type == '04':
        message = des_cipher.decrypt(msg).decode().strip()
        if message == control_message:
          print('successfully exchanged DES key')
          s.send(bytes.fromhex('05'))
          break

      elif msg_type == '08':
          print('received disconnect from server. closing connection and exiting')
          s.close()
          sys.exit(1)

    # second loop handles client messaging phase, breaking if server sends disconnect message
    while True:
      msg = s.recv(1024)
      msg_type = bytes.hex(msg[0:1])
      msg = msg[1:]

      if msg_type == '07':
        text = des_cipher.decrypt(msg)
        if text == 'disconnect':
          s.close()
          fail('server disconnected')
        print(f'server says: {text.decode()}')
        text = input('type message to server: ')
        ciphertext = des_cipher.encrypt(pad(text))
        s.send(bytes.fromhex('06') + ciphertext)

  # safely close the connection on Ctrl-C
  except KeyboardInterrupt:
    s.send(bytes.fromhex('08'))
    s.close()
    print('exiting on keyboard interrupt')
  

# had to add the pad function to make sure that the message we send is correct length for DES
def pad(msg):

  # assume modulus is 8 because DES keys are 8 bytes, now pad input message to be multiple of 8
  msg = bytes(msg, 'utf-8')
  while len(msg) % 8 != 0:
    msg = msg + b' '

  return msg

def parseArgs():
  parser = argparse.ArgumentParser(prog="463-chat",
                                   description='Encrypted chat application for CS 463 final project')

  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument('-C', '--client', action='store_true', help='operate in client mode')
  group.add_argument('-S', '--server', action='store_true', help='operate in server mode')
  parser.add_argument('-c', '--config-file', default='config.yaml')

  return parser

def genRSAKeyPair():
  return RSA.generate(1024)

def fail(msg):
  print(msg)
  sys.exit(1)

if __name__ == '__main__':
  main()
