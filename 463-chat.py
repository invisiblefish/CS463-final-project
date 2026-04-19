#!/usr/bin/env python

import socket
import yaml
import argparse
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES


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
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.bind(('', port))
  s.listen(5)
  print(f"Server is listening on {port}")

  key = genRSAKeyPair()
  private_key = key
  public_key = key.public_key()
  print('my public key is')
  print(public_key.export_key().decode())
  client_pub = None

  while True:
    c, addr = s.accept()
    print(f"Got connection from {addr}")
   

    
    msg_type = None
    while msg_type != '08':
      msg = c.recv(1024)
      msg_type = bytes.hex(msg[0:1])
      msg = msg[1:]

      if msg_type == '08':
        print('received disconnect from client. closing connection')
        continue
      elif msg_type == '01':
        print('received client public key')
        client_pub = RSA.import_key(msg.decode())
        print(client_pub.export_key().decode())
        print('sending public key to client')
        s_snd_pub_key = bytes.fromhex('02')
        s.send(s_snd_pub_key + public_key.export_key())
      else:
        print(msg.decode())

    #c.close()

def client(server, port):
  key = genRSAKeyPair()
  private_key = key
  public_key = key.public_key()
  print('my public key is')
  print(public_key.export_key().decode())
  server_pub = None

  s = socket.socket()
  try:
    s.connect((server, port))
  except ConnectionRefusedError:
    fail('Could not connect to server. Is the server running? Check your firewall')

  c_snd_pub_key = bytes.fromhex('01')
  s.send(c_snd_pub_key + public_key.export_key())
  
  msg_type = None
  msg = s.recv(1024)
  print(f'message type received: {msg_type}')

  while msg_type != '08':
    msg_type = bytes.hex(msg[0:1])
    #print(f'message type received: {msg_type}')
    msg = msg[1:]

    if msg_type == '02':
      server_pub = RSA.import_key(msg.decode())
      print(f'received server public key')
    else:
      #msg = s.recv(1024)
      pass
  

def parseMessage(msg):
  pass

def parseArgs():
  parser = argparse.ArgumentParser(prog="463-chat",
                                   description='Encrypted chat application for CS 463 final project')

  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument('-C', '--client', action='store_true', help='operate in client mode')
  group.add_argument('-S', '--server', action='store_true', help='operate in server mode')
  parser.add_argument('-c', '--config-file', default='config.yaml')
  #parser.add_argument('--private-key', help='path to your private key file', default

  return parser

def genRSAKeyPair():
  return RSA.generate(1024)

def fail(msg):
  print(msg)
  sys.exit(1)

if __name__ == '__main__':
  main()
