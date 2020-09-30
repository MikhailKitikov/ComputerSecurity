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


MSGLEN = 1024
IP = 'localhost'
PORT = 5000
SESSION_KEY_EXPIRATION_TIME = 60


def key_expired(created_at):
    return (time() - created_at) > SESSION_KEY_EXPIRATION_TIME


class Client:

	def __init__(self, sock):
		self.sock = sock
		self.generate_aes()
		self.authorized = False
		return
		
	def generate_aes():
		self.key = get_random_bytes(16)
		self.iv = self.key
		self.aes = AES.new(self.key, AES.MODE_CFB, self.iv) # session key
		self.created_at = time()
		
	def send_aes():
		# send aes
		msg = rsa.encrypt(self.key, self.pub)
		client.sock.sendall(msg)
	
   
class Server:
		
	def __init__(self):	
		# load database
		with open('users_db.json', 'r') as file:
			self.users_db = json.load(file)
		
		with open('texts_db.json', 'r') as file:
			self.texts_db = json.load(file)
	
		# create socket
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.s.bind((IP, PORT))
		self.s.listen(5)
		self.clients = deque()
		self.begin_loop()		
		return
		
		
	def broadcast(self, message):
		print(len(self.clients))
		for client in self.clients:
			try:
				client.sock.sendall(message)
			except:
				print("Client disconnected...")
				self.clients.remove(client)
				continue
		return
		
	
	def handle_client(self, client):
		# get public rsa
		try:
			pub = client.sock.recv(1024).decode()
			client.pub = rsa.key.PublicKey.load_pkcs1(pub, 'PEM')
		except:
			self.clients.remove(client)
			return
		
		client.send_aes()
		
		while True:
			try:
				msg = client.aes.decrypt(client.sock.recv(MSGLEN).strip(b'\r\n')).decode()
				
				# check key expiration
				if key_expired(client.created_at):
					client.sock.sendall(client.aes.encrypt('999'))
					client.generate_aes()
					client.send_aes()
					print('New sesion key generated')
				else:
					msg = client.aes.encrypt('ok')
					client.sock.sendall(msg)
				
				if msg == 'register':
					print('Starting registration...')
					
					# get credentials
					username_info = client.aes.decrypt(client.sock.recv(MSGLEN).strip(b'\r\n')).decode()
					password_info = client.aes.decrypt(client.sock.recv(MSGLEN).strip(b'\r\n')).decode()
					
					# decide of response					
					if username_info in self.users_db:
						response = '1'
					else:	
						self.users_db[username_info] = password_info
						with open('users_db.json', 'w') as file:
							json.dump(self.users_db, file)
							
						self.texts_db[username_info] = []
						with open('texts_db.json', 'w') as file:
							json.dump(self.texts_db, file)
						
						response = '0'
						client.authorized = True
					
					# send response
					client.sock.sendall(client.aes.encrypt(response))
					
				elif msg == 'login':
					print('Starting login...')
					
					# send ok
					msg = client.aes.encrypt('ok')
					client.sock.sendall(msg)
					
					# get credentials
					username_info = client.aes.decrypt(client.sock.recv(MSGLEN).strip(b'\r\n')).decode()
					password_info = client.aes.decrypt(client.sock.recv(MSGLEN).strip(b'\r\n')).decode()
					
					# decide of response					
					if username_info not in self.users_db:
						response = '1'
					elif self.users_db[username_info] != password_info:
						response = '2'
					else:						
						response = '0'
						client.authorized = True
					
					# send response
					client.sock.sendall(client.aes.encrypt(response))
					
				elif msg == 'logout':
					print('User logged out')
					client.authorized = False					
					
				elif msg == 'exit':
					print('Removing client...')
					self.clients.remove(client)
					return
								
			except RuntimeError:
				print("Removing client...")
				self.clients.remove(client)
				return
		return
		
		
	def begin_loop(self):
		while True:
			# wait for connections
			(clientsocket, address) = self.s.accept()

			# create new Client object and new thread
			new_client = Client(clientsocket)
			self.clients.append(new_client)
			
			Thread(target=self.handle_client,args=(new_client,)).start()
			
		return


if __name__ == '__main__':
	print("Starting server...")
	
	Server()
