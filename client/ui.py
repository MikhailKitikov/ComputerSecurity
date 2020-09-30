from copy import copy
from tkinter import *
from tkinter import messagebox
import json
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
from hashlib import sha256
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

MSGLEN = 512
IP = 'localhost'
PORT = 5000


def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data


def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding
    
   
def listen_if_ok():
	# listen if ok
    msg = client.aes.decrypt(client.sock.recv(MSGLEN).strip(b'\r\n')).decode()
    if msg == 'ok':
        pass
    elif msg == '999':
        client.retrieve_session_key()
    else:
        raise RuntimeError("operation failed")


############ helper funcs ###########

class Notifier:

    @classmethod
    def show_message(cls, title, text, screen, delete_parent=False):
        global message_screen
        cls.screen = screen
        cls.delete_parent = delete_parent
        message_screen = Toplevel(screen)
        message_screen.resizable(False, False)
        message_screen.title(title)
        message_screen.geometry("200x200")
        Label(message_screen, text=text, height='5').pack()
        Button(message_screen, text="OK", command=cls.delete_message_screen, height='5', width='5').pack()

    @classmethod
    def delete_message_screen(cls):
        message_screen.destroy()
        if cls.delete_parent:
            cls.screen.destroy()


def login_verify():
    # send login request

    ciphertext = client.aes.encrypt('login')
    client.sock.sendall(ciphertext)
    listen_if_ok()

    # read credentials
    username_info = username_verify.get()
    password_info = password_verify.get()

    # send credentials
    encoded_pass = sha256()
    encoded_pass.update(password_info.encode())
    client.sock.sendall(client.aes.encrypt(username_info))
    client.sock.sendall(client.aes.encrypt(encoded_pass.hexdigest()))

    # clear
    password_login_entry.delete(0, END)

    # get response
    response = client.aes.decrypt(client.sock.recv(MSGLEN).strip(b'\r\n')).decode()
    if response == '1':
        Notifier.show_message('Fail', 'User does not exist', login_screen)
        username_login_entry.delete(0, END)
    elif response == '2':
        Notifier.show_message('Fail', 'Invalid password', login_screen)
    elif response == '0':
        Notifier.show_message('Login', 'Login success!', login_screen, True)
        notepad_menu()
    else:
        print(response)
        raise RuntimeError('Unknown response')


def register_user():
    # send register request
    ciphertext = client.aes.encrypt('register')
    client.sock.sendall(ciphertext)
    listen_if_ok()

    # read credentials
    username_info = username.get()
    password_info = password.get()

    # send credentials
    encoded_pass = sha256()
    encoded_pass.update(password_info.encode())
    client.sock.sendall(client.aes.encrypt(username_info))
    client.sock.sendall(client.aes.encrypt(encoded_pass.hexdigest()))

    # get response
    response = client.aes.decrypt(client.sock.recv(MSGLEN).strip(b'\r\n')).decode()
    if response == '1':
        Notifier.show_message('Fail', 'User already exists', register_screen)
    elif response == '0':
        username_entry.delete(0, END)
        password_entry.delete(0, END)
        Notifier.show_message('Register', 'Register success!', register_screen, True)
        notepad_menu()
    else:
        raise RuntimeError('Unknown response')


def delete_login_screen():
    login_screen.destroy()


def delete_register_screen():
    register_screen.destroy()


############### notepad ###################

def notepad_menu():
    global notepad_menu_screen
    notepad_menu_screen = Toplevel(main_screen)
    notepad_menu_screen.resizable(False, False)
    notepad_menu_screen.title("Notepad menu")
    notepad_menu_screen.geometry("600x600")
    Label(notepad_menu_screen, text="", height='15').pack()

    def on_closing():
        notepad_menu_screen.destroy()
        client.sock.sendall(client.aes.encrypt('logout'))
        listen_if_ok()

    notepad_menu_screen.protocol("WM_DELETE_WINDOW", on_closing)

    Button(notepad_menu_screen, text="Create", width=50, height=5, command=create_notepad).pack()
    Label(notepad_menu_screen, text="", height='2').pack()
    Button(notepad_menu_screen, text="Edit", width=50, height=5, command=edit_notepad).pack()
    Label(notepad_menu_screen, text="", height='2').pack()
    Button(notepad_menu_screen, text="Delete", width=50, height=5, command=delete_notepad).pack()


def save_text():
    text = inputtxt.get("1.0", "end-1c")

    client.sock.sendall(client.aes.encrypt('save_text'))
    listen_if_ok()

    encrypted = encrypt(password, text)

    client.sock.sendall(msg.encode(filename))
    client.sock.sendall(msg.encode(encrypted))

    Notifier.show_message('Success', 'Text saved', save_as_screen, True)


def save_as():
    global save_as_screen
    save_as_screen = Toplevel()
    save_as_screen.resizable(False, False)
    save_as_screen.title("Save as")
    save_as_screen.geometry("400x400")
    Label(save_as_screen, text="", height='10').pack()

    global filename
    filename = StringVar()
    filename_lable = Label(save_as_screen, width=20, height=3, text="Filename * ")
    filename_lable.pack()
    filename_entry = Entry(save_as_screen, width=30, textvariable=filename)
    filename_entry.pack()
    Button(save_as_screen, text="Save", width=10, height=1, command=save_text).pack()


def create_notepad():
    global create_notepad_screen
    create_notepad_screen = Toplevel(notepad_menu_screen)
    create_notepad_screen.resizable(False, False)
    create_notepad_screen.title("Create notepad")
    create_notepad_screen.geometry("600x600")

    global inputtxt
    inputtxt = Text(create_notepad_screen, height=50,
                    width=85,
                    bg="white")
    display = Button(create_notepad_screen, height=3,
                     width=40,
                     text="Save as",
                     command=lambda: save_as())
    cancel = Button(create_notepad_screen, height=3,
                    width=40,
                    text="Cancel",
                    command=lambda: create_notepad_screen.destroy())

    inputtxt.grid(row=0, column=0, columnspan=2, ipadx=0)
    display.grid(row=1, column=0, ipadx=0)
    cancel.grid(row=1, column=1, ipadx=0)


def edit_notepad():
    global edit_notepad_screen
    edit_notepad_screen = Toplevel(notepad_menu_screen)
    edit_notepad_screen.resizable(False, False)
    edit_notepad_screen.title("Edit notepad")
    edit_notepad_screen.geometry("600x600")
    Label(edit_notepad_screen, text="").pack()


def delete_notepad():
    global delete_notepad_screen
    delete_notepad_screen = Toplevel(notepad_menu_screen)
    delete_notepad_screen.resizable(False, False)
    delete_notepad_screen.title("Delete notepad")
    delete_notepad_screen.geometry("600x600")
    Label(delete_notepad_screen, text="").pack()


############### login ###################

def login():
    global login_screen
    login_screen = Toplevel(main_screen)
    login_screen.resizable(False, False)
    login_screen.title("Login")
    login_screen.geometry("400x400")
    Label(login_screen, text="", height='10').pack()

    def on_closing():
        login_screen.destroy()
        client.sock.sendall(client.aes.encrypt('logout'))
        listen_if_ok()

    login_screen.protocol("WM_DELETE_WINDOW", on_closing)

    global username_verify
    global password_verify

    username_verify = StringVar()
    password_verify = StringVar()

    global username_login_entry
    global password_login_entry

    Label(login_screen, width=20, height=3, text="Username * ").pack()
    username_login_entry = Entry(login_screen, width=30, textvariable=username_verify)
    username_login_entry.pack()
    Label(login_screen, text="").pack()
    Label(login_screen, width=20, height=3, text="Password * ").pack()
    password_login_entry = Entry(login_screen, width=30, textvariable=password_verify, show='*')
    password_login_entry.pack()
    Label(login_screen, text="").pack()
    Button(login_screen, text="Login", width=20, height=3, command=login_verify).pack()


##################### register ####################

def register():
    global register_screen
    register_screen = Toplevel(main_screen)
    register_screen.resizable(False, False)
    register_screen.title("Register")
    register_screen.geometry("500x500")
    Label(register_screen, text="", height='10').pack()

    def on_closing():
        register_screen.destroy()
        client.sock.sendall(client.aes.encrypt('logout'))
        listen_if_ok()

    register_screen.protocol("WM_DELETE_WINDOW", on_closing)

    global username
    global password
    global username_entry
    global password_entry
    username = StringVar()
    password = StringVar()

    username_lable = Label(register_screen, width=20, height=3, text="Username * ")
    username_lable.pack()
    username_entry = Entry(register_screen, width=30, textvariable=username)
    username_entry.pack()
    password_lable = Label(register_screen, width=20, height=3, text="Password * ")
    password_lable.pack()
    password_entry = Entry(register_screen, width=30, textvariable=password, show='*')
    password_entry.pack()
    Label(register_screen, text="").pack()
    Button(register_screen, text="Register", width=20, height=3, command=register_user).pack()


############## welcome page ###################

def main_account_screen():
    global main_screen

    main_screen = Tk()  # create a GUI window
    main_screen.resizable(False, False)
    main_screen.geometry("600x600")  # set the configuration of GUI window
    main_screen.title("Account Login")  # set the title of GUI window

    def on_closing():
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            main_screen.destroy()
            client.sock.sendall(client.aes.encrypt('exit'))
            listen_if_ok()

    main_screen.protocol("WM_DELETE_WINDOW", on_closing)

    # create Login Button
    Label(text="", height='20').pack()
    Button(text="Login", height="4", width="50", command=login).pack()
    Label(text="").pack()

    Button(text="Register", height="4", width="50", command=register).pack()

    # start the GUI
    main_screen.mainloop()


############ socket ##################

class Client:

    def __init__(self, ip, port):

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((ip, port))

        if os.path.isfile('rsa/rsa_priv'):
            with open('rsa/rsa_pub.pem', 'rb') as file:
                self.pub = rsa.PublicKey.load_pkcs1(file.read())
            with open('rsa/rsa_priv.pem', 'rb') as file:
                self.priv = rsa.PrivateKey.load_pkcs1(file.read())
        else:
            (self.pub, self.priv) = rsa.newkeys(1024)
            with open('rsa/rsa_pub.pem', 'wb+') as file:
                file.write(self.pub.save_pkcs1('PEM'))
            with open('rsa/rsa_priv.pem', 'wb+') as file:
                file.write(self.priv.save_pkcs1('PEM'))

        # send rsa publickey to server
        msg = self.pub.save_pkcs1('PEM').decode()
        sent = self.sock.sendall(msg.encode())
        if sent is not None:
            raise RuntimeError("socket connection broken")

    def retrieve_session_key(self):
        # get session key
        key = rsa.decrypt(self.sock.recv(MSGLEN), self.priv)
        iv = key
        self.aes = AES.new(key, AES.MODE_CFB, iv)


############ entrypoint ################

if __name__ == '__main__':
    # connect to server
    global client
    client = Client(IP, PORT)

    main_account_screen()
