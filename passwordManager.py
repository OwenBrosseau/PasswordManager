import os, json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from tkinter import ttk
import tkinter as tk
import random
import pyperclip

# Storage format:
# dict = {siteName:[siteUsername, sitePassword]...}

# Data interaction functions

def hash(text):
    textBytes = text.encode('utf-8')
    textHash = SHA256.new(data=textBytes)
    textDigest = textHash.hexdigest()
    return textDigest

def pswdToKey(pswd):
    segment1 = pswd[:16]
    segment2 = pswd[16:32]
    segment3 = pswd[32:48]
    segment4 = pswd[48:]
    firstHalf = bytes([a ^ b for a, b in zip(segment1, segment2)])
    secondHalf = bytes([a ^ b for a, b in zip(segment3, segment4)])
    return bytes([a ^ b for a, b in zip(firstHalf, secondHalf)])

def createUser(user, pswd, pswdConfirm):
    if (pswd != pswdConfirm):
        return False
    
    nameDigest = hash(user)
    pswdDigest = hash(pswd)

    pswdDigest2 = hash(pswdDigest)

    with open("data/logindata", "w") as loginFile:
        loginFile.write(nameDigest + "," + pswdDigest2)

    return pswdToKey(pswdDigest.encode('utf-8'))

def verifyUser(name, pswd):
    key = hash(pswd)

    with open("data/logindata", "r") as loginFile:
        loginText = loginFile.read()
        list = loginText.split(",")
        nameHash = list[0]
        pswdHash = list[1]
    
    if hash(name) != nameHash or hash(key) != pswdHash:
        return False
    
    return pswdToKey(key.encode('utf-8'))

def readPasswords(key):
    if not os.path.isfile("data/passwords"):
        return {}
    
    with open("data/passwords", "rb") as pswdFile:
        nonce, tag, ciphertext = [ pswdFile.read(x) for x in (16, 16, -1) ]

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    pswdString = data.decode('utf-8')
    passwords = json.loads(pswdString)
    return passwords

def writePasswords(key, passwords):
    pswdBytes = json.dumps(passwords).encode('utf-8')
    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(pswdBytes)

    with open("data/passwords", "wb") as pswdFile:
        [pswdFile.write(x) for x in (cipher.nonce, tag, ciphertext)]
    
    return True

# Create user helper functions + GUI

def create(frame, user, pswd, pswdConfirm):
    key = createUser(user, pswd, pswdConfirm)
    if not key:
        return
    else:
        passwordListWindow(key)
        frame.destroy()

def createUserWindow():
    createUserFrame = tk.Tk()
    createUserFrame.config(width=250, height=250)
    createUserFrame.title("Create User")

    userLabel = ttk.Label(createUserFrame, text="Username: ")
    userLabel.place(x=30, y=80)
    userField = ttk.Entry(createUserFrame, width=15)
    userField.place(x=90, y=80)

    pswdLabel = ttk.Label(createUserFrame, text="Password: ")
    pswdLabel.place(x=30, y=110)
    pswdField = ttk.Entry(createUserFrame, width=15)
    pswdField.place(x=90, y=110)

    confLabel = ttk.Label(createUserFrame, text="Confirm: ")
    confLabel.place(x=30, y=140)
    pswdFieldConfirm = ttk.Entry(createUserFrame, width=15)
    pswdFieldConfirm.place(x=90, y=140)

    btnCreate = ttk.Button(createUserFrame, text ="Create User", command=lambda:create(createUserFrame, userField.get(), pswdField.get(), pswdFieldConfirm.get()))
    btnCreate.place(x=50, y=170)

# Log in helper functions + GUI

def logIn(textLabel, name, pswd, frame):
    key = verifyUser(name, pswd)
    if not key:
        textLabel.config(text="Username or Password was invalid, try again")
        return
    else:
        passwordListWindow(key)
        frame.destroy()

def loginWindow():
    loginFrame = tk.Tk()
    loginFrame.config(width=300, height=160)
    loginFrame.title("Log In")

    textLabel = ttk.Label(loginFrame, text="Welcome! Please log in!")
    textLabel.place(x=50, y=20)

    usernameField = ttk.Entry(loginFrame, width=15)
    usernameField.place(x=50, y=50)

    pswdField = ttk.Entry(loginFrame, show="*", width=15)
    pswdField.place(x=50, y=80)

    btnLogin = ttk.Button(loginFrame, text ="Log In", command=lambda:logIn(textLabel, usernameField.get(), pswdField.get(), loginFrame))
    btnLogin.place(x=50, y=110)

# List passwords helper functions + GUI

def refreshPasswords(selectBox, btnSelect, key):
    passwords = readPasswords(key)
    if len(passwords) > 0:
        btnSelect['state'] = 'enabled'
    else:
        btnSelect['state'] = 'disabled'
    selectBox['values'] = list(passwords.keys())

def passwordListWindow(key):
    passwords = readPasswords(key)

    pswdListFrame = tk.Tk()
    pswdListFrame.config(width=300, height=160)
    pswdListFrame.title("Saved Passwords")

    selectBox = ttk.Combobox(pswdListFrame, state="readonly", values=list(passwords.keys()))
    selectBox.place(x=50, y=20)
    if len(passwords) > 0:
        btnSelect = ttk.Button(pswdListFrame, text ="Select Password", command=lambda:viewPasswordWindow(selectBox.get(), key))
        btnSelect.place(x=50, y=50)
    else:
        btnSelect = ttk.Button(pswdListFrame, text ="Select Password", state="disabled", command=lambda:viewPasswordWindow(selectBox.get(), key))
        btnSelect.place(x=50, y=50)

    btnAdd = ttk.Button(pswdListFrame, text ="Add New Password", command=lambda:addPasswordWindow(key))
    btnAdd.place(x=50, y=80)

    btnAdd = ttk.Button(pswdListFrame, text ="Refresh Passwords", command=lambda:refreshPasswords(selectBox, btnSelect, key))
    btnAdd.place(x=50, y=110)

# View password helper functions + GUI

def copyPassword(pswd, btn):
    pyperclip.copy(pswd)
    btn.config(text="Copied to Clipboard")

def deletePassword(title, passwords, key, pswdFrame):
    del passwords[title]
    writePasswords(key, passwords)
    pswdFrame.destroy()

def viewPasswordWindow(title, key):
    passwords = readPasswords(key)

    if title not in list(passwords.keys()):
        return

    pswdFrame = tk.Tk()
    pswdFrame.config(width=250, height=180)
    pswdFrame.title(title)

    userLabel = ttk.Label(pswdFrame, text=passwords[title][0])
    userLabel.place(x=50, y=30)

    pswdLabel = ttk.Label(pswdFrame, text=passwords[title][1])
    pswdLabel.place(x=50, y=60)

    btnCopy = ttk.Button(pswdFrame, text ="Copy Password", command=lambda:copyPassword(passwords[title][1], btnCopy))
    btnCopy.place(x=50, y=90)

    btnDelete = ttk.Button(pswdFrame, text ="Delete Password", command=lambda:deletePassword(title, passwords, key, pswdFrame))
    btnDelete.place(x=50, y=120)

# Add new password helper functions + GUI

def addPassword(frame, textLabel, key, title, name, pswd, pswdConfirm):
    passwords = readPasswords(key)
    if (title in list(passwords.keys())):
        textLabel.config(text="Title already exists")
        return
    if pswd != pswdConfirm:
        textLabel.config(text="Passwords do not match")
        return
    passwords[title] = [name, pswd]
    writePasswords(key, passwords)
    frame.destroy()

def generatePassword(pswdField, pswdFieldConfirm):
    length = 12
    password = ""
    for i in range(length):
        password += chr(random.randint(33, 122))

    pswdField.delete(0, tk.END)
    pswdField.insert(0, password)

    pswdFieldConfirm.delete(0, tk.END)
    pswdFieldConfirm.insert(0, password)
    
def addPasswordWindow(key):
    addPswdFrame = tk.Tk()
    addPswdFrame.config(width=250, height=250)
    addPswdFrame.title("Add New Password")

    textLabel = ttk.Label(addPswdFrame, text="Enter Password Details:")
    textLabel.place(x=50, y=20)

    titleLabel = ttk.Label(addPswdFrame, text="Title: ")
    titleLabel.place(x=30, y=50)
    titleField = ttk.Entry(addPswdFrame, width=15)
    titleField.place(x=90, y=50)

    userLabel = ttk.Label(addPswdFrame, text="Username: ")
    userLabel.place(x=30, y=80)
    usernameField = ttk.Entry(addPswdFrame, width=15)
    usernameField.place(x=90, y=80)

    pswdLabel = ttk.Label(addPswdFrame, text="Password: ")
    pswdLabel.place(x=30, y=110)
    pswdField = ttk.Entry(addPswdFrame, width=15)
    pswdField.place(x=90, y=110)

    confLabel = ttk.Label(addPswdFrame, text="Confirm: ")
    confLabel.place(x=30, y=140)
    pswdFieldConfirm = ttk.Entry(addPswdFrame, show="*", width=15)
    pswdFieldConfirm.place(x=90, y=140)

    btnPass = ttk.Button(addPswdFrame, text ="Auto Generate Password", command=lambda:generatePassword(pswdField, pswdFieldConfirm))
    btnPass.place(x=50, y=170)

    btnAdd = ttk.Button(addPswdFrame, text ="Add Password", command=lambda:addPassword(addPswdFrame, textLabel, key, titleField.get(), usernameField.get(), pswdField.get(), pswdFieldConfirm.get()))
    btnAdd.place(x=70, y=200)

# Run appropriate starting window

if not os.path.isfile("data/logindata"):
    if (os.path.isfile("data/passwords")):
        os.remove("data/passwords")
    createUserWindow()
else:
    loginWindow()

tk.mainloop()