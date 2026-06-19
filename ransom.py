import cryptography
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64
import getpass
import os

def load_salt():
    try:
        return open("salt.salt", "rb").read()
    except FileNotFoundError:
        print("Failede to load existing salt, most likely that the file does not exist.")
        return

def key_generation(password, salt_size):
    if os.path.exists("salt.salt"):
        print("Detected existing salt file. Using that instead....")
        salt = load_salt()
    else:
        salt = os.urandom(salt_size)

        with open("salt.salt", "wb") as file:
          file.write(salt)

    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encryption(key, file):
    fern = Fernet(key)

    with open(file, "rb") as f:
        file_data = f.read()

    encrypted_data = fern.encrypt(file_data)

    with open(file, "wb") as file_:
        file_.write(encrypted_data)

    os.rename(file, file + ".encrypted")

def encrypt_folder(folder_path, key):
    for (root, dirs, files) in os.walk(folder_path):
        for index, item in enumerate(files, start=1):
            full_path = os.path.join(root, item)

            if index == 1:
                print("-"*55)

            print(f"[{index}] Encrypting {full_path}")

            encryption(key, full_path)

def decryption(key, filetarget):
    f = Fernet(key)
    file_data = open(filetarget, "rb").read()

    try:
        decrypted_data = f.decrypt(file_data)
    except InvalidToken:
        print(f"Failed to decrypt file '{filetarget}'. Possible invalid password")
        return
    else:
        print(f"Successfully decrypted file '{filetarget}'")
    with open(filetarget, "wb") as file:
        file.write(decrypted_data)

    os.rename(filetarget, filetarget.replace(".encrypted", ""))

def decrypt_folder(key, folderpath):
    for (root, dirs, files) in os.walk(folderpath):
        for i, item in enumerate(files, start=1):
            fullpath = os.path.join(root, item)

            print(f"[{i}] Decrypting file: {fullpath}")

            decryption(key, fullpath)

def main():
    target = input("File/Folder to encrypt or decrypt:\t").strip()

    encrypt_or_decrypt = input("Encrypt/Decrypt:\t")

    if encrypt_or_decrypt.lower() == "encrypt":
        password = getpass.getpass("Enter password for encryption:\t")
    elif encrypt_or_decrypt.lower() == "decrypt":
        password = getpass.getpass("Enter password for decryption:\t")

    key = key_generation(password, 16)

    if encrypt_or_decrypt.lower() == "encrypt":
        if os.path.isdir(target):
            encrypt_folder(target, key)
        elif os.path.isfile(target):
            encryption(key, target)
    elif encrypt_or_decrypt.lower() == "decrypt":
        if os.path.isdir(target):
            decrypt_folder(key, target)
        elif os.path.isfile(target):
            decryption(key, target)

if __name__=="__main__":
    try:
        main()
    except PermissionError:
        pass
