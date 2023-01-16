# Import necessary libraries
import base64
import os
import hashlib
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Class to add colour to terminal text
class colour:
   GREEN = '\033[92m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def check_password(password):
    # Hash value for master password
    # current password is "password"
    master_hash = b'J\x15\xa3\x0fL\xfbi|8\x9c\x91\xb7\x15\xe7\xbf,U\xa5l\xcf%\xc18\xa5i\x96%\xe3\xec\xca\xb6\x8d\xdc}\tB+\xce)~\xdd/\xae\xcf=\xebF?hZ\x0f\x99\xe6\x17\x15\x1f\xe6\x1b\x18\xd0\xc4\xed\xbfM'

    # Salt value for password hash function
    password_salt = b"\xc9\xf3R\xe7\x97Q\xfa\x14\xb6&\xe9\xd7D\x82\xf7/"

    # Hashing password attempt, 5 million iterations SHA256
    hashattempt = hashlib.pbkdf2_hmac('sha512',password,password_salt, 5000000)
    # Return if entered password hash == master password hash
    return hashattempt == master_hash

def establish_key(password):
    # Generate encryption key using master password
    # Ensures that if master hash is changed when files are encrypted, they cannot be decrypted through use of KDF
    # Salt value for key
    key_salt = b"v)\x1c\x18\xad\xebn\xe3s\xaf\xc2\xc4\xc6\xce\xe1o"
    
    # Initialise Key Derivation Function settings
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA512(),
        length = 32,
        salt = key_salt,
        iterations = 5000000,
    )
    # Create key using KDF and password
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)

def get_files(script_name):
    # Function to gather all files in current working directory in array
    files = []
    for file in os.listdir():
        # Exclude directories and python script
        if os.path.isfile(file) and file != script_name and file != "flag.txt":
            files.append(file)
    # Return files array
    return files

def encrypt_files(key, files):
    # Function to encrypt files
    for file in files:
        # Read file contents
        with open(file, "rb") as thefile:
            contents = thefile.read()
       
       # Encrypt file contents
        contents_encrypted = key.encrypt(contents)
       
       # Write encrypted content to file
        with open(file, "wb") as thefile:
            thefile.write(contents_encrypted)

def decrypt_files(key, files):
    # Function to decrypt files
    for file in files:
        # Read file contents
        with open(file, "rb") as thefile:
            contents = thefile.read()
        
        # Decrypt files contents
        contents_decrypted = key.decrypt(contents)

        # Write decrypted content to file
        with open(file, "wb") as thefile:
            thefile.write(contents_decrypted)

def encryption_check(flag):
    # Check to see if files are currently encrypted or unencrypted using flag.txt.
    with open(flag) as f:
        if "0" in f:
            # Return False if unencrypted
            return False
        else:
            # Return True if encrypted
            return True

if __name__ == '__main__':
    # Establish knowledge of master password
    while True:
        password = (getpass.getpass(prompt='Enter password: ', stream=None)).encode()   
        print("\nVerifying password...")
        if check_password(password):
            print(f"{colour.GREEN}Password verified{colour.END}")
            break
        else:
            print(f"{colour.RED}Incorrect password{colour.END}")

    # Establish key for encryption using master password
    print("Generating key 🔑")
    key = establish_key(password)
    print(f"{colour.GREEN}Key generated{colour.END}")

    # Create array of files in current directory
    files = get_files(os.path.basename(__file__))

    # Determine current encryption status of files using flag text file
    encryption_status = encryption_check("flag.txt")

    while True:
        # If files currently encrypted
        if encryption_status == True:
            print(f"\nYour files are currently {colour.GREEN}encrypted{colour.END} 🔒")
            decision = str(input("Would you like to decrypt your files (y/n): "))

        # If files currently unencrypted
        elif encryption_status == False:
            print(f"\nYour files are currently {colour.RED}unencrypted{colour.END} 🔓")
            decision = str(input("Would you like to encrypt your files (y/n): "))
        
        # Files encrypted --> unencrypted
        if encryption_status and decision == "y":
            decrypt_files(key, files)
            f = open("flag.txt", "w")
            f.write("1")
            f.close()
            print("Your files are now decrypted")
    
        # Files unencrypted --> encrypted
        elif not encryption_status and decision == "y":
            encrypt_files(key, files)
            f = open("flag.txt", "w")
            f.write("0")
            f.close()
            print("Your files are now encrypted")

        # Choosing no change in encryption
        elif decision == "n":
            pass

        # Repeat while loop if input is not "y" or "n" (invalid input)
        else:
            print("Invalid input")
            continue

        # Exit after encryption / decryption
        print("Goodbye")
        break