# Standard library imports
import json                                             # For working with the JSON contents
import os                                               # For interacting with file system
import random                                           # For generating random numbers

# Third-party imports                   
from Crypto.Cipher import DES3, AES                     # For encryption and decryption operation
from cryptography.hazmat.primitives import padding      # For cryptographic padding
import secrets                                          # For generating cryptographically secure random numbers

class Encryption:
    """
    This class contains necessary encryption functions.

    Methods:
        select_file(self):
            This function is responsible for displaying the Choose File option in the GUI for performing encryption.
        read_file_contents(self):
            This function will read the content of a file and return the filename and content which is read from the file selected to be encrypted.
        salt_gen(self):
            This function will generate a random value of a salt.
        kdf_val_gen(self):
            This function will generate a random number for kdf_value.
        update_password_feedback(*args):
            This function will capture the password value enter in the GUI provide a message to user based on the password received.
        encrypt(self, data, algorithm, hmac_key, encryption_key, kdf_iter, salt)::
            This function will perform the encryption of the selected file.
        encrypt_controller(self):
            This function is responsible for handing the encryption process i.e. it orchestrates the flow of encryption.
    """
    def select_file(self):
        """
        Displays user the option to select a file in GUI for encryption.
        """
        file_entry_encrypt.delete(0, tk.END)
        filetypes = (('text files', '*.txt'), ('All files', '*.*'))
        initial_path = os.getcwd()
        filename = fd.askopenfilename(title='Open a file', initialdir=initial_path, filetypes=filetypes)
        file_entry_encrypt.insert(0, filename)

    def read_file_contents(self):
        """
        Reads the content of the file to be encrypted.

        Returns:
            tuple: A tuple containing the name of the file and contents present in the file selected to be encrypted
        """
        filename = file_entry_encrypt.get()
        try:
            with open(filename, "rb") as f:
                contents = f.read()
            return filename, contents
        except exceptions.FileReadError as e:
            file_label_encrypt.config(text="File could not be read", fg="red")
            raise
        except FileNotFoundError:
            file_label_encrypt.config(text="File not found!", fg="red")
            raise

    def salt_gen(self):
        """
        Generates a random 16bit salt.

        Returns:
            Random salt.
        """
        return secrets.token_bytes(16)

    def kdf_val_gen(self):
        """
        Generates a random value for kdf.

        Returns:
            Random kdf value
        """
        return random.randint(10000, 1000000)

    def update_password_feedback(*args):
        """
        This function receives the password entered by user character by character and informs them about its validity.
        """
        password_length = len(password_var.get())
        if password_length== 0:
            password_feedback_label.config(text="Password cannot be blank", fg="blue")
        elif password_length < 8:
            password_feedback_label.config(text="Enter stronger password", fg="red")
        else:
            password_feedback_label.config(text="Valid Password", fg="green")
