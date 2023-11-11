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

    def encrypt(self, data, algorithm, hmac_key, encryption_key, kdf_iter, salt):
        """
        Performs the encryption operation.

        Args:
            data: The content that is to be encrypted.
            algorithm: The algorithm that needs to be used for encryption.
            hmac_key: The hmac key that needs to be used for encryption.
            kdf_iter: The number of kdf iterations that needs to be used.
            salt: The salt that needs to be used.
        
        Returns:
            bytes: Series of bytes containing encrypted data and metadata.
        """
        self.data = data
        self.algorithm = algorithm
        self.hmac_key = hmac_key
        self.enc_key = encryption_key
        self.kdf_iter = kdf_iter
        self.salt = salt

        block_size = 8 if self.algorithm == '3DES' else 16
        iv = os.urandom(block_size)
        
        if algorithm == '3DES':
            encryption_key = encryption_key[:24]
            cipher = DES3.new(encryption_key, DES3.MODE_CBC, iv)
        elif algorithm == 'AES128':
            encryption_key = encryption_key[:16]
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        elif algorithm == 'AES256':
            encryption_key = encryption_key[:32]
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        else:
            raise ValueError('Invalid algorithm')

        # padding data to a multiple of block size
        data += (block_size - len(data) % block_size) * bytes([block_size - len(data) % block_size])

        # Try encrypting the data else throw an exception.
        try:
            encrypted_data = cipher.encrypt(bytes(data))
        except Exception as e:
            error_label.config(text="Encryption failed", fg="yellow", bg="gray")
            raise exceptions.EncryptionError("Encryption failed: " + str(e))

        key_info = KeyInfo()

        # Get the encryption and hashing algorithm 
        chosen_hash_algo = hashing_algo_combo.get()
        chosen_encryption_algo = encryption_algo_combo.get()

        __, hmac_hash_module = key_info.key_hash(chosen_hash_algo)

        # Compute the hmac
        hmac_val = hmac.new(self.hmac_key, iv + encrypted_data, hmac_hash_module).digest()
        salt_base64 = self.salt.hex()

        # Put the metadata in dictionary.
        info_to_decrypt = {
            "enc_algo": chosen_encryption_algo,
            "hash_algo": chosen_hash_algo,
            "kdf_iter": self.kdf_iter,
            "salt": salt_base64
        }
        info_bytes = json.dumps(info_to_decrypt).encode('utf-8')
        concatenated_bytes = encrypted_data + iv + hmac_val + info_bytes + len(info_bytes).to_bytes(2, byteorder='big')
    
        # Return the encrypted data with iv, hmac, metadata
        return concatenated_bytes
    
    def encrypt_controller(self):
        """
        Orchestrates the encryption operation.
        """
        filename, contents = self.read_file_contents()
        salt = self.salt_gen()
        kdf_iter = self.kdf_val_gen()
        password = encrypt_password_entry.get()
        user_input_validator = UserInputValidation()

        key_info = KeyInfo()
        
        # Obtain the encryption and hashing algorithm chosen by the user.
        chosen_encryption_algo = encryption_algo_combo.get()
        chosen_hash_algo = hashing_algo_combo.get()

        if(user_input_validator.is_password_valid(password)):
            # Perform benchmark testing with different iterations.
            # key_info.benchmark(chosen_hash_algo, password, salt)

            enc_key, hmac_key = key_info.derive_keys(chosen_encryption_algo, chosen_hash_algo, password, kdf_iter, salt)
            enc_data = self.encrypt(contents, chosen_encryption_algo, hmac_key, enc_key, kdf_iter, salt)
            
            # Write the encrypted data in '.enc' format.
            filename = filename + '.enc'
            f = open(filename, 'wb')
            f.write(enc_data)
            f.close()
            encrypt_label.config(text=f"File encrypted and saved to:\n{os.path.abspath(filename)}", fg="yellow", bg="gray")


class Decryption:
    """
    This class contains necessary decryption functions.

    Methods:
        display_open_file_decrypt(self):
            This function is responsible for displaying the Choose File option in the GUI for performing decryption.
        def read_decrypted_file_contents(self):
            This function reads the .enc file which is in decrypted form and returns the name of the file and its contents.
        extract_metadata_length(self, encrypted_data):
            This function provides with the values needed to extract the metadata.
        extract_encryption_metadata(self, encrypted_data, metadata_len, metadata_len_bytes_int):
            This function extracts fields from the metadata that is needed during the decryption.
        decrypt_data(self, encrypted_data, password):
            This function performs the decryption operation.
        output_decrypted_file(self, dec_data, filename):
            This function outputs the file which is decrypted into its original format.
        def clear_decrypted_textbox(self, dec_data):
            This function is used to clear the decrypted textbox in the GUI on subsequent decryption operation.    
    """
    def display_open_file_decrypt(self):
        """
        Displays the user the option to select a file in GUI for decryption.
        """
        file_entry_decrypt.delete(0, tk.END)
        filetypes = (('encrypted files', '*.enc'), ('All files', '*.*'))
        initial_path = os.getcwd()
        filename = fd.askopenfilename(title='Open a file', initialdir=initial_path, filetypes=filetypes)
        file_entry_decrypt.insert(0, filename)
    
    def read_decrypted_file_contents(self):
        """
        Reads the content of file within '.enc' format.

        Returns:
            tuple: A tuple containing the name of the file and its contents to be decrypted.
        """
        filename = file_entry_decrypt.get()
        user_input_validator = UserInputValidation()
        try:
            # Check if the file extension of the file to decrypt is in '.enc' format.
            if(user_input_validator.is_decrypt_file_extension_valid(filename)):
                with open(filename, 'rb') as f:
                    contents = f.read()
                    return filename, contents
        except exceptions.InvalidFileExtensionError as e:
            file_label_decrypt.config(text=str(e), fg="red")
            raise
        except FileNotFoundError:
            file_label_decrypt.config(text="File not found!", fg="red")
            raise

    def extract_metadata_values(self, encrypted_data):
        """
        Calculates the values for metadata field extraction

        Args:
            encrypted_data: Data that is read from the encrypted file.
        
        Returns:
            tuple: A tuple containing the length of the in both byte string and integer format.
        """
        # Extracts last two bytes of encrypted data
        self.metadata_bytes = encrypted_data[len(encrypted_data) - 2 : len(encrypted_data)]

        # Converts metadata_len_bytes from byte string to integer value
        self.metadata_len_int = int.from_bytes(self.metadata_bytes, 'big')

        # Creates new byte string representing the length of metadata bytes.
        self.metadata_len_bytes = len(self.metadata_bytes).to_bytes(2, byteorder='big')

        # Converts metadata_bytes_int from byte string to integer.
        self.metadata_len = int.from_bytes(self.metadata_len_bytes, 'big')
        return self.metadata_len_int, self.metadata_len