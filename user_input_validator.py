# Local imports
import exceptions

class UserInputValidation:
    """
    This is a class which provides functionalities for user input validation.

    Methods:
        is_encrypt_file_extension_valid(self, extension):
            Checks whether the user entered file extension is valid for encryption.
        is_decrypt_file_extension_valid(self, file_path):
            Checks whether the user entered file extension is valid for decryption.
        is_password_valid(self, password):
            Checks whether the user entered password is a valid password that can be used for encryption.
    """
    def is_decrypt_file_extension_valid(self, file_path):
        """
        Checks the extension of file before decryption.

        Args:
            extension: Extension of the chosen file.
        """
        if file_path.endswith('.enc'):
            return True
        else:
            raise exceptions.InvalidFileExtensionError("Invalid file extension! Please use a file with .enc extension.")
    
    def is_password_valid(self, password):
        """
        Checks the user entered password on whether it satisfies the given criteria.

        Args:
            password: Password entered by the user.
        """
        password_length = len(password)
        if password_length == 0:
            raise exceptions.BlankInputException("Password cannot be blank")
        elif password_length < 8:
            raise exceptions.PasswordTooShortException("Enter stronger password")
        else:
            return True