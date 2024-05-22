'''
Defines several custom Exception classes that can be used to handle different types of errors that may occur in a Python program.
'''

class InvalidFileExtensionError(Exception):
    pass

class FileReadError(Exception):
    pass

class BlankInputException(Exception):
    pass