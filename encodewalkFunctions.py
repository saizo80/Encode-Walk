import os, sys, subprocess
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class encodewalk():
    def __init__(self):
        pass
    
    def __encrypt(self, file_to_encrypt, verbose):
        """Gets data from file, encrypts, and writes to file
        
        Args:
            file_to_encrypt (str): The path to the unencrypted
                file to read data in.
            verbose (bool): A flag used to determine where to 
                print status to console.
        
        Returns: None
        """
        
        input_file = open(file_to_encrypt, 'rb')
        
        # make a key of random bytes
        key = get_random_bytes(32) 
        cipher = AES.new(key, AES.MODE_CFB)
        # split the path to the file
        file_name = file_to_encrypt.split('/') 
        # encrypt the file name and replace the current in the list
        file_name[len(file_name) - 1] = cipher.encrypt(str.encode(file_name[len(file_name) - 1])).hex()
        # join the list back 
        toFile = "/".join(file_name)
        # make sure that a double // doesn't appear in file path
        toFile = toFile.replace("//","/")
        # create the new file at the path + binff (marker for encrypted files)
        output_file = open(toFile + ".binff", 'wb')
        # write the iv
        output_file.write(cipher.iv)
        # write the first 16 bytes of the key after the iv
        output_file.write(key[:16])

        # use a buffer to encrypt and write the data
        buffer = input_file.read(65536)
        while len(buffer) > 0:
            ciphered_bytes = cipher.encrypt(buffer)
            output_file.write(ciphered_bytes)
            buffer = input_file.read(65536)
        
        # write the second half of the key at the end of the file
        output_file.write(key[-16:])
        input_file.close()
        output_file.close()
        # delete the original file
        subprocess.call(['rm', file_to_encrypt])
        if verbose:
            print ('Deleted: {}'.format(file_to_encrypt))
    
    def __decrypt(self, file_to_decrypt, verbose):
        """Reads in encrypted file and decrypts
        
        Args:
            file_to_encrypt (str): Path of the file to
                be decrypted.
            verbose (bool): Marker for whether to print
                status to the console.
        
        Returns: None
        """
        
        # get the iv and key from the file
        iv, key = self.__getSplitKeyAndIV(file_to_decrypt)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        temp = file_to_decrypt.split('/')
        # get the filename of the file to decrypt
        toFile = temp[len(temp)-1]
        
        # decode the filename and replace it in the list
        toFile = bytes.fromhex(toFile.replace(".binff", ""))
        toFile = cipher.decrypt(toFile)
        toFile = toFile.decode()
        temp[len(temp) - 1] = toFile
        # open the file to decrypt
        input_file = open(file_to_decrypt, 'rb')
        # join and check path for decypted file
        outfile = "/".join(temp)
        outfile = outfile.replace("//","/")
        output_file = open(outfile, 'wb')

        # skip the iv and the first 16 bytes from the key
        input_file.read(32)
        

        buffer = input_file.read(65536)
        while len(buffer) > 0:
            # make sure the 16 bytes of key isn't included in buffer
            if len(buffer) < 65536:
                buffer = buffer[:-16]
            decrypted_bytes = cipher.decrypt(buffer)
            output_file.write(decrypted_bytes)
            buffer = input_file.read(65536)
        
        input_file.close()
        output_file.close()
        # delete the encrypted file
        subprocess.call(['rm', file_to_decrypt])
        if verbose:
            print ('Deleted: {}'.format(file_to_decrypt))
    
    def __encryptFolder(self, folderName, verbose, encrypt):
        """Encrypts or decrypts the folder depending on the encrypt bool.
        
        Args:
            folderName (str): Path of the folder.
            verbose (bool): Marker for whether to print
                status to the console.
            encrypt (bool): Flag to encrypt or decrypt.
        
        Returns: None
        """
        # generate basic key and iv
        key = 16 * b'\0'
        iv = 16 * b'\0'
        cipher = AES.new(key, AES.MODE_CFB, iv)
        # remove the trailing '/' if present in the path
        if folderName[-1] == '/':
            folderName = folderName[:-1]
        if encrypt:
            temp = folderName.split('/')
            # save the original folder name
            original = temp[len(temp) - 1]
            # encode and change the folder name in the list
            temp[len(temp) - 1] = cipher.encrypt(str.encode(temp[len(temp) - 1])).hex()
            toFolder = "/".join(temp).replace("//", "/")
            if verbose:
                print ("Changing {} to {}".format(original, temp[len(temp) - 1]))
            # change the folder name to the encrypted plus 'fff' at the end to distinguish
            subprocess.call(['mv', folderName, toFolder+'fff'])
        if not encrypt:
            temp = folderName.split('/')
            original = temp[len(temp) - 1]
            # remove the 'fff' at the end of the file
            original = original[:-3]
            
            # decrypt and change folder name in the list
            temp[len(temp) -1] = cipher.decrypt(bytes.fromhex(original)).decode()
            toFolder = "/".join(temp).replace("//", "/")
            if verbose:
                print ("Changing {} to {}".format(original, temp[len(temp) - 1]))
            # change the folder name in the console
            subprocess.call(['mv', folderName, toFolder])
            
            
    
    def __getSplitKeyAndIV(self, f):
        """Reads in iv and gets split key from the file
        to be decrypted.
        
        Args:
            f (str): Path to the file to be scanned.
        
        Returns:
            iv (bytes): The iv used to decrypt.
            key (bytes): The reconstructed key used
                to decrypt.
        """
        
        x = open(f, 'rb')
        # read iv (first 16 bytes)
        iv = x.read(16)
        # combine the next 16 bytes and the last 16 bytes
        key = x.read(16) + x.read()[-16:]
        return iv, key

    def recursiveWalk(self, walk_dir, verbose, force):
        """Recursively walks through a file tree and 
            encrypts or decrypts all files.
        
        Args:
            walk_dir (str): Path to the root folder.
            verbose (bool): Marker to write status to console.
        
        Returns: None
        """
        if not force:
            for root, subdirs, files in os.walk(walk_dir):
                for filename in files:
                    if 'DS_Store' in filename:
                        continue
                    if verbose:
                        print(os.path.join(root, filename))

                    if '.binff' not in filename:
                        self.__encrypt(os.path.join(root, filename), verbose)
                    else:
                        self.__decrypt(os.path.join(root, filename), verbose)
            # important to start from bottom because foldername/paths will change
            for root, subdirs, files in os.walk(walk_dir, topdown=False):
                for name in subdirs:
                    if name[-3:] == 'fff':
                        self.__encryptFolder(os.path.join(root, name), verbose, False)
                    else:
                        self.__encryptFolder(os.path.join(root, name), verbose, True)
                        
            if walk_dir[-3:] == 'fff':
                self.__encryptFolder(walk_dir, verbose, False)
            else:
                self.__encryptFolder(walk_dir, verbose, True)
                
        # force encrypt and ignore already encrypted elements
        if force == 'encrypt':
            for root, subdirs, files in os.walk(walk_dir):
                for filename in files:
                    if 'DS_Store' in filename:
                        continue
                    if '.binff' not in filename:
                        self.__encrypt(os.path.join(root, filename), verbose)
                        if verbose:
                            print(os.path.join(root, filename))
            
            for root, subdirs, files in os.walk(walk_dir, topdown=False):
                for name in subdirs:
                    if name[-3:] != 'fff':
                        self.__encryptFolder(os.path.join(root, name), verbose, True)
                        
            if walk_dir[-3:] != 'fff':
                self.__encryptFolder(walk_dir, verbose, True)
        
        # force decrypt and ignore decrypted elements
        if force == 'decrypt':
            for root, subdirs, files in os.walk(walk_dir):
                for filename in files:
                    if 'DS_Store' in filename:
                        continue
                    if '.binff' in filename:
                        self.__decrypt(os.path.join(root, filename), verbose)
                        if verbose:
                            print(os.path.join(root, filename))
            
            for root, subdirs, files in os.walk(walk_dir, topdown=False):
                for name in subdirs:
                    if name[-3:] == 'fff':
                        self.__encryptFolder(os.path.join(root, name), verbose, False)
                        
            if walk_dir[-3:] == 'fff':
                self.__encryptFolder(walk_dir, verbose, False)
    
    def singleFile(self, filePath, verbose):
        """Encrypts or decrypts a single file.
        
        Args:
            walk_dir (str): Path to the file.
            verbose (bool): Marker to write status to console.
        
        Returns: None
        """
        # no need to check for force if just processing one file

        filePathTemp = filePath.split('/')
        filename = filePathTemp[len(filePathTemp) - 1]
        if '.binff' in filename:
            if verbose:
                print (filePath)
            self.__decrypt(filePath, verbose)
        else:
            if verbose:
                print (filePath)
            self.__encrypt(filePath, verbose)
    
    def singleFolder(self, walk_dir, verbose, force):
        """Encrypts or decrypts all files in a single folder.
        
        Args: 
            walk_dir (str): Path to folder.
            verbose (bool): Marker to write status to console.
            
        Returns: None
        """
        
        if not force:
            for root, subdirs, files in os.walk(walk_dir):
                for filename in files:
                    if 'DS_Store' in filename:
                        continue
                    if verbose:
                        print(os.path.join(root, filename))
                    if '.binff' not in filename:
                        self.__encrypt(os.path.join(root, filename), verbose)
                    else:
                        self.__decrypt(os.path.join(root, filename), verbose)
                break
            # encrypt/decrypt the folder name as well
            if walk_dir[-3:] == 'fff':
                self.__encryptFolder(walk_dir, verbose, False)
            else:
                self.__encryptFolder(walk_dir, verbose, True)
        
        elif force == 'encrypt':
            for root, subdirs, files in os.walk(walk_dir):
                for filename in files:
                    if 'DS_Store' in filename:
                        continue
                    if '.binff' not in filename:
                        self.__encrypt(os.path.join(root, filename), verbose)
                        if verbose:
                            print(os.path.join(root, filename))
                break
            if walk_dir[-3:] != 'fff':
                self.__encryptFolder(walk_dir, verbose, True)
        
        elif force == 'decrypt':
            for root, subdirs, files in os.walk(walk_dir):
                for filename in files:
                    if 'DS_Store' in filename:
                        continue
                    if '.binff' in filename:
                        self.__decrypt(os.path.join(root, filename), verbose)
                        if verbose:
                            print(os.path.join(root, filename))
                break
            if walk_dir[-3:] == 'fff':
                self.__encryptFolder(walk_dir, verbose, False)