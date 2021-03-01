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
        
        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_CFB)
        file_name = file_to_encrypt.split('/')
        file_name[len(file_name) - 1] = cipher.encrypt(str.encode(file_name[len(file_name) - 1])).hex()
        toFile = "/".join(file_name)
        toFile = toFile.replace("//","/")
        output_file = open(toFile + ".binff", 'wb')
        output_file.write(cipher.iv)
        output_file.write(key[:16])

        buffer = input_file.read(65536)
        while len(buffer) > 0:
            ciphered_bytes = cipher.encrypt(buffer)
            output_file.write(ciphered_bytes)
            buffer = input_file.read(65536)
            
        output_file.write(key[-16:])
        input_file.close()
        output_file.close()
        subprocess.call(['rm', file_to_encrypt])
        if verbose:
            print ('Deleted: {}'.format(file_to_encrypt))
    
    def __decrypt(self, file_to_encrypt, verbose):
        """Reads in encrypted file and decrypts
        
        Args:
            file_to_encrypt (str): Path to the file to
                be decrypted.
            verbose (bool): Marker for whether to print
                status to the console.
        
        Returns: None
        """
        
        iv, key = self.__getSplitKeyAndIV(file_to_encrypt)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        temp = file_to_encrypt.split('/')
        toFile = temp[len(temp)-1]
        
        toFile = bytes.fromhex(toFile.replace(".binff", ""))
        toFile = cipher.decrypt(toFile)
        toFile = toFile.decode()
        temp[len(temp) - 1] = toFile
        input_file = open(file_to_encrypt, 'rb')
        outfile = "/".join(temp)
        outfile = outfile.replace("//","/")
        output_file = open(outfile, 'wb')

        input_file.read(32)
        

        buffer = input_file.read(65536)
        while len(buffer) > 0:
            if len(buffer) < 65536:
                buffer = buffer[:-16]
            decrypted_bytes = cipher.decrypt(buffer)
            output_file.write(decrypted_bytes)
            buffer = input_file.read(65536)
        
        input_file.close()
        output_file.close()
        subprocess.call(['rm', file_to_encrypt])
        if verbose:
            print ('Deleted: {}'.format(file_to_encrypt))
    
    def __encryptFolder(self, folderName, verbose, encrypt):
        key = 16 * b'\0'
        iv = 16 * b'\0'
        cipher = AES.new(key, AES.MODE_CFB, iv)
        if folderName[-1] == '/':
            folderName = folderName[:-1]
        if encrypt:
            temp = folderName.split('/')
            original = temp[len(temp) - 1]
            temp[len(temp) - 1] = cipher.encrypt(str.encode(temp[len(temp) - 1])).hex()
            toFolder = "/".join(temp).replace("//", "/")
            if verbose:
                print ("Changing {} to {}".format(original, temp[len(temp) - 1]))
            subprocess.call(['mv', folderName, toFolder+'fff'])
        if not encrypt:
            temp = folderName.split('/')
            original = temp[len(temp) - 1]
            original = original[:-3]
            
            temp[len(temp) -1] = cipher.decrypt(bytes.fromhex(original)).decode()
            toFolder = "/".join(temp).replace("//", "/")
            if verbose:
                print ("Changing {} to {}".format(original, temp[len(temp) - 1]))
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
        iv = x.read(16)
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
    
    def singleFile(self, walk_dir, verbose):
        """Encrypts or decrypts a single file.
        
        Args:
            walk_dir (str): Path to the file.
            verbose (bool): Marker to write status to console.
        
        Returns: None
        """
        
        walk_dir_temp = walk_dir.split('/')
        filename = walk_dir_temp[len(walk_dir_temp) - 1]
        if '.binff' in filename:
            if verbose:
                print (walk_dir)
            self.__decrypt(walk_dir, verbose)
        else:
            if verbose:
                print (walk_dir)
            self.__encrypt(walk_dir, verbose)
    
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