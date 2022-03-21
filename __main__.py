#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Terminal tool for encryping/decrypting files, either single, in folders
or recursively in a tree of folders.
"""
__author__      = "Matthew Thornton"
__credits__     = ["Matthew Thornton"]
__version__     = "2.0"
__maintainer__  = "Matthew Thornton"

"""
Todo:
* Implement force system
    - Force one way or the other. Ignore those that are already 
        encrypted or decrypted
* Implement ability to do files without the full path
"""
import os, sys
import encodewalkFunctions

def main():
    encode = encodewalkFunctions.encodewalk()
    counter = 0
    walk_dir = None
    verbose = False
    recur = False
    force = None
    for x in sys.argv:
        if '/' in x and counter != 0:
            walk_dir = x
        elif '-v' in x:
            verbose = True
        elif '-r' in x:
            recur = True
        elif '-d' in x:
            force = 'decrypt'
        elif '-e' in x:
            force = 'encrypt'
        counter += 1
        
    if walk_dir is None:
        walk_dir = input("Enter the directory or file to walk: ")  
        walk_dir = walk_dir.replace("\\", "")  
        
    while walk_dir[-1] == " ":
        walk_dir = walk_dir[:-1]
    if verbose:
        print()
    if os.path.isfile(walk_dir):
        encode.singleFile(walk_dir, verbose)
    else:
        if recur:
            encode.recursiveWalk(walk_dir, verbose, force)
        else:
            encode.singleFolder(walk_dir, verbose, force)
          
if __name__ == '__main__':
    main()