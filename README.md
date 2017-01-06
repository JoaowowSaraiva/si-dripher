## Dripher

A litle project build for Computer Security, a discipline of our graduation in Informatic Engineering

## **1. What is it ?**

This project aims to implement a simple application for encryption and decryption of files, as well as for digital signature and integrity control. The idea is for the program to monitor a set of folders created by the application itself during installation by a user. Each folder corresponds to an application function that is activated after a user drags one or more files there (eg, when a user drags a file to the Encrypt folder, the program encrypts the file and moves the result to the Encrypted folder and so on)

Some of the comments are in Portuguese but it will be changed as soon as possible

## **2. Installation, usability and how it works**

- Our project have a *Makefile* with it you can install, compile and run _**dripher**_, you can also clean some files with it or read his info by doing _make info_ on your terminal.

- Our program sources is the file named dripher.c

### **2.1 Installation**

* By typing _**make install**_ your program will get everything you need. It will create the folders that the program use and it will compile the sources. It will also creat a pair of **RSA** keys, the private one will be inside the _Sign_ folder and the public one will be in _Verify_ folder.

  Thit is basically what you need to install _**dripher**_.
  
### **2.2 Usability and how it works**

 - Do _**make run**_ to run **_dripher_**

* To use it, you should drag and drop files to the folders: _Encrypt, Decrypt, Digest, Integrity, Sign, Verify_ because these are the folders that the program monitors. Output folders are all the other's.
 * When you move a file to the Encrypt folder, in the folder _Encrypted_ you will have the file encrypted and his key and iv.
 * When you drag a file his key and his iv to _Decrypt_ folder you will have the file decrypted in the _Decrypted_ folder.
 * When you drag a file to _Digest_ folder you will get the hash value and the file in the _Hashes_ folder. 
 * When you drag a file and his hash value to the _Integrity_ folder if it's integrity was not violated the file will apear in _Int-Valid_ folder, else it wll apear in _Int-not-Valid_ folder.
 * When you drag a file to _Sign_ folder, the file signature will be created in your _Signed_ folder. (it will sign the file with the _private-key-file.pem_ file that is already in _Sign_ folder.
 * When you drag a file and his signature to _Verify_ folder it will check the signature of the file. If it feets, the file will be moved to the _Valed-Sign_ folder, otherwise it will moved to _Not-Valid-Sign_ folder.
 
 
 
