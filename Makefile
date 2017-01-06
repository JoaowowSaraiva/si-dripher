##Makefile test
#
#
#
#
#
#


CC=cc
FLAGS= -Wall ##-c
LIBS= -lm -lpthread -lcrypto
#Alvo por defeito é o primeiro

c: 
	$(CC) dripher.c $(LIBS) -o dripher


info:
	echo "\t\n\n -make [install] para compilar o programa,  criar as pastas necessarias e gerar chave publica e privada\n -make [run] para o programa correr\n -make [clean] para deitar fora ficheiro inuteis\n -make [c] ou apenas make para compilar o programa\t\n\n"


install:
	mkdir Encrypt
	mkdir Encrypted
	mkdir Decrypt
	mkdir Digest
	mkdir Integrity
	mkdir Sign
	mkdir Verify
	mkdir Hashes
	mkdir Int-Not-Valid
	mkdir Int-Valid
	mkdir Valid-Sign
	mkdir Signed
	mkdir Not-Valid-Sign
	mkdir Decrypted
	mkdir MAC
	$(CC) dripher.c $(LIBS) -o dripher
	openssl genrsa -out private-key-file.pem
	openssl rsa -in private-key-file.pem -pubout > public-key-file.pem
	mv private-key-file.pem Sign
	mv public-key-file.pem Verify
	
run: 
	./dripher&

##limpa ficheiros inuteis
clean: 
	rm *~

