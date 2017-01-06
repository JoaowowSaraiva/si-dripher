#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/des.h>
#include <openssl/pem.h>

#define KEY_SIZE 2048
#define PUBXP 65537


/*

TODO:

	

*/
//void calc_md5 (char file_name[], char file_out[]);
//RSA *genRSAkeys();
void removerfich2(char * s , char * path);
void apagarhash2( char *s, char * path);

void apagarhash(char * s ,char * path);
unsigned char * gencKey( unsigned char *ckey );
void enc(char * s,char * p,char * path);
void move(char * path,char * newpath,char * s);
unsigned char * genIv( unsigned char *ivec );
void Checknewfiles(int * numberOfFiles, char * path);
void move2(char * path,char * s,char * newpath);
void dec(char * s,unsigned char * ckey, unsigned char * ivec);
char * renomearA(char * what,char * s,char * format);
char * renomearD(char * what,char * s);
FILE *  criarfich(unsigned char * s,char * nome);
char * devolveIV(char * s ,char * path);
char * devolvekey(char * s ,char * path);
void removerfich(char *s , char * path);
void integrity( char file[], char * path);
unsigned char *calc_sha256 (char file_name[], char file_out[],char * path);
unsigned char * devolveHASH(char * s ,char * path); 
void sign(char *file_name, char *private_key);
char * findsign(char * s);
void verify(char *file_name, char * path);



int main(int argc, char const *argv[])
{	
       // int i= 0; //descomentar i e as linhas a baixo para ver as vezes que o programa ja correu.
	int numberOfFiles;


	while(1){
	Checknewfiles(&numberOfFiles,"Encrypt/");
	Checknewfiles(&numberOfFiles,"Decrypt/");
	Checknewfiles(&numberOfFiles,"Digest/");
	Checknewfiles(&numberOfFiles,"Integrity/");
	Checknewfiles(&numberOfFiles,"Sign/");
	Checknewfiles(&numberOfFiles,"Verify/");	
	//printf("RUN numero: %d\n",i);
	sleep(10);
	//i++;	
	}
	
	return 0;
}
void Checknewfiles(int * numberOfFiles, char * path){ //ver ficheiros dentro da pasta

	
        DIR *dir;
	struct dirent *ent;

	struct dirent ** filesInDir;
        *numberOfFiles = scandir(path,&filesInDir,NULL,alphasort);
	int a ;
	char c[5];
	char b[5];
	//int conta = 0;	
		if ((dir = opendir (path)) != NULL) 
		{
 		 /* Mostra os ficheiros dentro da pasta*/
 		 	while ((ent = readdir (dir)) != NULL) 
			{		
				a=strlen(ent->d_name);
				strncpy(b,path,3);
				strncpy(c,ent->d_name,3);
			if(ent->d_name[a-1] != '~' && ((strncmp(c,"enc",3))!=0) && ((strncmp("Enc",b,3)) == 0 ) && (ent->d_name[a-1] != '.'))
						enc(ent->d_name,ent->d_name,path);
			if(ent->d_name[a-1] != '~' && ((strncmp("Dig",b,3)) == 0 ) && (ent->d_name[a-1] != '.'))
						calc_sha256( ent->d_name, ent->d_name, path );
			if(ent->d_name[a-1] != '~' && ((strncmp("Int",b,3)) == 0 ) && (ent->d_name[a-1] != '.') && (ent->d_name[a-1]!='g'))
						integrity(ent->d_name,path);
			if(ent->d_name[a-1] != '~' && ((strncmp("Sig",b,3)) == 0 ) && (ent->d_name[a-1] != '.') )
						sign(ent->d_name,path);
			if(ent->d_name[a-1] != '~' && ((strncmp("Ver",b,3)) == 0 ) && (ent->d_name[a-1] != '.') && ((strcmp(ent->d_name,"public-key-file.pem") != 0)) && (ent->d_name[a-1] != 'g') ){ //fixed forma rudimentar
						verify(ent->d_name,path);
}
			if(ent->d_name[a-1] != '~' && ((strncmp(c,"dec",3))!=0) && ((strncmp("Dec",b,3)) == 0 ) && (ent->d_name[a-1] != '.'))
					{
						
				     		char * g = devolveIV(ent->d_name,"Decrypt/");
						char * h = devolvekey(ent->d_name,"Decrypt/");
						if((g != NULL) && (h != NULL))
						{	 
							 char d[100];
							 char key[	]= "key-";
							 char * aux = malloc(100);
							 strcpy(d,ent->d_name);
							 aux=strtok(d,".");	
							 strcat(key,aux);
							 strcat(key,".txt");
							
							 dec(ent->d_name,h,g);

							 chdir(path);
							 char rm[]="./";
							 strcat(rm,key);
							 remove(rm);
							 
							
							 strcpy(key,"iv-");
							 strcpy(d,ent->d_name);
							 aux=strtok(d,".");	
							 strcat(key,d);
							 strcat(key,".txt");

							 chdir(path);
							 char rmi[]="./";
							 strcat(rmi,key);
							 remove(rmi);
							
						}
					}
			}
		 closedir (dir);
		}
		else
        		perror ("");/* could not open directory */
    	
}


void verify(char * s, char * path) //funcao que verifica assinaturas, esta assinaturas sao verificadas com pk e sk geradas na instalacao do programa.
{
    char tmp_buf[1024];
	chdir(path);
	BIO *bio_public;
        RSA *rsa_public = RSA_new();
	
        FILE *fp;
	unsigned char *hash;
        unsigned char sig[256];
	char public_key[]= "public-key-file.pem";
        char * file_name_sig = malloc(100);
	fp = fopen(s,"rb");
	int i = 0 ;

if(fp == NULL){
	printf("Não existe o ficheiro na pasta ou por algum motivo não se abre \n o ficheiro é %s\n",s);
}
else{
	fclose(fp);
	getcwd(tmp_buf, 1024);
	file_name_sig=findsign(s);
	if(file_name_sig == NULL)
	{
		printf("Não existe sig correspondente para este ficheiro na pasta\n");
	}
	else{
		hash = calc_sha256(s,s,path); // calcular hash desse file
		//hash = devolveHASH(s,path);
		if(hash == NULL)
	 	  {
			printf("Não existe hash para este ficheiro\n");


	  	 }
       		 else
	  	 {

            getcwd(tmp_buf, 1024);


            chdir("./Verify");            
			fp = fopen(file_name_sig,"rb"); 
			if(fp == NULL)
				printf("O ficheiro %s , não existe ou não abre \n",file_name_sig);
			else
			 {	
				while (!feof(fp) && i < 256) {
      	  				sig[i++] = fgetc(fp);
   	 				}
			fclose(fp);
			
				bio_public = BIO_new_file(public_key, "rb");	
				rsa_public = PEM_read_bio_RSA_PUBKEY(bio_public,NULL, NULL, NULL);
				if (rsa_public == NULL) 
      	 		   		printf("error reading rsa_public\n");
				else
				   {
					unsigned int tam = 0 ;
					
					
					
					tam = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH , sig, 256, rsa_public);
					if (tam == 1)
					{
					// Operção correu bem deu 1
					 
 					 chdir("..");
				         
    					 move("Verify/","Valid-Sign/",s);
					 chdir(path);
					}
					else{

					//Operção correu mal deu 0, vamos ver para a pasta Não valido

					 chdir("..");
				        
    					 move("Verify/","Not-Valid-Sign/",s);
					
					 chdir(path);
					}
				   }
			 fclose(fp);
			 }
			removerfich(file_name_sig,path);
			chdir(path);
		  	apagarhash2(s,path);
	  	 }

		
	}
 

}
chdir("..");
getcwd(tmp_buf, 1024);

}

void sign(char *file_name, char * path) {//funcao que assina ficheiros com par de chaves RSA
    BIO *bio_private;
    RSA *rsa_private;
    FILE *fOut;
 
    chdir(path);
    unsigned char *hash;
    unsigned char sig_ret[KEY_SIZE];
     int sig_len, i=0;
     unsigned int *sigret_len = 0;
    char * private_key = malloc(100);
    strcpy(private_key,"private-key-file.pem");


    if((strncmp(file_name,"private-key-file.pem",strlen(private_key)-1)) != 0)
    {

    chdir("..");
    hash = calc_sha256(file_name,file_name,path);
    if(strcmp(hash, "ERROR_HASH_STEP")==0){
		printf("ERROR_HASH_STEP!! Conflito de hashes, cuidado com os ficheiros gerados\n");
	return;
    }

    chdir(path);
  

	
    bio_private = BIO_new_file("private-key-file.pem", "rb");
    rsa_private = PEM_read_bio_RSAPrivateKey(bio_private, NULL, NULL, NULL);
    	if (rsa_private == NULL) {
        printf("Error reading RSA private key\n");
        return;
   	 }
   // printf("DEBUG - RSA size: %d\n", RSA_size(rsa_private));
  //  printf("DEBUG - calling RSA_sign()\n");
   	
    int tam = 0 ;

    tam = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig_ret, &sig_len, rsa_private);

    // ja temos a assinatura num array(sig_ret), so falta passar para o ficheiro file.sig

    char * sig_file_name = malloc(64);
    snprintf(sig_file_name, 64, "%s%s", file_name, ".sig");
  //  printf("DEBUG - ficheiro assinado de saida: %s\n", sig_file_name);

	 sig_file_name = renomearD(".sig",sig_file_name);
   	 fOut = fopen(sig_file_name, "wb+");
   	for (i = 0; i < sig_len; i++) {
        fputc(sig_ret[i], fOut);
        }
   	 if (ferror(fOut)) {
      	  printf("problem saving signature file to disk\n");
     	   return ;
   	 }
   	 fclose(fOut);
    	chdir("..");
    	move("Sign/","Signed/",sig_file_name);
	apagarhash(file_name,path);
	removerfich(file_name,path);
    	return ;
    }
 //  else
//	printf("Private key não encontrada\n");
 // printf("Saindo da pasta apos busca de %s \n",file_name);
  chdir("..");
 }

unsigned char *calc_sha256 (char file_name[], char file_out[],char * path){ 
  //printf("Entramos na funcao calc_sha256 file_name:%s, file_out:%s, path:%s\n", file_name, file_out, path);
  chdir(path);
  
  FILE* file = fopen(file_name, "rb");
  
  if (file == NULL){
  return "ERROR_HASH_STEP";
  }
  
  int bytesRead = 0;
  const int bufSize = 32768;
  char* buffer = malloc(bufSize);
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;


  SHA256_Init(&sha256);
  
  while((bytesRead = fread(buffer, 1, bufSize, file))){
    SHA256_Update(&sha256, buffer, bytesRead);
  }


  SHA256_Final(hash, &sha256);

  char teste[128];
  int n=0;
  for (n = 0; n < SHA256_DIGEST_LENGTH; n++)
    sprintf(teste + (n * 2) ,"%02x",(unsigned char)hash[n]);
  putchar('\n');	

 FILE *f;
 file_out = renomearD(".hash",file_out);
 f = fopen (file_out, "wb");
 
  fwrite(teste, sizeof(char), 128, f); 
 //Hash criado e guardado em teste
  
fclose(f);
fclose(file);

  if(strcmp(file_out,"tempFile.hash") == 0 )
	chdir("..");
  else if (strcmp(path,"Sign/") == 0)
	chdir("..");
  else if (strcmp(path,"Verify/") == 0)
	chdir("..");
  else 
  { move(path,"Hashes/",file_out);
    move(path,"Hashes/",file_name);
   }
    return strdup(hash);
}

void apagarhash(char * s ,char * path)//procura e apaga o ficheiro .hash 
{
        chdir(path);
        char d[strlen(s)-1];
	char * key = malloc(100);
	

	strcpy(d,s);
	strtok(d,".");	
	strcpy(key,d);
	strcat(key,".hash");


        chdir("..");
	removerfich(key,path);
}

void apagarhash2(char * s ,char * path)//vertente da funcao a cima
{
        chdir(path);
        char d[strlen(s)-1];
	char * key = malloc(100);
	

	strcpy(d,s);
	strtok(d,".");	
	strcpy(key,d);
	strcat(key,".hash");

	removerfich2(key,path);
}

void removerfich(char * s , char * path)//funcao que remove o file 's' em 'path'
{
	int a = strlen(s);
	char rm[]="./";
	chdir(path);
	
	strcat(rm,s);
	remove(rm);
	chdir("..");

}


void removerfich2(char * s , char * path)//outra vertente da funcao a cima
{
	char rm[]="./";
	chdir(path);

	strcat(rm,s);
	remove(rm);
	
	
}


char * findsign(char * s)//funcao que procura a assinatura correspondente ao ficheiro ex: file file.sig e nao file2.sig
{
	DIR *dir;
	struct dirent *ent;
	char d[50];
	char key[]="public-key-"; 
	char * aux =  malloc(100);
	char * indata = NULL;
        char * text = malloc(100);
	int compararfich;
	strcpy(d,s);
	aux=strtok(d,".");
	if(((strcmp(aux,"sig") )== 0) || ((strcmp(aux,"hash") )== 0))
		return NULL;	
	strcpy(key,d);
	strcat(key,".sig");
	if ((dir = opendir (".")) != NULL) 
		{
 		 /* Mostra os ficheiros dentro da pasta*/
 		 	while ((ent = readdir (dir)) != NULL) 
			{	
				compararfich= strcmp(key,ent->d_name);
				if(compararfich == 0)
				  {

					strcpy(text,key);
					 closedir (dir);
					return text;
				 }
			}
		}
		else
        		perror ("");/* could not open directory */
	


 return indata;
}








unsigned char * devolveHASH(char * s ,char * path)
{
	chdir(path);
	DIR *dir;
	struct dirent *ent;
	 char d[10];
	 char key[20];
       
	
	char * indata = NULL;
	int compararfich;
	strcpy(d,s);
	strtok(d,".");	
	strcpy(key,d);
	strcat(key,".hash");
	if (((dir = opendir (".")) != NULL) && ((strcmp(key,s))!= 0)) 
		{
 		 /* Mostra os ficheiros dentro da pasta*/
 		 	while ((ent = readdir (dir)) != NULL) 
			{	
				compararfich= strcmp(key,ent->d_name);
				if(compararfich == 0)
				  {

					FILE * ifp = fopen(key,"r");
					fseek(ifp, 0L, SEEK_END);
   					int fsize = ftell(ifp);	
			
					indata = malloc(fsize);
					fseek(ifp, 0L, SEEK_SET);
					
					fread(indata,1,fsize, ifp);
					
					fclose(ifp);
					return ent->d_name;
				 }
			}
		}
		else
        		perror ("");/* could not open directory */
   return indata;


}

void integrity( char file[], char * path){//calcula a integridade do valor de hash do file 'file' no sitio 'path'
					  //redireciona para as pastas respetivas, tento o ficheiro sido alterado ou não
  
  
  chdir(path);
  FILE *fIn, *fHash, *tempFile;
  int fsize=0, fsize2=0;
  char * hash;
  char d[100];
  fIn = fopen (file, "r");
  
  hash = devolveHASH(file,path);
  if(hash == NULL){
	chdir("..");  
	 return;
  }
  else
     printf("%s\n",hash);
  strcpy(d,hash);

  fHash = fopen (d, "r");
  
  if(fHash == NULL)
	printf("Errado \n");
  
  //size do FILE que tem o hash
  fseek(fHash, 0L, SEEK_END); 
  fsize = ftell(fHash);  
  fseek(fHash, 0L, SEEK_SET);
  
  char v[fsize - 1];

  fread(v, fsize, 1, fHash);

  chdir("..");
  calc_sha256(file,"tempFile.txt",path);
  chdir(path);
  tempFile = fopen ("tempFile.hash", "r");

  fseek(tempFile, 0L, SEEK_END); 
  fsize2 = ftell(fHash);  
  fseek(tempFile, 0L, SEEK_SET);

  char c[fsize2];
  fread(c, fsize2, 1, tempFile);
  
  if((strncmp(v,c,fsize-1) )== 0){ //deu bem, entao envia o ficheiro para a pasta Int-Valid

     move(path,"Int-Valid/",file);
     apagarhash(file,path);
     chdir(path);
   }
  else{
   /* enviar o pasta not virified */


    move(path,"Int-Not-Valid/",file);
    apagarhash(file,path);
    chdir(path);
  }

fclose(fIn);
fclose(fHash);
fclose(tempFile);
chdir("..");

 removerfich("tempFile.hash",path);
  return;
  
}


char * renomearA(char * what,char * s,char * format)//renomeia ficheiros para facilitar outras operações
{	
       char * aux = malloc(100);
       char * text = malloc(100);
       char d[100];
       strcpy(d,s);
       strcpy(text,what);
       aux = strtok(d,".");
       strcat(text,aux);
       strcat(text,format);
       return text;
}
char * renomearD(char * what,char *s)
{
       char * aux = malloc(100);
       char * text = malloc(100);
       char d[100];

       strcpy(d,s);
	
       aux = strtok(d,".");
       strcat(aux,what);
       strcpy(text,aux);

      return text;
}



void dec(char * s,unsigned char * ckey, unsigned char * ivec) //funcao que de faz Decrypt usando o iv e a key respetica
{

    chdir("Decrypt/");


    FILE * ifp = fopen(s,"r");
  	if( ifp == NULL)
		printf("ERROO na abertura do ficheiro dec();\n");
    char * aux = malloc(100);
    aux = renomearD(".txt",s);

    FILE * ofp = fopen(aux,"w+");
    	if( ofp == NULL)
		printf("ERROO ERROO na abertura do ficheiro dec();\n");
    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    int outLen1 = 0; 
    int outLen2 = 0;
    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize);

    fseek(ifp, 0L, SEEK_SET);

    fread(indata,1,fsize, ifp);

    EVP_CIPHER_CTX ctx;
    EVP_DecryptInit(&ctx,EVP_aes_256_cbc(),ckey,ivec);
    EVP_DecryptUpdate(&ctx,outdata,&outLen1,indata,fsize);
    EVP_DecryptFinal(&ctx,outdata + outLen1,&outLen2);
    fwrite(outdata,1,outLen1+outLen2,ofp);
   
    fclose(ifp);
    fclose(ofp);
    
     
    		char rm[]="./";
		strcat(rm,s);
		remove(rm);
		chdir("..");

  
   move("Decrypt/","Decrypted/",aux);
}
void move(char * path,char * newpath,char * s)//funcao que move ficheiros para a o lugar pretendido
{	

	char folder[100];
	
	chdir(path);


	if((strcmp(".",path))!=0)
		strcpy(folder,"../");
	strcat(folder,newpath);
	strcat(folder,s);


	rename(s,folder);
	if((strcmp(".",path))!=0)
		chdir("..");
	
		
}

char * devolvekey(char * s ,char * path)//retorna a Key de um ficheiro
{	
	chdir(path);
	DIR *dir;
	struct dirent *ent;
	 char d[100];
	char key[]= "key-";

	char * indata = NULL;
	int compararfich;
	strcpy(d,s);

	strtok(d,".");	
	strcat(key,d);
	strcat(key,".txt");
	if ((dir = opendir (".")) != NULL) 
		{
 		 /* Mostra os ficheiros dentro da pasta*/
 		 	while ((ent = readdir (dir)) != NULL) 
			{	
				compararfich= strcmp(key,ent->d_name);
				if(compararfich == 0)
				  {

					FILE * ifp = fopen(key,"r");
					fseek(ifp, 0L, SEEK_END);
   					int fsize = ftell(ifp);	
			
					indata = malloc(fsize);
					fseek(ifp, 0L, SEEK_SET);
					
					fread(indata,1,fsize, ifp);

					fclose(ifp);
					chdir("..");
					return indata;
				 }
			}
		}
		else
        		perror ("");/* could not open directory */
	chdir("..");
   return indata;
}
char * devolveIV(char * s ,char * path)// o mesmo que a funcao a cima mas desta vez retorna o IV
{	
	chdir(path);
	DIR *dir;
	struct dirent *ent;
	 char d[100];
	char iv[]= "iv-";

	char * indata = NULL;
	int compararfich;
	strcpy(d,s);

	strtok(d,".");	
	strcat(iv,d);
	strcat(iv,".txt");
	if ((dir = opendir (".")) != NULL) 
		{
 		 /* Mostra os ficheiros dentro da pasta*/
 		 	while ((ent = readdir (dir)) != NULL) 
			{	
				compararfich= strcmp(iv,ent->d_name);
				if(compararfich == 0)
				  {

					FILE * ifp = fopen(iv,"r");
					fseek(ifp, 0L, SEEK_END);
   					int fsize = ftell(ifp);	
			
					indata = malloc(fsize);
					fseek(ifp, 0L, SEEK_SET);
					
					fread(indata,1,fsize, ifp);

					fclose(ifp);
					chdir("..");
					return indata;
				 }
			}
		}
		else
        		perror ("");/* could not open directory */
	chdir("..");
   return indata;
}
void enc(char * s,char * p,char * path)//funcao que encrypta usando aes_256_cbc , com chave geradas pelas funcoes genCKEY genIV
{	
	chdir(path);
	const    int    bufSize = 33;
	const    int    ivecsize = 17;
	unsigned char * ckey = malloc(bufSize);
	unsigned char * ivec = malloc(ivecsize);
	FILE * f = fopen(s,"r");
	int fsize ;
	
	FILE * fpi;
	FILE * fp;

	char e[100];
	char i[100];
	char en[100];
	char * d =malloc(100);
	int outLen1 = 0;  		
	int outLen2 = 0;

	//Ficheiro que vai ser encriptado 's' esta na pasta 'P' 
	//copiamos o nome do ficheiro para termos ficheiro.aes	
	strcpy(d,s);

	d = renomearD(".aes",d);
	
	//D que e onde escrevemos a cifra
	strcpy(en,d);
	
	//copiamos o nome do ficheiro para termos o ficheiro na pasta que ja foi cifrado encficheiro.txt
	FILE * E = fopen(en,"w");
	if (E == NULL) 
		printf("Ficheiro E impossivel ser aberto\n");
	else{
	if (f == NULL) 
		printf("Ficheiro impossivel ser aberto\n");
	else{
		fseek(f, 0L, SEEK_END);
		fsize = ftell(f);
 		unsigned char *indata = malloc(fsize);
    	        unsigned char *outdata = malloc(fsize*2);
		ivec = genIv(ivec);
		ckey = gencKey(ckey);
			
    		fseek(f, 0L, SEEK_SET);
		fread(indata,1,fsize,f);
	
		
		EVP_CIPHER_CTX ctx;
    		EVP_EncryptInit(&ctx,EVP_aes_256_cbc(),ckey,ivec);
    		EVP_EncryptUpdate(&ctx,outdata,&outLen1,indata,fsize);
    		EVP_EncryptFinal(&ctx,outdata + outLen1,&outLen2);
		
    		fwrite(outdata,1,outLen1+outLen2,E);
		fclose(f);
		fclose(E);
		strcpy(e,"key-");
		strcat(e,p);
		d = renomearD(".txt",e); // FIcheiros sem extensao txt ou q seja ficam iv.txt com as estas linhas
		strcpy(e,d);
		strcpy(i,"iv-");
		strcat(i,p);
		d = renomearD(".txt",i);
		strcpy(i,d); 
		fp = criarfich(ckey,e);
		fpi = criarfich(ivec,i);
		//move o ficheiro criptado o iv e a key para a pasta
		int a = strlen(s) - 1 ;
		
		if((s[a]=='h') && (s[a - 1]=='s') && (s[a- 2] == 'a' ) && (s[a - 3]=='h'))//execao criada para ir para a pasta MAC
		{	
			
			move(path,"MAC/",e);
			move(path,"MAC/",i);
			move(path,"MAC/",en);
		}
		else{	
		move(path,"Encrypted/",e);
		move(path,"Encrypted/",i);
		move(path,"Encrypted/",en);
		}
		//Parte de baixo coloca o ficheiro existente com o formato encNOME.txt para saber que ja foi encriptado		
		chdir("./Encrypt");	
		char rm[]="./";
		strcat(rm,p);
		remove(rm);
		chdir("..");	
		
	  }
	}
	
	
	;
}


FILE *  criarfich(unsigned char * s,char * nome)
{
	FILE * fp = fopen(nome,"w");
	
	if(fp ==NULL)
		printf("FIcheiro nao existe, criarfich()\n");	
	else
	  {
		//ficheiro criando
		fprintf(fp,"%s",s);
		
		fclose(fp);
	  }

	return fp;
}


unsigned char * genIv( unsigned char *ivec ){//funcao que gera IV a partir do ficheiro urandom
  int randomDataF = open ("/dev/urandom", O_RDONLY);
  int verify=0;

  if(randomDataF < 0){
    printf("error genIv, bad file descriptor:%d\nExit now\n", randomDataF);
   return ivec ; 
  }

  verify=read(randomDataF, ivec, 16);
 
  if(verify<0){
    printf("error genIv, cant read\nExit now\n");
    return NULL;
  }

	return ivec;
}


unsigned char * gencKey( unsigned char *ckey ){//funcao que gera a KEY a partir do ficheiro /dev/urandom
  
  int randomDataF = open("/dev/urandom", O_RDONLY);
  int verifyRead=0;

  if( randomDataF < 0){
    printf("Error gencKey, openning file negative file descriptor: %d\nExit now\n", randomDataF);
    return ckey;
  }
  
 verifyRead = read(randomDataF, ckey, 32);
  
  if(verifyRead<0){
    printf("Error reading from file gencKey\nExit now\n");
    return NULL;
  }
  
	return ckey;
}


















/**

void calc_md5 (char file_name[], char file_out[]){

  FILE *f = fopen (file_name, "rb");

  int bytesRead=0;
  MD5_CTX ctx;
  unsigned char c [MD5_DIGEST_LENGTH];
  unsigned char data[1024];

  if(f==NULL){
    printf("error open file calc_MD5, leaving now ...\n");
    return;}

  MD5_Init (&ctx);
  
  while ((bytesRead = fread (data, 1, 1024, f)) != 0)
        MD5_Update (&ctx, data, bytesRead);
    MD5_Final (c,&ctx);
  
  int i;
  char teste[65];
                
  for(i = 0; i < MD5_DIGEST_LENGTH; i++){
    printf("%02x", c[i]);
    sprintf(teste + (i * 2) ,"%02x",(unsigned char)c[i]);
  }

fclose(f);

  char v[1000];
 
  

  FILE *fl;
  fl = fopen (file_out, "wb");

  fwrite(teste, sizeof(char), 32, fl);

  
}










RSA *genRSAkeys(){

  RSA *rsa;
  BIO *public, *secret;
  int err, ret=0;

  rsa = RSA_generate_key(KEY_SIZE, PUBXP, NULL, NULL);

  if(rsa == NULL) {
    printf("error genRSAkeys\nExit now");
    return ;
  }

  public = BIO_new_file("public.pem", "w+");
  ret = PEM_write_bio_RSAPublicKey(public, rsa);
  
  secret = BIO_new_file("private-key-file.pem", "w+");
  ret = PEM_write_bio_RSAPrivateKey( secret, rsa, NULL, NULL, 0, NULL, NULL);

  return rsa;
}












**/
