// Project 3 Chat Client by Kaylin Zaroukian

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>


int should_exit = 0;
unsigned char symmetric_key[32];
unsigned char iv[16];
// servers public key
EVP_PKEY *public_key, *private_key;

void sigHandler(int signum) {
	if (signum == SIGUSR1) {
		exit(1);
	}
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

// encrypts with rsa public key
int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

void encrypt_msg(char* decrypt_txt, char* encrypt_txt, int encryptedtxt_len) {
  // now we re-encrypt before sending
  unsigned char encrypt_iv[16];
  char encrypted_text[5000];
  RAND_bytes(encrypt_iv,16);

  encryptedtxt_len = encrypt(decrypt_txt, strlen(decrypt_txt), symmetric_key, encrypt_iv, encrypted_text);
  char num_char[3];
  sprintf(num_char,"%d",encryptedtxt_len);
  printf("NUM CHAR: %s\n", num_char);

  printf("encrypted txt: %s\n", encrypted_text);
  printf("encrypt length: %d\n", encryptedtxt_len);
  //char encrypt_and_iv[encryptedtxt_len+19];
//	char encrypt_len[3];
  //sprintf(encrypt_len, "%d",encryptedtxt_len);
  memcpy(encrypt_txt, num_char, 3);
  memcpy(encrypt_txt+3, encrypt_iv, 16);
  memcpy(encrypt_txt+19,encrypted_text,encryptedtxt_len);
  printf("encrypt_and_iv: %s\n", encrypt_txt);
  encrypt_txt[encryptedtxt_len+19] = '\0';

  printf("encrypt_and_iv size: %d\n", strlen(encrypt_txt));
}

void* receivemessage(void* arg) {
	int serversocket = *(int*)arg;
	while(1) {
		// receive message
		char line[5000];
		int k = recv(serversocket,line,5000,0);

		// now we decrypt the message
		//char decrypted_text[5000];
		//int decryptedtext_len = decrypt(line2, strlen(line2+1), )

		// get the iv
		printf("received message: %s\n", line);

		// once we get the iv get the encrypted msg
		char decrypted_line[5000];
		char len_res[3];
		unsigned char iv2[16];
		memcpy(len_res, line, 3);
		int encrypt_length = atoi(len_res);
		printf("Num: %d\n", encrypt_length);
		memcpy(iv2, line+3, 16);
		printf("iv: %s\n", iv2);
		char no_iv[5000];

		int r = 0;

		memcpy(no_iv,line+19,5000);
		printf("no iv: %s\n", no_iv);
		printf("str len of no iv %d, sizeo of %d\n", strlen(no_iv), sizeof(no_iv));

		int decryptedline_len = decrypt(no_iv, encrypt_length, symmetric_key, iv2, decrypted_line);
		printf("decrypting worked?\n");

		if (strncmp(decrypted_line,"escape_msg",10) == 0) {
			printf("its a trap\n");
			char* close_message = "disconnecting_client";
			char encrypt[5000];
			int length = 0;
			encrypt_msg(close_message,encrypt, length);

			int x=send(serversocket,encrypt,length+19,0);
			close(serversocket);

			// kills the thread
			kill(getppid(),SIGUSR1);
			should_exit = 1;
			return 0;
		}

		if (k >= 0) {
			printf("Incoming Message: %s\n",line);
		}

		if(strncmp(line, "Quit", 4) == 0) {
			close(serversocket);
			should_exit = 1;
			return 0;

		}

	}
}

int main(int argc, char** argv){
	should_exit = 0;

	// we will need to create more than one socket?
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0) {
		printf("There was an error creating the socket\n");
		return 1;
	}

	printf("Enter port number: ");
  char port[5000];
  fgets(port, 5000, stdin);
  int clientport = atoi(port);

	printf("Enter IP address: ");
	char ipaddress[5000];
	fgets(ipaddress, 5000, stdin);

	struct sockaddr_in serveraddr;
	serveraddr.sin_family=AF_INET;

	serveraddr.sin_port=htons(clientport);
	serveraddr.sin_addr.s_addr=inet_addr(ipaddress);

	int e = connect(sockfd, (struct sockaddr*)&serveraddr,sizeof(serveraddr));
	if(e < 0) {
		printf("There was an error connecting\n");
		return 2;
	}

	OpenSSL_add_all_algorithms();

	// recv RSA pub key
	// char pub_key[5000];
	// int g = recv(sockfd, pub_key, sizeof(pub_key), 0);


  // from cryptotest.c
	FILE* pubkey_file = fopen("RSApub.pem","rb");
	FILE* privkey_file = fopen("RSApriv.pem","rb");
//	generates the public key
	public_key = PEM_read_PUBKEY(pubkey_file,NULL,NULL,NULL);
	private_key = PEM_read_PrivateKey(privkey_file,NULL,NULL,NULL);

	// only want to randomly generate symmetric key once
	RAND_bytes(symmetric_key,32);

	// encrypted key to send
	unsigned char encrypted_key[256];

	// encrypt our symmetric key using the RSA public public_key
	int encryptedkey_len = rsa_encrypt(symmetric_key, 32, public_key, encrypted_key);
	// now we send the encrypted key to the server
	// should we send a warning message first?

	char* key_msg = "~key";
	printf("Key: %s", symmetric_key);

	char complete_key_msg[encryptedkey_len+4];
	//printf("sending key msg size: %d\n", encryptedkey_len);
	//printf("encrypted_key: %s\n", encrypted_key);
	memcpy(complete_key_msg,key_msg,4);
	memcpy(complete_key_msg + 4,encrypted_key,encryptedkey_len);
	int r = send(sockfd,complete_key_msg,encryptedkey_len+4,0);
	// int c= -1;

	// // blocks till the key is sent
	// while (c < 0) {
	// 	c = send(sockfd,encrypted_key,encryptedkey_len+1,0);
	// 	printf("sending encrypted key");
	// }
	if (r == 0) {
		printf("ERROR key unable to be sent\n");
		return 3;
	}

	while(1) {

		if(should_exit == 1){
			close(sockfd);
			return 0;
		}

		// send message
		// randomly generates a iv everytime we send a message

		pthread_t receive;

		pthread_create(&receive, NULL, receivemessage, &sockfd);

		pthread_detach(receive);

		//int x=send(sockfd,line,strlen(line)+1,0);
		// send the encrypted text


		printf("Enter a line: ");
		char line[5000];
		fgets(line,5000,stdin);

		RAND_bytes(iv,16);
		printf("IV %s\n",iv );

		printf("encrypting\n");
		char encrypted_text[5000];
		printf("symmetric key %s \n", symmetric_key);
		int encryptedtxt_len = encrypt(line, strlen(line), symmetric_key, iv, encrypted_text);
		char num_char[3];
		sprintf(num_char,"%d",encryptedtxt_len);
		printf("NUM CHAR: %s\n", num_char);

		printf("encrypted txt: %s\n", encrypted_text);
		printf("encrypt length: %d\n", encryptedtxt_len);
		char encrypt_and_iv[encryptedtxt_len+19];
	//	char encrypt_len[3];
		//sprintf(encrypt_len, "%d",encryptedtxt_len);
		memcpy(encrypt_and_iv, num_char, 3);
		memcpy(encrypt_and_iv+3, iv, 16);
		memcpy(encrypt_and_iv+19,encrypted_text,encryptedtxt_len);
		printf("encrypt_and_iv: %s\n", encrypt_and_iv);
		encrypt_and_iv[encryptedtxt_len+19] = '\0';

		printf("encrypt_and_iv size: %d\n", strlen(encrypt_and_iv));
		int x=send(sockfd,encrypt_and_iv,encryptedtxt_len+19,0);

		if(strncmp(line, "Quit\n", 4) == 0) {
			close(sockfd);
			return 0;

		}
		EVP_cleanup();
	  ERR_free_strings();
	}


}
