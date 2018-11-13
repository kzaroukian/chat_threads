// Project 3 Chat Server by Kaylin Zaroukian

// NEED TO COMPILE LIKE: gcc chat_server.c -lpthread -o s -lcrypto

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

// struct to hold all connected clients
struct clients {
  struct in_addr client_address[10];
  char client_name[10][5];
  u_int socket[10];
  int connections_num;
  char symmetric_keys[10][32];
  u_int kicked_socket;
};

struct clients *connections;
char password[6];
unsigned char symmetric_key[32];

EVP_PKEY *public_key;
EVP_PKEY *private_key;


struct clients* getClients() {
  return connections;
}

void sigHandler(int signum) {
	if (signum == SIGUSR1) {
		return;
	}
}


char* commands() {
  char* send = "Commands: \n get all clients - returns all clients \n sendto clientName - send to specific client\n bcast - sends to all \n *kick clientname - disconnects a client\n me - returns my username";
  return send;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

// got from cryptotest.c
int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key,NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

// got from cryptotest.c
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  printf("entered decrypt\n");
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    printf("IF ERROR IS HERE\n");
    handleErrors();

  }
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    printf("3 if\n");
    handleErrors();
  }
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    printf("3 if\n");
    handleErrors();
  }
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

// got from cryptotest.c
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

void* handleclient(void* arg) {
  printf("made it into recv thread\n");
  struct clients *client_val = (struct clients *)malloc(sizeof(struct clients));
  struct clients *get_clients_vals;
  unsigned char iv[16];

  int clientsocket = *(int*)arg;

  if (clientsocket == -1) {
    return 0;
  }
  printf("Socket: %d\n", clientsocket);

  int loop_num = 0;
  while (1) {
    loop_num += 1;
    printf("\n");
    printf("Iteration: %d\n", loop_num);
    printf("\n");

    char line[5000];
    char decrypted_line[5000];
    int t = recv(clientsocket,line,5000,0);

    get_clients_vals = getClients();

    // find our index in the struct
    int s_index = 0;
    int z = 0;
    for(;z < get_clients_vals->connections_num; z++) {
      if (clientsocket == get_clients_vals->socket[z]) {
        s_index = z;
      }
    }

    // first thing we receive should be the encrypted key
    if(strncmp(line,"~key",4) == 0) {
      printf("key\n");

      char encrypted_key[5000];
      memcpy(encrypted_key,line+4,t-4);
      // we should have now received the encrypted key
      int decryptedkey_len = rsa_decrypt(encrypted_key, 256, private_key,symmetric_key);

      printf("Encrypted Key: \n");
      BIO_dump_fp(stdout, encrypted_key, t-4);

      printf("Symmetric Key: \n");
      BIO_dump_fp(stdout,symmetric_key, decryptedkey_len);

      // now we have the decrypted symmetric key!
      memcpy(get_clients_vals->symmetric_keys[s_index], symmetric_key, decryptedkey_len);
      continue;
    } else if (loop_num >1){

      printf("Thread for: %s\n",get_clients_vals->client_name[s_index]);

      printf("Received Encrypted msg: \n");
      BIO_dump_fp(stdout, line, t);
      printf("\n");

      // first we need to decrypt the received message

      int encrypt_length = 0;
      memcpy(&encrypt_length, line, 4);
      memcpy(iv, line+4, 16);
      char no_iv[t-20];
      int r = 0;
      memcpy(no_iv,line+20,t-20);

      printf("IV\n");
      BIO_dump_fp(stdout, iv, 16);

      printf("Encrypted Text: \n");
      BIO_dump_fp(stdout, no_iv, t-20);
      printf("\n");

      int decryptedline_len = decrypt(no_iv, encrypt_length, get_clients_vals->symmetric_keys[s_index], iv, decrypted_line);
      printf("Finished decrypting\n");

      printf("\n");
      printf("DECRYPTED LINE: %s\n", decrypted_line);

      // means we need to destroy this thread
      // this closes the thread
      if (strncmp(decrypted_line,"disconnecting_client",20) == 0) {
        close(clientsocket);
        return 0;

      }

      if (get_clients_vals->socket[s_index] == -1) {
        close(clientsocket);
        return 0;
      }

      char sendVal[5000];
      if(strncmp(decrypted_line, "commands",8) == 0){
        char* results = commands();
        memcpy(sendVal,results,5000);

        // now we re-encrypt before sending
        char encrypted_text[5000];
        unsigned char iv2[16];
        printf("Pre encryption: %s\n", results);
        printf("Starting Encryption: \n");

        RAND_bytes(iv2,16);

        int encryptedtxt_len = encrypt(results, strlen(results), get_clients_vals->symmetric_keys[s_index], iv2, encrypted_text);

        unsigned char encrypt_and_iv[encryptedtxt_len+20];

        memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
        memcpy(encrypt_and_iv+4, iv2, 16);
        memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

        printf("IV\n" );
        BIO_dump_fp(stdout, iv2, 16);
        printf("\n");

        printf("Encrypted Text: \n");
        BIO_dump_fp(stdout, encrypted_text, encryptedtxt_len);
        printf("\n");

        printf("Encrypted message to send: \n");
        BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);
        printf("\n");

        int u = send(clientsocket, encrypt_and_iv, encryptedtxt_len+20,0);
      }
      if(strncmp(decrypted_line, "get all clients\n", 15) == 0) {

        int y = 0;
        get_clients_vals = getClients();
        char hold[500] = {0};
        for(;y<get_clients_vals->connections_num;y++) {
          char temp[4];
          printf("Loop # %d\n",y );
          printf("Username: %s\n",get_clients_vals->client_name[y] );
          memcpy(temp,get_clients_vals->client_name[y],3);
          strcat(temp, " ");
          strcat(hold,temp);
        }

        // now we re-encrypt before sending

        printf("Pre encryption: %s\n",hold);
        printf("Starting Encryption: \n");
        char encrypted_text[5000];
        unsigned char iv2[16];

        RAND_bytes(iv2,16);

        int encryptedtxt_len = encrypt(hold, strlen(hold), get_clients_vals->symmetric_keys[s_index], iv2, encrypted_text);

        unsigned char encrypt_and_iv[encryptedtxt_len+20];

        unsigned char final_encrypt[encryptedtxt_len];

        memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
        memcpy(encrypt_and_iv+4, iv2, 16);
        memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

        printf("IV\n" );
        BIO_dump_fp(stdout, iv2, 16);
        printf("\n");

        printf("Encrypted Text: \n");
        BIO_dump_fp(stdout, encrypted_text,encryptedtxt_len);
        printf("\n");

        printf("Encrypted message to send: \n");
        BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);
        printf("\n");

        int u = send(clientsocket, encrypt_and_iv, encryptedtxt_len+20,0);
      }
      if(strncmp(decrypted_line,"me\n",2) == 0) {
        printf("text is me\n");
        get_clients_vals = getClients();
        int y = 0;
        char temp[3];
        for(;y<get_clients_vals->connections_num;y++) {
          if(get_clients_vals->socket[y] == clientsocket)  {
            memcpy(temp,get_clients_vals->client_name[y],3);
          }

        }

        printf("Pre encryption: %s\n", temp);

        printf("Starting Encryption: \n");

        char encrypted_text[5000];
        unsigned char iv2[16];

        RAND_bytes(iv2,16);

        int encryptedtxt_len = encrypt(temp, strlen(temp), get_clients_vals->symmetric_keys[s_index], iv2, encrypted_text);
        unsigned char encrypt_and_iv[encryptedtxt_len+20];

        memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
        memcpy(encrypt_and_iv+4, iv2, 16);
        memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

        printf("IV\n" );
        BIO_dump_fp(stdout, iv2, 16);
        printf("\n");

        printf("Encrypted Text: \n");
        BIO_dump_fp(stdout, encrypted_text, encryptedtxt_len);
        printf("\n");

        printf("Encrypted message to send: \n");
        BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);
        printf("\n");

        int u = send(clientsocket, encrypt_and_iv,encryptedtxt_len+20,0);
      }

      if (strncmp(decrypted_line,"bcast",4)==0) {
        char* temp = "What message would you like to send?";

        printf("Pre encryption: %s\n", temp);
        printf("Starting Encryption: \n");

        char encrypted_text[5000];
        unsigned char iv1[16];

        RAND_bytes(iv1,16);

        int encryptedtxt_len = encrypt(temp, strlen(temp),get_clients_vals->symmetric_keys[s_index], iv1, encrypted_text);

        unsigned char encrypt_and_iv[encryptedtxt_len+20];

        memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
        memcpy(encrypt_and_iv+4, iv1, 16);
        memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

        printf("IV\n" );
        BIO_dump_fp(stdout, iv1, 16);
        printf("\n");

        printf("Encrypted text: \n");
        BIO_dump_fp(stdout, encrypted_text, encryptedtxt_len);
        printf("\n");

        printf("Encrypted text to send: \n");
        BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);
        printf("\n");

        int u = send(clientsocket, encrypt_and_iv,encryptedtxt_len+20,0);

        int s = 0;
        char ans[5000];
        char decrypted_ans[5000];
        char iv2[16];

        while(s < 1) {
          s = recv(clientsocket,ans,5000,0);
        }

        printf("DECRYPTION\n");

        int ans_encrypt_len = 0;
        memcpy(&ans_encrypt_len, ans, 4);
        memcpy(iv2, ans+4, 16);
        char no_iv2[s-20];

        memcpy(no_iv2,ans+20,s-20);

        printf("IV\n");
        BIO_dump_fp(stdout, iv2, 16);
        printf("\n");

        printf("Encrypted text:\n");
        BIO_dump_fp(stdout, no_iv2, s-20);
        printf("\n");

        printf("Received encrypted msg\n");
        BIO_dump_fp(stdout, ans, s);
        printf("\n");

        int decryptedans_len = decrypt(no_iv2, ans_encrypt_len, get_clients_vals->symmetric_keys[s_index], iv2, decrypted_ans);
        printf("decrypting finished!\n");

        printf("\n");
        printf("DECRYPTED VALUE: %s\n", decrypted_ans);
        printf("\n");

        int o = 0;
        for(;o<get_clients_vals->connections_num; o++) {
          if(get_clients_vals->socket[o] > 0) {
            printf("Starting Encryption: \n");
            printf("On: %s\n", get_clients_vals->client_name[o]);

            char encrypted_msg[5000];
            unsigned char iv_msg[16];

            RAND_bytes(iv_msg,16);

            int encryptedmsg_len = encrypt(decrypted_ans, strlen(decrypted_ans), get_clients_vals->symmetric_keys[o], iv_msg, encrypted_msg);

            unsigned char encryptmsg_and_iv[encryptedmsg_len+20];

            memcpy(encryptmsg_and_iv, &encryptedmsg_len, 4);
            memcpy(encryptmsg_and_iv+4, iv_msg, 16);
            memcpy(encryptmsg_and_iv+20, encrypted_msg, encryptedmsg_len);

            printf("IV\n" );
            BIO_dump_fp(stdout, iv_msg, 16);
            printf("\n");

            printf("Encrypted text:\n" );
            BIO_dump_fp(stdout, encrypted_msg, encryptedmsg_len);
            printf("\n");

            printf("Encrypted Message to send:\n");
            BIO_dump_fp(stdout, encryptmsg_and_iv, encryptedmsg_len+20);
            printf("\n");
            int p = send(get_clients_vals->socket[o],encryptmsg_and_iv, encryptedmsg_len+20,0);
          }
        }

      }
      if(strncmp(decrypted_line,"sendto",6) == 0){
        char match[3];
        memcpy(match,decrypted_line + 7,3);

        u_int send_socket = 0;
        printf("TO: %s\n",match);
        printf("Size: %lu\n", strlen(match));
        int y = 0;
        int send_spot = 0;
        for(;y<get_clients_vals->connections_num;y++) {

          if (strncmp(match,get_clients_vals->client_name[y], strlen(match)) == 10) {
            //printf("ISSA MATCH\n");
            send_socket = get_clients_vals->socket[y];
            send_spot = y;
          }

        }
        if (send_socket > 0) {
          char* temp = "What message would you like to send?";

          printf("Value to encrypt: %s\n", temp);

          printf("Starting Encryption: \n");

          char encrypted_text[5000];
          unsigned char iv1[16];

          RAND_bytes(iv1,16);

          int encryptedtxt_len = encrypt(temp, strlen(temp), get_clients_vals->symmetric_keys[s_index], iv1, encrypted_text);

          unsigned char encrypt_and_iv[encryptedtxt_len+20];

          memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
          memcpy(encrypt_and_iv+4, iv1, 16);
          memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

          printf("IV\n" );
          BIO_dump_fp(stdout, iv1, 16);
          printf("\n");

          printf("Encrypted text: \n");
          BIO_dump_fp(stdout, encrypted_text, encryptedtxt_len);
          printf("\n");

          printf("Encrypted Message to send:\n");
          BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);
          printf("\n");

          int u = send(clientsocket, encrypt_and_iv,encryptedtxt_len+20,0);

          // block till we get our message
          int s = 0;
          char ans[5000];
          char decrypted_ans[5000];
          // need to decrypt this
          while(s < 1) {
            s = recv(clientsocket,ans,5000,0);
          }

          printf("RECEIVED MSG\n");
          BIO_dump_fp(stdout,ans,s);
          printf("\n");

          printf("starting decryption \n");
          unsigned char iv2[16];

          int ans_encrypt_len = 0;
          memcpy(&ans_encrypt_len , ans, 4);
          memcpy(iv2, ans+4, 16);
          unsigned char no_iv2[s-20];

          memcpy(no_iv2,ans+20,s-20);

          printf("IV\n");
          BIO_dump_fp(stdout,iv2,16);
          printf("\n");

          printf("Encrypted text\n");
          BIO_dump_fp(stdout,no_iv2,s-20);
          printf("\n");

          int decryptedans_len = decrypt(no_iv2, ans_encrypt_len, get_clients_vals->symmetric_keys[s_index], iv2, decrypted_ans);
          printf("decryption finished\n");
          printf("\n");
          printf("received from client: %s\n", decrypted_ans);
          printf("\n");

          // now we re-encrypt before sending

          printf("Starting Encryption: \n");

          char encrypted_msg[5000];
          unsigned char iv_msg[16];

          RAND_bytes(iv_msg,16);

          int encryptedmsg_len = encrypt(decrypted_ans, strlen(decrypted_ans), get_clients_vals->symmetric_keys[send_spot], iv_msg, encrypted_msg);

          unsigned char encryptmsg_and_iv[encryptedmsg_len+20];

          memcpy(encryptmsg_and_iv, &encryptedmsg_len, 4);
          memcpy(encryptmsg_and_iv+4, iv_msg, 16);
          memcpy(encryptmsg_and_iv+20, encrypted_msg, encryptedmsg_len);

          printf("IV\n" );
          BIO_dump_fp(stdout, iv_msg, 16);
          printf("\n");

          printf("Encrypted text\n" );
          BIO_dump_fp(stdout, encrypted_msg, encryptedmsg_len);
          printf("\n");

          printf("Encrypted MSG to send:\n");
          BIO_dump_fp(stdout, encryptmsg_and_iv, encryptedmsg_len+20);
          printf("\n");

          int j = send(send_socket, encryptmsg_and_iv, encryptedmsg_len+20,0);
        }
      }

      if(strncmp(decrypted_line, "*kick", 5) == 0) {
        printf("Entered kick\n");
        char match[3];
        memcpy(match,decrypted_line + 6,3);
        u_int send_socket = 0;
        printf("TO: %s\n",match);
        printf("Size: %lu\n", strlen(match));
        int y = 0;
        int index = 0;
        for(;y<get_clients_vals->connections_num;y++) {

          if (strncmp(match,get_clients_vals->client_name[y], strlen(match)) == 10) {
            send_socket = get_clients_vals->socket[y];
            index = y;
          }
      }

      if (send_socket > 0) {
        char* temp = "Please enter the password";
        // now we re-encrypt before sending;

        printf("String to encrypt: %s\n", temp);
        printf("Starting Encryption: \n");

        char encrypted_text[5000];
        unsigned char iv1[16];

        RAND_bytes(iv1,16);

        int encryptedtxt_len = encrypt(temp, strlen(temp), get_clients_vals->symmetric_keys[s_index], iv1, encrypted_text);

        unsigned char encrypt_and_iv[encryptedtxt_len+20];

        memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
        memcpy(encrypt_and_iv+4, iv1, 16);
        memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

        printf("IV\n" );
        BIO_dump_fp(stdout, iv1, 16);
        printf("\n");

        printf("Encrypted text\n" );
        BIO_dump_fp(stdout, encrypted_text, encryptedtxt_len);
        printf("\n");

        printf("Encrypted MSG to send: \n");
        BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);
        printf("\n");

        int u = send(clientsocket, encrypt_and_iv, encryptedtxt_len+20,0);
        // block till we get our message
        int s = 0;
        char ans[5000];
        char decrypted_ans[5000];
        unsigned char iv2[16];

        while(s < 1) {
          s = recv(clientsocket,ans,5000,0);
        }

        printf("Start decryption\n");

        int ans_encrypt_len = 0;
        memcpy(&ans_encrypt_len, ans, 4);
        memcpy(iv2, ans+4, 16);
        char no_iv2[s-20];

        printf("Received Message: \n");
        BIO_dump_fp(stdout, ans, s);
        printf("\n");

        memcpy(no_iv2,ans+20,s-20);

        printf("IV\n");
        BIO_dump_fp(stdout, iv2,16);
        printf("\n");

        printf("Encrypted Text:\n");
        BIO_dump_fp(stdout, no_iv2,s);
        printf("\n");

        int decryptedans_len = decrypt(no_iv2, ans_encrypt_len, get_clients_vals->symmetric_keys[s_index], iv2, decrypted_ans);
        printf("decrypting worked!\n");
        printf("\n");
        printf("Decrypted val: %s\n", decrypted_ans);
        printf("\n");

        if(strncmp(decrypted_ans,password,6) == 0) {
          get_clients_vals->socket[index] = -1;
          printf("Closing Socket at %s\n", get_clients_vals->client_name[index]);

          memcpy(get_clients_vals->client_name[index],"",5);
          char* exit = "escape_msg";

          // next we encrypt again
          printf("MSG to encrypt: %s\n", exit);

          printf("Starting Encryption: \n");

          char encrypted_msg[5000];
          unsigned char iv_msg[16];

          RAND_bytes(iv_msg,16);

          int encryptedmsg_len = encrypt(exit, strlen(exit), get_clients_vals->symmetric_keys[index], iv_msg, encrypted_msg);

          unsigned char encryptmsg_and_iv[encryptedmsg_len+20];

          memcpy(encryptmsg_and_iv, &encryptedmsg_len, 4);
          memcpy(encryptmsg_and_iv+4, iv_msg, 16);
          memcpy(encryptmsg_and_iv+20, encrypted_msg, encryptedmsg_len);

          printf("IV\n" );
          BIO_dump_fp(stdout, iv_msg, 16);
          printf("\n");

          printf("Encrypted text: \n");
          BIO_dump_fp(stdout, encrypted_msg, encryptedmsg_len);
          printf("\n");

          printf("Encrypted message to send: \n");
          BIO_dump_fp(stdout, encryptmsg_and_iv, encryptedmsg_len+20);
          printf("\n");

          // send message to client to let them know we're closing them
          int f = send(send_socket,encryptmsg_and_iv,encryptedmsg_len+20,0);

        }
      }
    }

      if(strncmp(decrypted_line, "Quit\n", 4) == 0) {
        printf("Quit sent\n");
        close(clientsocket);
        return 0;
      }

    }


  }
}

void* handleserver(void* arg) {

  int clientsocket = *(int*)arg;;

  while(1) {
    char line2[5000];
    printf("Enter a line: \n");
    fgets(line2,5000,stdin);

    int u = send(clientsocket, line2, strlen(line2)+1,0);

    if(strncmp(line2, "Quit", 4) == 0) {
      close(clientsocket);
      return 0;

    }
  }

}

int main(int argc, char** argv) {

  int i = 1;
  connections = (struct clients*)malloc(sizeof(struct clients));
  memcpy(password, "monday",6);
  OpenSSL_add_all_algorithms();

  // from cryptotest.c
  FILE* pubkey_file = fopen("RSApub.pem","rb");
  FILE* privkey_file = fopen("RSApriv.pem","rb");
  // generates the public key
  public_key = PEM_read_PUBKEY(pubkey_file,NULL,NULL,NULL);
  private_key = PEM_read_PrivateKey(privkey_file,NULL,NULL,NULL);

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if(sockfd < 0){
		printf("Problem creating socket\n");
		return 1;
	}

  printf("Enter port number: ");
  char port[5000];
  fgets(port, 5000, stdin);
  int serverport = atoi(port);

	struct sockaddr_in serveraddr,clientaddr;
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_port=htons(serverport);
	serveraddr.sin_addr.s_addr=INADDR_ANY;
  printf("Connected %d\n",i);
  if (i > 1) {
    printf("Connected %d\n", i);
  }
  i++;

  // add client addresses to struct

	int b = bind(sockfd, (struct sockaddr*)&serveraddr,sizeof(serveraddr));
	if(b < 0) {
		printf("Bind error\n");
		return 3;
	}
	// listen for incoming clients on this port, 10 acts as a backlog
	listen(sockfd,10);


  int s = 0;
  int placeholder = 0;
	while(1){
    printf("placeholder val prior %d\n",placeholder );
		int len = sizeof(clientaddr);
    // accepting a client socket
		int clientsocket = accept(sockfd, (struct sockaddr*)&clientaddr,&len);
    // add client address to struct

    // only add to struct if we have a successful connection
    memcpy(&connections->client_address[placeholder].s_addr, &clientaddr.sin_addr.s_addr,8);
    connections->connections_num += 1;
    connections->socket[placeholder] = clientsocket;
    char temp[5];
    sprintf(temp, "u%d",placeholder);
    memcpy(connections->client_name[placeholder],temp, 3);
    printf("Username: %s\n", connections->client_name[placeholder]);

    printf("Clinet Socket: %d\n", clientsocket);
    printf("placeholder %d\n", placeholder);
    printf("Connections Size: %d\n", connections->connections_num);
    printf("Socket Num: %d\n",connections->socket[0] );
    printf("Socket Num: %d\n",connections->socket[1] );


    placeholder += 1;
    // add the socket to our struct
    // we will need to go through and check
    pthread_t receive;
    pthread_t send;
    printf("\n");
    printf("creating threads\n");
    printf("\n");

    pthread_create(&receive, NULL, handleclient, &clientsocket);
    pthread_detach(receive);

    pthread_create(&send, NULL, handleserver, &clientsocket);
    pthread_detach(send);

	}
  EVP_cleanup();
  ERR_free_strings();

	return 0;
}
