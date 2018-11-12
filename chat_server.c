// Project 3 Chat Server by Kaylin Zaroukian

// NEED TO COMPILE LIKE: gcc threadtcpechoserver.c -lpthread -o s

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
};

// struct of args to pass and send
struct args{
  u_int our_socket;
  int index;
  struct clients client_list;
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
  char* send = "Commands: \n get all clients - returns all clients \n sendto clientName - send to specific client\n sendto - sends to all \n *kick clientname - disconnects a client\n me - returns my username";
  return send;
}

int round_by_sixteen(int len) {
  int final = 0;
  int i = 0;
  while(final < 1) {
    int low_val = 16 * i;
    int high_val = 16 * (i + 1);
    if (len > low_val && len < high_val) {
      final = high_val;
    }
    i++;
  }

  return final;
}

char* getListOfClients() {
  struct clients *get_clients_vals = getClients();
  printf("Total Connections: %d\n", get_clients_vals->connections_num);
  char* connected_list;
  int s = 0;
  int index = 0;
  for(;s<get_clients_vals->connections_num;s++) {
    strcat(connected_list, get_clients_vals->client_name[s]);
    memcpy(connected_list,get_clients_vals->client_name[s],index);
    index+=3;
  }
  return connected_list;

}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

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

int encrypt_msg(char* decrypt_txt, char* encrypt_and_iv, int encryptedtxt_len) {
  printf("encrypting\n");

  unsigned char iv2[16];
  char encrypted_text[500];
  RAND_bytes(iv2,16);
  printf("IV %s\n",iv2 );

  //char encrypted_text[5000];
  //printf("symmetric key %s \n", symmetric_key);
  encryptedtxt_len = encrypt(decrypt_txt, strlen(decrypt_txt), symmetric_key, iv2, encrypted_text);

  //printf("encrypted txt: %s\n", encrypted_text);
  printf("encrypt length: %d\n", encryptedtxt_len);
  //unsigned char encrypt_and_iv[encryptedtxt_len+19];

  memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
  memcpy(encrypt_and_iv+4, iv2, 16);
  memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

  printf("IV\n" );
  BIO_dump_fp(stdout, iv2, 16);


  printf("encrypt_and_iv size: %d\n", strlen(encrypt_and_iv));

  printf("BIO DUMP\n");
  BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);

  return 1;
}

void* handleclient(void* arg) {
  printf("made it into recv thread\n");
  struct args *our_arg = (struct args *) arg;
  struct clients *client_val = (struct clients *)malloc(sizeof(struct clients));
  struct clients *get_clients_vals;
  unsigned char iv[16];
  //struct clients client = our_arg->client_list;
  //struct clients *client_val = (struct clients *) client;

  int clientsocket = our_arg->our_socket;

  // need a better way to handle this
  if (clientsocket == -1) {
    return 0;
  }
  printf("Socket: %d\n", clientsocket);

  // as soon as client connects send the public RSA key
  //send(clientsocket, public_key, sizeof(public_key),0);
  int loop_num = 0;
  while (1) {
    loop_num += 1;
    printf("Iteration: %d\n", loop_num);
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
    //memcpy(&client_val)

    // first thing we receive should be the encrypted key
    // but just in case we'll block
    if(strncmp(line,"~key",4) == 0) {
      printf("key\n");

      char encrypted_key[5000];
      memcpy(encrypted_key,line+4,sizeof(line)-4);
      // we should have now received the encrypted key
      int decryptedkey_len = rsa_decrypt(encrypted_key, 256, private_key,symmetric_key);
      //printf("SYM KEY: %s\n", symmetric_key);

      // now we have the decrypted symmetric key!
      memcpy(get_clients_vals->symmetric_keys[s_index], symmetric_key, decryptedkey_len);
      continue;
    } else if (loop_num >1){

      // get the iv
    //  printf("received message: %s\n", line);

      // once we get the iv get the encrypted msg
      //char len_res[3];

      printf("received msg: \n");
      BIO_dump_fp(stdout, line, t);

      int encrypt_length = 0;
      memcpy(&encrypt_length, line, 4);

      //printf("Num: %d\n", encrypt_length);
      memcpy(iv, line+4, 16);
      //printf("iv: %s\n", iv);
      char no_iv[5000];

      int r = 0;

      memcpy(no_iv,line+20,t-20);
      //printf("no iv: %s\n", no_iv);
      //printf("str len of no iv %d, sizeo of %d\n", strlen(no_iv), sizeof(no_iv));

      int decryptedline_len = decrypt(no_iv, encrypt_length, symmetric_key, iv, decrypted_line);
      printf("decrypting worked?\n");


      // means we need to destroy this thread
      // this only closes the thread doesn't delete it
      if (strncmp(decrypted_line,"disconnecting_client",20) == 0) {
        close(clientsocket);
        //kill(getppid(),SIGUSR1);
        return 0;

      }
      printf("Got from client: %s\n", decrypted_line);
      printf("Total Connections: %d\n", get_clients_vals->connections_num);
      printf("Socket 1: %d\n", get_clients_vals->socket[0]);
      printf("Socket 2: %d\n", get_clients_vals->socket[1]);


      char sendVal[5000];
      if(strncmp(decrypted_line, "commands",8) == 0){
        char* results = commands();
        memcpy(sendVal,results,5000);
        // now we re-encrypt before sending
        // char encrypted_text[5000];
        // int length = 0;
        // encrypt_msg(decrypted_line, encrypted_text, length);
        // int u = send(clientsocket, encrypted_text, length+19,0);
        char encrypted_text[5000];
        unsigned char iv2[16];
        printf("Starting Encryption: \n");


        RAND_bytes(iv2,16);
      //  printf("IV %s\n",iv2 );

      //printf("symmetric key %s \n", symmetric_key);
        int encryptedtxt_len = encrypt(results, strlen(results), symmetric_key, iv2, encrypted_text);

        char num_char[3];

        //printf("encrypted txt: %s\n", encrypted_text);
      //  printf("encrypt length: %d\n", encryptedtxt_len);
        unsigned char encrypt_and_iv[encryptedtxt_len+20];

        int val = encryptedtxt_len+19;
        char final[35] = {0};
        unsigned char test[16];
        memcpy(test,iv2,16);

        unsigned char final_encrypt[encryptedtxt_len];

        memcpy(final_encrypt,encrypted_text,encryptedtxt_len);
        final_encrypt[encryptedtxt_len] = '\0';

        memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
        memcpy(encrypt_and_iv+4, iv2, 16);
        memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

        printf("IV\n" );
        BIO_dump_fp(stdout, iv2, 16);


        //printf("encrypt_and_iv size: %d\n", strlen(encrypt_and_iv));

        printf("BIO DUMP\n");
        BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);

        int u = send(clientsocket, encrypt_and_iv, encryptedtxt_len+20,0);
      }
      if(strncmp(decrypted_line, "get all clients\n", 15) == 0) {
        // char* results = getListOfClients();
        // memcpy(sendVal,results,5000);
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
        // char encrypted_text[5000];
        // int length = 0;
        // encrypt_msg(hold, encrypted_text, length);

        printf("Starting Encryption: \n");
        char encrypted_text[5000];
        unsigned char iv2[16];

        RAND_bytes(iv2,16);
        //printf("IV %s\n",iv2 );

        //printf("symmetric key %s \n", symmetric_key);
        int encryptedtxt_len = encrypt(hold, strlen(hold), symmetric_key, iv2, encrypted_text);

        char num_char[3];

      //  printf("encrypted txt: %s\n", encrypted_text);
      //  printf("encrypt length: %d\n", encryptedtxt_len);
        unsigned char encrypt_and_iv[encryptedtxt_len+20];

        int val = encryptedtxt_len+19;
        char final[35] = {0};
        unsigned char test[16];
        memcpy(test,iv2,16);

        unsigned char final_encrypt[encryptedtxt_len];

        memcpy(final_encrypt,encrypted_text,encryptedtxt_len);
        final_encrypt[encryptedtxt_len] = '\0';

        memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
        memcpy(encrypt_and_iv+4, iv2, 16);
        memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

        printf("IV\n" );
        BIO_dump_fp(stdout, iv2, 16);


        //printf("encrypt_and_iv size: %d\n", strlen(encrypt_and_iv));

        printf("BIO DUMP\n");
        BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);

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


        // int length = 0;
        // int r = 0;
        // while (r < 1) {
        //   r = encrypt_msg(temp, encrypted_text, length);
        //
        // }
        // printf("encrypted_text %s\n", encrypted_text);
        // printf("length %d\n", length);

        // now we re-encrypt before sending

        printf("Starting Encryption: \n");

        printf("Temp: %s\n", temp);
        printf("encrypting\n");

        char encrypted_text[5000];
        unsigned char iv2[16];

        RAND_bytes(iv2,16);
        //printf("IV %s\n",iv2 );

      //  printf("symmetric key %s \n", symmetric_key);
        int encryptedtxt_len = encrypt(temp, strlen(temp), symmetric_key, iv2, encrypted_text);

        char num_char[3];

        //printf("encrypted txt: %s\n", encrypted_text);
      //  printf("encrypt length: %d\n", encryptedtxt_len);
        unsigned char encrypt_and_iv[encryptedtxt_len+20];

        int val = encryptedtxt_len+19;
        char final[35] = {0};
        unsigned char test[16];
        memcpy(test,iv2,16);

        unsigned char final_encrypt[encryptedtxt_len];

        memcpy(final_encrypt,encrypted_text,encryptedtxt_len);
        final_encrypt[encryptedtxt_len] = '\0';

        memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
        memcpy(encrypt_and_iv+4, iv2, 16);
        memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

        printf("IV\n" );
        BIO_dump_fp(stdout, iv2, 16);


        printf("encrypt_and_iv size: %d\n", strlen(encrypt_and_iv));

        printf("BIO DUMP\n");
        BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);

        int u = send(clientsocket, encrypt_and_iv,encryptedtxt_len+20,0);
      }

      if(strncmp(decrypted_line,"sendto",6) == 0){
        char match[3];
        memcpy(match,decrypted_line + 7,3);
        u_int send_socket = 0;
        printf("TO: %s\n",match);
        printf("Size: %lu\n", strlen(match));
        int y = 0;
        for(;y<get_clients_vals->connections_num;y++) {
          printf("Compare Val %d\n", strncmp(match,"all", strlen(match)));

          if (strncmp(match,get_clients_vals->client_name[y], strlen(match)) == 10) {
            //printf("ISSA MATCH\n");
            send_socket = get_clients_vals->socket[y];
          }

        }
        if (send_socket > 0) {
          char* temp = "What message would you like to send?";
          // need to first encrypt
          // now we re-encrypt before sending

          // char encrypted_text_1[5000];
          // int length1 = 0;
          // encrypt_msg(temp,encrypted_text_1, length1);
          // int u = send(clientsocket, encrypted_text_1, length1+19,0);

          printf("msg : %s\n", temp);
          printf("Starting Encryption: \n");

          char encrypted_text[5000];
          unsigned char iv1[16];

          RAND_bytes(iv1,16);
          //printf("IV %s\n",iv1 );

          //printf("symmetric key %s \n", symmetric_key);
          int encryptedtxt_len = encrypt(temp, strlen(temp), symmetric_key, iv1, encrypted_text);

          char num_char[3];

          //printf("encrypted txt: %s\n", encrypted_text);
          //printf("encrypt length: %d\n", encryptedtxt_len);
          unsigned char encrypt_and_iv[encryptedtxt_len+20];

          memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
          memcpy(encrypt_and_iv+4, iv1, 16);
          memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

          printf("IV\n" );
          BIO_dump_fp(stdout, iv1, 16);


          //printf("encrypt_and_iv size: %d\n", strlen(encrypt_and_iv));

          printf("Encrypted MSG:\n");
          BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);

          printf("sending now\n");
          // this is the problem
          int u = send(clientsocket, encrypt_and_iv,encryptedtxt_len+20,0);
          // why

          printf("sent msg request val is %d\n",u);

          // block till we get our message
          int s = 0;
          char ans[5000];
          char decrypted_ans[5000];
          printf("keep going\n");
          // need to decrypt this
          while(s < 1) {
            s = recv(clientsocket,ans,5000,0);
            printf("going\n");
          }

          printf("starting decryption \n");
          //char ans_len[3];
          printf("Size of received: %d\n", s);
          unsigned char iv2[16];

          int ans_encrypt_len = 0;
          memcpy(&ans_encrypt_len , ans, 4);
          //printf("Num: %d\n", ans_len);
          memcpy(iv2, ans+4, 16);
        //  printf("iv: %s\n", iv2);
          char no_iv2[5000];

          memcpy(no_iv2,ans+20,5000);
          //printf("no iv2: %s\n", no_iv2);

          int decryptedans_len = decrypt(no_iv2, ans_encrypt_len, symmetric_key, iv2, decrypted_ans);
          printf("decrypting worked?\n");
          printf("received from client: %s\n", decrypted_ans);


          // now we re-encrypt before sending
          // char encrypted_text[5000];
          // int length = 0;
          // encrypt_msg(decrypted_ans, encrypted_text, length);

          printf("Starting Encryption: \n");

          char encrypted_msg[5000];
          unsigned char iv_msg[16];

          RAND_bytes(iv_msg,16);
          //printf("IV %s\n",iv_msg);
          printf("decrypted ans size %d vs socket size %d\n",strlen(decrypted_ans),s );

          //printf("symmetric key %s \n", symmetric_key);
          int encryptedmsg_len = encrypt(decrypted_ans, strlen(decrypted_ans), symmetric_key, iv_msg, encrypted_msg);

          //printf("encrypted txt: %s\n", encrypted_msg);
        //  printf("encrypt length: %d\n", encryptedmsg_len);
          unsigned char encryptmsg_and_iv[encryptedmsg_len+20];

          memcpy(encryptmsg_and_iv, &encryptedmsg_len, 4);
          memcpy(encryptmsg_and_iv+4, iv_msg, 16);
          memcpy(encryptmsg_and_iv+20, encrypted_msg, encryptedmsg_len);

          printf("IV\n" );
          BIO_dump_fp(stdout, iv_msg, 16);


          //printf("encrypt_and_iv size: %d\n", strlen(encryptmsg_and_iv));

          printf("encrypted msg\n");
          BIO_dump_fp(stdout, encryptmsg_and_iv, encryptedmsg_len+20);

          int j = send(send_socket, encryptmsg_and_iv, encryptedmsg_len+20,0);
          printf("waiting %d\n", j);

        } else if(strncmp(match,"all", strlen(match)) == 0) {
          char* temp = "What message would you like to send?";

          // char encrypted_text_1[5000];
          // int length1 = 0;
          // encrypt_msg(temp,encrypted_text_1,length1);
          //
          // int u = send(clientsocket, encrypted_text_1, length1+19,0);

          printf("Starting Encryption: \n");

          char encrypted_text[5000];
          unsigned char iv1[16];

          RAND_bytes(iv1,16);
          //printf("IV %s\n",iv1 );

          //printf("symmetric key %s \n", symmetric_key);
          int encryptedtxt_len = encrypt(temp, strlen(temp), symmetric_key, iv1, encrypted_text);

          char num_char[3];

          //printf("encrypted txt: %s\n", encrypted_text);
          //printf("encrypt length: %d\n", encryptedtxt_len);
          unsigned char encrypt_and_iv[encryptedtxt_len+20];

          memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
          memcpy(encrypt_and_iv+4, iv1, 16);
          memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

          printf("IV\n" );
          BIO_dump_fp(stdout, iv1, 16);


        //  printf("encrypt_and_iv size: %d\n", strlen(encrypt_and_iv));

          printf("BIO DUMP\n");
          BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);

          int u = send(clientsocket, encrypt_and_iv,encryptedtxt_len+20,0);

          int s = 0;
          char ans[5000];
          char decrypted_ans[5000];
          char iv2[16];

          while(s < 1) {
            s = recv(clientsocket,ans,5000,0);
          }

          printf("DECRYPTION\n");

          char ans_len[3];
          //memcpy(ans_len, ans, 3);
          int ans_encrypt_len = 0;
          memcpy(&ans_encrypt_len, ans, 4);
          //printf("Num: %d\n", ans_len);
          memcpy(iv2, ans+3, 16);
          //printf("iv: %s\n", iv2);
          char no_iv2[5000];

          memcpy(no_iv2,ans+19,5000);
          //printf("no iv2: %s\n", no_iv2);

          int decryptedans_len = decrypt(no_iv2, ans_encrypt_len, symmetric_key, iv2, decrypted_ans);
          printf("decrypting worked?\n");

          // now we decrypt the msg
          // now we re-encrypt before sending
          // char encrypted_text[5000];
          // int length = 0;
          // encrypt_msg(decrypted_ans, encrypted_text, length);
          printf(" Decrypted char: %s\n", decrypted_ans);

          printf("Starting Encryption: \n");

          char encrypted_msg[5000];
          unsigned char iv_msg[16];

          RAND_bytes(iv_msg,16);
          //printf("IV %s\n",iv_msg);

          //printf("symmetric key %s \n", symmetric_key);
          int encryptedmsg_len = encrypt(decrypted_ans, strlen(decrypted_ans), symmetric_key, iv_msg, encrypted_msg);

          //printf("encrypted txt: %s\n", encrypted_msg);
        //  printf("encrypt length: %d\n", encryptedmsg_len);
          unsigned char encryptmsg_and_iv[encryptedmsg_len+20];

          memcpy(encryptmsg_and_iv, &encryptedmsg_len, 4);
          memcpy(encryptmsg_and_iv+4, iv_msg, 16);
          memcpy(encryptmsg_and_iv+20, encrypted_msg, encryptedmsg_len);

          printf("IV\n" );
          BIO_dump_fp(stdout, iv_msg, 16);


          //printf("encrypt_and_iv size: %d\n", strlen(encryptmsg_and_iv));

          printf("BIO DUMP\n");
          BIO_dump_fp(stdout, encryptmsg_and_iv, encryptedmsg_len+20);


          int o = 0;
          for(;o<get_clients_vals->connections_num; o++) {
            if(get_clients_vals->socket[o] > 0) {
              int p = send(get_clients_vals->socket[o],encryptmsg_and_iv, encryptedmsg_len+20,0);
            }
          }

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
          printf("Compare Val All %d\n", strncmp(match,"all", strlen(match)));

          if (strncmp(match,get_clients_vals->client_name[y], strlen(match)) == 10) {
            printf("ISSA MATCH\n");
            send_socket = get_clients_vals->socket[y];
            index = y;
          }
      }

      if (send_socket > 0) {
        char* temp = "Please enter the password";
        // now we re-encrypt before sending
        // char encrypted_text[5000];
        // int length = 0;
        // encrypt_msg(temp, encrypted_text,length);

        printf("Starting Encryption: \n");

        char encrypted_text[5000];
        unsigned char iv1[16];

        RAND_bytes(iv1,16);
      //  printf("IV %s\n",iv1 );

      //  printf("symmetric key %s \n", symmetric_key);
        int encryptedtxt_len = encrypt(temp, strlen(temp), symmetric_key, iv1, encrypted_text);

        char num_char[3];

        //printf("encrypted txt: %s\n", encrypted_text);
        //printf("encrypt length: %d\n", encryptedtxt_len);
        unsigned char encrypt_and_iv[encryptedtxt_len+20];

        memcpy(encrypt_and_iv, &encryptedtxt_len, 4);
        memcpy(encrypt_and_iv+4, iv1, 16);
        memcpy(encrypt_and_iv+20, encrypted_text, encryptedtxt_len);

        printf("IV\n" );
        BIO_dump_fp(stdout, iv1, 16);


        //printf("encrypt_and_iv size: %d\n", strlen(encrypt_and_iv));

        printf("BIO DUMP\n");
        BIO_dump_fp(stdout, encrypt_and_iv, encryptedtxt_len+20);

        int u = send(clientsocket, encrypt_and_iv, encryptedtxt_len+20,0);
        // block till we get our message
        int s = 0;
        char ans[5000];
        char decrypted_ans[5000];
        unsigned char iv2[16];

        while(s < 1) {
          s = recv(clientsocket,ans,5000,0);
          printf("RECV val: %d\n", s);
        }

        printf("Start decryption\n");
        char ans_len[3];
        memcpy(ans_len, ans, 3);
        int ans_encrypt_len = atoi(ans_len);
        printf("Num: %d\n", ans_len);
        memcpy(iv2, ans+3, 16);
        printf("iv: %s\n", iv2);
        char no_iv2[5000];

        memcpy(no_iv2,ans+19,5000);
        printf("no iv2: %s\n", no_iv2);

        int decryptedans_len = decrypt(no_iv2, ans_encrypt_len, symmetric_key, iv2, decrypted_ans);
        printf("decrypting worked?\n");

        if(strncmp(decrypted_ans,password,6) == 0) {
          get_clients_vals->socket[index] = -1;
          printf("Closing Socket at %s\n", get_clients_vals->client_name[index]);

          //get_clients_vals->client_name[index] = "";
          memcpy(get_clients_vals->client_name[index],"",5);
          char* exit = "escape_msg";

          // next we encrypt again
          // char encrypted_text1[5000];
          // int length1 = 0;
          // encrypt_msg(exit, encrypted_text1,length1);

          printf("Starting Encryption: \n");

          char encrypted_msg[5000];
          unsigned char iv_msg[16];

          RAND_bytes(iv_msg,16);
          //printf("IV %s\n",iv_msg);

          //printf("symmetric key %s \n", symmetric_key);
          int encryptedmsg_len = encrypt(exit, strlen(exit), symmetric_key, iv_msg, encrypted_msg);

          //printf("encrypted txt: %s\n", encrypted_msg);
          //printf("encrypt length: %d\n", encryptedmsg_len);
          unsigned char encryptmsg_and_iv[encryptedmsg_len+20];

          memcpy(encryptmsg_and_iv, &encryptedmsg_len, 4);
          memcpy(encryptmsg_and_iv+4, iv_msg, 16);
          memcpy(encryptmsg_and_iv+20, encrypted_msg, encryptedmsg_len);

          printf("IV\n" );
          BIO_dump_fp(stdout, iv_msg, 16);


          //printf("encrypt_and_iv size: %d\n", strlen(encryptmsg_and_iv));

          printf("BIO DUMP\n");
          BIO_dump_fp(stdout, encryptmsg_and_iv, encryptedmsg_len+20);


          // send message to client to let them know we're closing them
          int f = send(send_socket,encryptmsg_and_iv,encryptedmsg_len+20,0);
          //close(send_socket);

          //break;
          //continue;
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
  struct args *our_arg = (struct args *)arg;
  int clientsocket = our_arg->our_socket;

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

    printf("creating arg struct\n");

    struct args *args_to_pass = (struct args*)malloc(sizeof(struct args));
    memcpy(&args_to_pass->client_list, &connections, sizeof(connections));
    // we need to loop through and copy each item (sad)
    args_to_pass->client_list.connections_num = connections->connections_num;
    // memcpy(&args_to_pass->client_list.connections_num, &connections->connections_num, sizeof(connections->connections_num));
    int s = 0;
    for(;s<connections->connections_num;s++) {
      args_to_pass->client_list.socket[s] = connections->socket[s];
      memcpy(args_to_pass->client_list.client_name[s], connections->client_name[s], 3);
    }
    args_to_pass->our_socket = clientsocket;
    args_to_pass->index = placeholder;
    printf("Socket Num: %d\n", args_to_pass->client_list.socket[0]);
    printf("Connections num: %d\n", args_to_pass->client_list.connections_num);

    printf("ARG SOCKET: %d\n", clientsocket);

    placeholder += 1;
    // add the socket to our struct
    // we will need to go through and check
    pthread_t receive;
    pthread_t send;
    printf("\n");
    printf("creating threads\n");
    printf("\n");

    pthread_create(&receive, NULL, handleclient, args_to_pass);
    pthread_detach(receive);

    pthread_create(&send, NULL, handleserver, args_to_pass);
    pthread_detach(send);




	}
  EVP_cleanup();
  ERR_free_strings();

	return 0;
}
