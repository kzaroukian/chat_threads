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
      // the key should be sent next
      // block till we get our key
      // each thread needs a different key
      //int r = -1;
      char encrypted_key[5000];
      memcpy(encrypted_key,line+4,sizeof(line)-4);
      //printf("length: %d, encrypted key: %s\n", strlen(encrypted_key),encrypted_key);
      // while (r < 0) {
      //   r = recv(clientsocket,encrypted_key,32,0);
      //   printf("encrypted key\n");
      // }
      // int r = recv(clientsocket,encrypted_key,32,0);
      // printf("we should have the encrypted key now r val: %d\n", r);

      // we should have now received the encrypted key
      int decryptedkey_len = rsa_decrypt(encrypted_key, 256, private_key,symmetric_key);
    //printf("Key: %s", symmetric_key);

      // now we have the decrypted symmetric key!
      memcpy(get_clients_vals->symmetric_keys[s_index], symmetric_key, decryptedkey_len);
      continue;
    } else if (loop_num >1){
      // we already have the decrypted key
      // int m = -1;
      //
      // // now we should receive the iv
      // while(m < 0) {
      //   m = recv(clientsocket,iv,16,0);
      // }


      // get the iv
      printf("received message: %s\n", line);

      // once we get the iv get the encrypted msg
      char len_res[3];
      memcpy(len_res, line, 3);
      int encrypt_length = atoi(len_res);
      printf("Num: %d\n", encrypt_length);
      memcpy(iv, line+3, 16);
      printf("iv: %s\n", iv);
      char no_iv[5000];
    //  char* here = "got 'em'";
      // got the iv - now tell the server we got it
      //send(clientsocket,here,strlen(here),0);

      // block till we get the encrypted msg
      int r = 0;
      // while(r < 1){
      //   // our encrypted msg
      //   recv(clientsocket, no_iv, 5000, 0);
      // }
      // block till we
      memcpy(no_iv,line+19,5000);
      printf("no iv: %s\n", no_iv);
      printf("str len of no iv %d, sizeo of %d\n", strlen(no_iv), sizeof(no_iv));
      //int fin = strlen(no_iv);
      // lets decrypt the message sent
      //int decrypt_len = round_by_sixteen(fin);
      //printf("Data: %d\n", encrypt_length);
    //  printf("Decrypt length %d\n", decrypt_len);
      int decryptedline_len = decrypt(no_iv, 16, symmetric_key, iv, decrypted_line);
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
        int u = send(clientsocket, sendVal, strlen(sendVal)+1,0);
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
        int u = send(clientsocket, hold, strlen(hold)+1,0);
      }
      if(strncmp(decrypted_line,"me\n",2) == 0) {
        get_clients_vals = getClients();
        int y = 0;
        for(;y<get_clients_vals->connections_num;y++) {
          if(get_clients_vals->socket[y] == clientsocket)  {
            char temp[3];
            memcpy(temp,get_clients_vals->client_name[y],3);
            int u = send(clientsocket, temp, strlen(temp)+1,0);
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
        for(;y<get_clients_vals->connections_num;y++) {
          printf("Compare Val %d\n", strncmp(match,"all", strlen(match)));

          if (strncmp(match,get_clients_vals->client_name[y], strlen(match)) == 10) {
            //printf("ISSA MATCH\n");
            send_socket = get_clients_vals->socket[y];
          }

        }
        if (send_socket > 0) {
          char* temp = "What message would you like to send?";
          int u = send(clientsocket, temp, strlen(temp)+1,0);
          // block till we get our message
          int s = 0;
          char ans[5000];
          char decrypted_ans[5000];
          char iv2[16];
          // need to decrypt this
          while(s < 1) {
            s = recv(clientsocket,ans,5000,0);
          }
          int b = -1;
          while (b < 1) {
            b = recv(clientsocket,iv2,32,0);
          }

          // now we decrypt the msg
          int decryptedans_len = decrypt(ans, sizeof(ans), symmetric_key, iv2, decrypted_ans);

          send(send_socket, decrypted_ans, strlen(decrypted_ans)+1,0);
        } else if(strncmp(match,"all", strlen(match)) == 0) {
          char* temp = "What message would you like to send?";
          int u = send(clientsocket, temp, strlen(temp)+1,0);
          int s = 0;
          char ans[5000];
          char decrypted_ans[5000];
          char iv2[16];

          while(s < 1) {
            s = recv(clientsocket,ans,5000,0);
          }
          int b = -1;
          while (b < 1) {
            b = recv(clientsocket,iv2,32,0);
          }
          // now we decrypt the msg
          int decryptedans_len = decrypt(ans, sizeof(ans), symmetric_key, iv2, decrypted_ans);

          int o = 0;
          for(;o<get_clients_vals->connections_num; o++) {
            if(get_clients_vals->socket[o] > 0) {
              int p = send(get_clients_vals->socket[o],decrypted_ans, strlen(decrypted_ans)+1,0);
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
        int u = send(clientsocket, temp, strlen(temp)+1,0);
        // block till we get our message
        int s = 0;
        char ans[5000];
        while(s < 1) {
          s = recv(clientsocket,ans,5000,0);
          printf("RECV val: %d\n", s);
        }
        if(strncmp(ans,password,6) == 0) {
          get_clients_vals->socket[index] = -1;
          printf("Closing Socket at %s\n", get_clients_vals->client_name[index]);

          //get_clients_vals->client_name[index] = "";
          memcpy(get_clients_vals->client_name[index],"",5);
          char* exit = "escape_msg";

          // send message to client to let them know we're closing them
          int f = send(send_socket,exit,strlen(exit)+1,0);
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

    EVP_cleanup();
    ERR_free_strings();


	}

	return 0;
}
