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

// struct to hold all connected clients
struct clients {
  struct in_addr client_address[10];
  char client_name[10][5];
  u_int socket[10];
  int connections_num;
};

// struct of args to pass and send
struct args{
  u_int our_socket;
  int index;
  struct clients client_list;
};

struct clients *connections;
char password[6];

struct clients* getClients() {
  return connections;
}

void sigHandler(int signum) {
	if (signum == SIGUSR1) {
		return;
	}
}

char* commands() {
  char* send = "Commands: \n get all clients \n sendto: clientNum message \n sendto: everyone message \n kick clientname";
  return send;
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

void* handleclient(void* arg) {
  printf("made it into recv thread\n");
  struct args *our_arg = (struct args *) arg;
  struct clients *client_val = (struct clients *)malloc(sizeof(struct clients));
  struct clients *get_clients_vals;
  //struct clients client = our_arg->client_list;
  //struct clients *client_val = (struct clients *) client;

  int clientsocket = our_arg->our_socket;
  printf("Socket: %d\n", clientsocket);

  while (1) {
    char line[5000];
    int t = recv(clientsocket,line,5000,0);
    get_clients_vals = getClients();
    //memcpy(&client_val)
    // means we need to destroy this thread
    // this only closes the thread doesn't delete it
    if (strncmp(line,"disconnecting_client",20) == 0) {
      close(clientsocket);
      //kill(getppid(),SIGUSR1);
      return 0;

    }
    printf("Got from client: %s\n", line);
    printf("Total Connections: %d\n", get_clients_vals->connections_num);
    printf("Socket 1: %d\n", get_clients_vals->socket[0]);
    printf("Socket 2: %d\n", get_clients_vals->socket[1]);


    char sendVal[5000];
    if(strncmp(line, "commands",8) == 0){
      char* results = commands();
      memcpy(sendVal,results,5000);
      int u = send(clientsocket, sendVal, strlen(sendVal)+1,0);
    }
    if(strncmp(line, "get all clients\n", 15) == 0) {
      // char* results = getListOfClients();
      // memcpy(sendVal,results,5000);
      int y = 0;
      for(;y<get_clients_vals->connections_num;y++) {
        char temp[3];
        printf("Username: %s\n",get_clients_vals->client_name[y] );
        memcpy(temp,get_clients_vals->client_name[y],3);
        int u = send(clientsocket, temp, strlen(temp)+1,0);

      }
    }

    if(strncmp(line,"sendto",6) == 0){
      char match[3];
      memcpy(match,line + 7,3);
      u_int send_socket = 0;
      printf("TO: %s\n",match);
      printf("Size: %lu\n", strlen(match));
      int y = 0;
      for(;y<get_clients_vals->connections_num;y++) {
        printf("Compare Val %d\n", strncmp(match,"all", strlen(match)));

        if (strncmp(match,get_clients_vals->client_name[y], strlen(match)) == 10) {
          printf("ISSA MATCH\n");
          send_socket = get_clients_vals->socket[y];
        }
        //char temp[3];
        //printf("Username: %s\n",get_clients_vals->client_name[y] );
        //memcpy(temp,get_clients_vals->client_name[y],3);

      }
      if (send_socket > 0) {
        char* temp = "What message would you like to send?";
        int u = send(clientsocket, temp, strlen(temp)+1,0);
        // block till we get our message
        int s = 0;
        char ans[5000];
        while(s < 1) {
          s = recv(clientsocket,ans,5000,0);
        }
        send(send_socket, ans, strlen(ans)+1,0);
      } else if(strncmp(match,"all", strlen(match)) == 0) {
        char* temp = "What message would you like to send?";
        int u = send(clientsocket, temp, strlen(temp)+1,0);
        int s = 0;
        char ans[5000];
        while(s < 1) {
          s = recv(clientsocket,ans,5000,0);
        }
        int o = 0;
        for(;o<get_clients_vals->connections_num; o++) {
          if(get_clients_vals->socket[o] > 0) {
            int p = send(get_clients_vals->socket[o],ans, strlen(ans)+1,0);
          }
        }

      }
    }

    if(strncmp(line, "kick", 4) == 0) {
      printf("Entered kick\n");
      char match[3];
      memcpy(match,line + 5,3);
      u_int send_socket = 0;
      printf("TO: %s\n",match);
      printf("Size: %lu\n", strlen(match));
      int y = 0;
      int index = 0;
      for(;y<get_clients_vals->connections_num;y++) {
        printf("Compare Val %d\n", strncmp(match,"all", strlen(match)));

        if (strncmp(match,get_clients_vals->client_name[y], strlen(match)) == 10) {
          printf("ISSA MATCH\n");
          send_socket = get_clients_vals->socket[y];
          index = y;
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
  }

    if(strncmp(line, "Quit\n", 4) == 0) {
      printf("Quit sent\n");
      close(clientsocket);
      return 0;
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
    connections->connections_num = placeholder+1;
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

	return 0;
}
