// Project 3 Chat Client by Kaylin Zaroukian

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

int should_exit = 0;

void sigHandler(int signum) {
	if (signum == SIGUSR1) {
		exit(1);
	}
}

void* receivemessage(void* arg) {
	int serversocket = *(int*)arg;
	while(1) {
		// receive message
		char line2[5000];
		int k = recv(serversocket,line2,5000,0);

		if (strncmp(line2,"escape_msg",10) == 0) {
			printf("its a trap\n");
			char* close_message = "disconnecting_client";
			int x=send(serversocket,close_message,strlen(close_message)+1,0);
			close(serversocket);

			// kills the thread
			kill(getppid(),SIGUSR1);
			should_exit = 1;
			return 0;
		}

		if (k >= 0) {
			printf("Incoming Message: %s\n",line2);
		}

		if(strncmp(line2, "Quit", 4) == 0) {
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

	while(1) {

		pthread_t receive;

		pthread_create(&receive, NULL, receivemessage, &sockfd);

		pthread_detach(receive);

		if(should_exit == 1){
			close(sockfd);
			return 0;
		}

		// send message
		printf("Enter a line: ");
		char line[5000];
		fgets(line,5000,stdin);
		int x=send(sockfd,line,strlen(line)+1,0);

		if(strncmp(line, "Quit\n", 4) == 0) {
			close(sockfd);
			return 0;

		}
	}


}
