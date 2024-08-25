// need:
// load up server addrinfo on localhost : some port
// create and bind a socket to that address
// listen for connections on that port
// accept any connections on port from clients
// spin up a new thread for each client
// receive incoming from each client
// forward received to relevant clients
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdbool.h>

#define MAX_CLIENT_COUNT 10

void broadcast(char *msg, uint len);


struct client_sock {
  int fd;
  struct sockaddr_storage addr;
  pthread_t thread;
  char alias[16];
  bool connected;
};

struct client_sock clients[MAX_CLIENT_COUNT];
int connected_client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void disconnect_client(struct client_sock *client) {
  char disconnect_msg[32];
  sprintf(disconnect_msg, "%s left the chat\n", client->alias);
  broadcast(disconnect_msg, strlen(disconnect_msg));
  // need to remove this client from connected list and then shift list
  // along
  // get access to client list 
  pthread_mutex_lock(&clients_mutex);
  client->connected = false;
  --connected_client_count;
  pthread_mutex_unlock(&clients_mutex);
}

int send_all_to(char *msg, uint *len, int to_fd) {
  uint sent = 0;
  uint left = *len;
  while (sent < *len) {
    int just_sent = send(to_fd, msg + sent, left, 0);
    if (just_sent == -1) {
      // error
      return -1;
    }

    sent += just_sent;
    left -= just_sent;
  }

  *len = sent;
  return 0;
}

void broadcast(char *msg, uint len) {
  pthread_mutex_lock(&clients_mutex);
  for (int i = 0; i < MAX_CLIENT_COUNT; ++i) {
    if (clients[i].connected == 0) {
      continue;
    }

    if (send_all_to(msg, &len, clients[i].fd) == -1) {
      char ip_str[INET6_ADDRSTRLEN];
      inet_ntop(clients[i].addr.ss_family,
                get_in_addr((struct sockaddr *)&(clients[i].addr)), ip_str,
                sizeof ip_str);

      fprintf(stderr, "server: failed to send to %s\n", ip_str);
    }
  }
  pthread_mutex_unlock(&clients_mutex);
}

void *handle_client(void *args) {
  struct client_sock *client = (struct client_sock *)args;
  char buf[1024];
  char ip_str[INET6_ADDRSTRLEN];
  inet_ntop(client->addr.ss_family,
            get_in_addr((struct sockaddr *)&client->addr), ip_str,
            sizeof ip_str);

  // first let's prompt user for a username
  char *msg = "username: ";
  uint msg_len = strlen(msg);
  if (send_all_to(msg, &msg_len, client->fd) == -1) {
    fprintf(stderr, "server: failed to send to %s\n", ip_str);
    return (void *)2;
  }
  if (recv(client->fd, &client->alias, sizeof client->alias, 0) == -1) {
    fprintf(stderr, "server: error receiving data from %s\n", ip_str);
    return (void *)1;
  }

  client->alias[strcspn(client->alias, "\n")] = 0;

  client->connected = 1;

  printf("server: new connection %s (%s)\n", client->alias, ip_str); 
  sprintf(buf, "%s joined the room\n", client->alias);
  broadcast(buf, strlen(buf));

  while (1) {
    // empty out buffer
    memset(buf, 0, sizeof buf);
    uint recv_count = recv(client->fd, &buf, sizeof buf, 0);
    switch (recv_count) {
    case -1: // error
      fprintf(stderr, "server: error receiving data from %s\n", ip_str);
      return (void *)1;
    case 0: // connection closed
      printf("server: connection %s closed\n", ip_str);
      disconnect_client(client);
      return (void *)0;
    default: // got some data
      printf("server: %s: %s\n", ip_str, buf);
      // send it out to everyone
      char amended_msg[strlen(buf) + strlen(client->alias) + 3];
      sprintf(amended_msg, "%s: %s", client->alias, buf);
      broadcast(amended_msg, strlen(amended_msg));
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "usage: chatc port\n");
    exit(1);
  }

  struct addrinfo hints, *res;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  int status;
  if ((status = getaddrinfo(NULL, argv[1], &hints, &res)) == -1) {
    fprintf(stderr, "server: getaddrinfo: %s", gai_strerror(status));
    exit(1);
  }

  int self_sockfd;
  struct addrinfo *p;
  for (p = res; p != NULL; p = p->ai_next) {
    if ((self_sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) ==
        -1) {
      fprintf(stderr, "server: socket");
      continue;
    }

    // reuse port from previous run, if some socket is still hanging about
    int yes = 1;
    if (setsockopt(self_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) ==
        -1) {
      fprintf(stderr, "server: setsockopt");
      exit(1);
    }

    if (bind(self_sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      fprintf(stderr, "server: bind");
      continue;
    }

    break;
  }

  // failed to bind
  if (p == NULL) {
    fprintf(stderr, "server: failed to bind socket");
    exit(1);
  }

  // can discard addrinfo
  freeaddrinfo(res);

  if (listen(self_sockfd, MAX_CLIENT_COUNT) == -1) {
    fprintf(stderr, "server: listen");
    exit(1);
  }

  // setup polling for incoming connections
  struct pollfd sockpfd;
  sockpfd.fd = self_sockfd;
  sockpfd.events = POLL_IN;

  char ip_str[INET6_ADDRSTRLEN];

  printf("server: listening on port %s\n", argv[1]);

  // set all threads as available
  for (size_t i = 0; i < MAX_CLIENT_COUNT; ++i) {

  }

  
  while (1) {
    // wait for 100ms to see if there's a new connection incoming
    int conn_incoming = poll(&sockpfd, 1, 100);
    if (conn_incoming == -1) {
      fprintf(stderr, "server: poll");
      continue;
    }
    if (conn_incoming == 1 && (sockpfd.revents & POLL_IN)) {
      // there is a connection waiting
      struct sockaddr_storage *new_conn_addr =
          &clients[connected_client_count].addr;
      socklen_t new_addr_len = sizeof *new_conn_addr;
      int new_connfd =
          accept(self_sockfd, (struct sockaddr *)new_conn_addr, &new_addr_len);
      if (new_connfd == -1) {
        // failed to connect to client
        fprintf(stderr, "server: failed to connect to client");
        memset(new_conn_addr, 0, new_addr_len);
        continue;
      }

      clients[connected_client_count].fd = new_connfd;

      // spin up new thread for this client
      pthread_create(&clients[connected_client_count].thread, NULL,
                     handle_client, &clients[connected_client_count]);
      ++connected_client_count;
    }
  }
}
