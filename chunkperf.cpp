#include <iostream>
#include <cstring>
#include <cassert>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CLIENT_FLAG "c::"
#define DEFAULT_CLIENT_CONNECT_IP "127.0.0.1"

#define SERVER_FLAG "s::"
#define DEFAULT_SERVER_LISTEN_IP "0.0.0.0"

#define PORT_FLAG "p:"
#define DEFAULT_PORT 1234

#define CLIENT_BIND_PORT_FLAG "b:"
#define DEFAULT_CLIENT_BIND_PORT 0

#define NUM_CHUNKS_FLAG "n:"
#define DEFAULT_NUM_CHUNKS 1

#define CHUNK_LENGTH_FLAG "l:"
#define DEFAULT_CHUNK_LENGTH 1000000

#define CHUNK_DELAY_FLAG "d:"
#define DEFAULT_CHUNK_DELAY_MS 0

#define ALL_FLAGS                                                         \
  CLIENT_FLAG SERVER_FLAG PORT_FLAG CLIENT_BIND_PORT_FLAG NUM_CHUNKS_FLAG \
      CHUNK_LENGTH_FLAG CHUNK_DELAY_FLAG

typedef struct __attribute__((__packed__)) {
  unsigned long chunk_length = DEFAULT_CHUNK_LENGTH;
} request_t;

int main(int argc, char *argv[]) {
  // Either c or s or 0 if not specified.
  char mode = 0;

  in_addr client_connect_ip;
  inet_aton(DEFAULT_CLIENT_CONNECT_IP, &client_connect_ip);

  in_addr server_listen_ip;
  inet_aton(DEFAULT_SERVER_LISTEN_IP, &server_listen_ip);

  unsigned short port = DEFAULT_PORT;
  unsigned short client_bind_port = DEFAULT_CLIENT_BIND_PORT;

  unsigned long num_chunks = DEFAULT_NUM_CHUNKS;
  unsigned long chunk_delay_ms = DEFAULT_CHUNK_DELAY_MS;

  request_t request;

  int c;
  while ((c = getopt(argc, argv, ALL_FLAGS)) != -1) {
    switch (c) {
      case CLIENT_FLAG[0]:
        mode = 'c';
        if (optarg) inet_aton(optarg, &client_connect_ip);
        break;
      case SERVER_FLAG[0]:
        mode = 's';
        if (optarg) inet_aton(optarg, &server_listen_ip);
        break;
      case PORT_FLAG[0]:
        assert(optarg && "Missing option.");
        port = atoi(optarg);
        break;
      case CLIENT_BIND_PORT_FLAG[0]:
        assert(optarg && "Missing option.");
        client_bind_port = atoi(optarg);
        break;
      case NUM_CHUNKS_FLAG[0]:
        assert(optarg && "Missing option.");
        num_chunks = atol(optarg);
        break;
      case CHUNK_LENGTH_FLAG[0]:
        assert(optarg && "Missing option.");
        request.chunk_length = atol(optarg);
        break;
      case CHUNK_DELAY_FLAG[0]:
        assert(optarg && "Missing option.");
        chunk_delay_ms = atol(optarg);
        break;
      default:
        std::cerr
            << "Usage: " << argv[0] << " {-" << SERVER_FLAG[0]
            << " [listen-ip=" << DEFAULT_SERVER_LISTEN_IP << "] | -"
            << CLIENT_FLAG[0] << " [connect-ip=" << DEFAULT_CLIENT_CONNECT_IP
            << "] [-" << NUM_CHUNKS_FLAG[0]
            << " <num-chunks=" << DEFAULT_NUM_CHUNKS << ">] [-"
            << CHUNK_LENGTH_FLAG[0] << " <chunk-length=" << DEFAULT_CHUNK_LENGTH
            << ">] [-" << CHUNK_DELAY_FLAG[0]
            << " <chunk-delay-ms=" << DEFAULT_CHUNK_DELAY_MS << ">]} [-"
            << PORT_FLAG[0] << " <port=" << DEFAULT_PORT << ">]" << std::endl;
        return -1;
        break;
    }
  }

  if (mode == 'c') {
    std::cout << "Connecting to: " << inet_ntoa(client_connect_ip) << ":"
              << port << std::endl;
    int sockfd = 0;
    assert((sockfd = socket(AF_INET, SOCK_STREAM, 0)) >= 0);

    if (client_bind_port) {
      int option = 1;
      assert(setsockopt(sockfd, SOL_SOCKET, (SO_REUSEPORT | SO_REUSEADDR),
                        (char *)&option, sizeof(option)) == 0);

      struct sockaddr_in cli_addr;
      memset(&cli_addr, 0, sizeof(cli_addr));
      cli_addr.sin_family = AF_INET;
      inet_aton("0.0.0.0", &cli_addr.sin_addr);
      cli_addr.sin_port = htons(client_bind_port);
      assert(bind(sockfd, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) == 0);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr = client_connect_ip;
    assert(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
           0);

    std::cout << "Requesting " << num_chunks << " chunks of "
              << request.chunk_length << " bytes every " << chunk_delay_ms
              << " ms." << std::endl;
    unsigned long total = 0;
    for (unsigned long i = 1; i <= num_chunks; i++) {
      std::cout << "Requesting chunk " << i << " of " << num_chunks << "."
                << std::endl;
      assert(write(sockfd, &request, sizeof(request)) == sizeof(request));

      char recvBuff[request.chunk_length];
      int n;
      unsigned long chunkTotal = 0;
      while (chunkTotal < request.chunk_length &&
             (n = read(sockfd, &recvBuff, sizeof(recvBuff))) > 0) {
        chunkTotal += n;
        total += n;
      }
      assert(n >= 0 && "Read failed.");
      std::cout << "Received a chunk of " << request.chunk_length << " bytes."
                << std::endl;
      if (chunk_delay_ms > 0 && i < num_chunks) {
        usleep(chunk_delay_ms * 1000);
      }
    }

    std::cout << "Received " << total << " bytes." << std::endl;
  } else if (mode == 's') {
    std::cout << "Listening on: " << inet_ntoa(server_listen_ip) << ":" << port
              << std::endl;

    int listenfd, connfd;
    struct sockaddr_in serv_addr;

    assert((listenfd = socket(AF_INET, SOCK_STREAM, 0)) >= 0);

    int option = 1;
    assert(setsockopt(listenfd, SOL_SOCKET, (SO_REUSEPORT | SO_REUSEADDR),
                      (char *)&option, sizeof(option)) == 0);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr = server_listen_ip;
    serv_addr.sin_port = htons(port);
    assert(bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) ==
           0);
    assert(listen(listenfd, 1) == 0);

    while (true) {
      struct sockaddr_in cli_addr;
      assert((connfd = accept(listenfd, (struct sockaddr *)NULL, NULL)) >= 0);
      std::cout << "Accepted connection from: " << inet_ntoa(cli_addr.sin_addr)
                << ":" << ntohs(cli_addr.sin_port) << std::endl;

      request_t request;
      int n;
      while ((n = read(connfd, &request, sizeof(request))) > 0) {
        assert(n == sizeof(request));

        std::cout << "Sending a chunk of " << request.chunk_length << " bytes."
                  << std::endl;
        char sendBuff[request.chunk_length];
        memset(sendBuff, 0, request.chunk_length);
        write(connfd, sendBuff, request.chunk_length);
      }
      assert(n == 0 && "Read failed.");

      close(connfd);
    }

  } else {
    std::cerr << "Must specify either -" << CLIENT_FLAG[0] << " or -"
              << SERVER_FLAG[0] << std::endl;
    return -1;
  }

  return 0;
}
