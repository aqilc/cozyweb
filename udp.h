/////////////////////////////////////////////////////////////////////////////////////////////
// udp.h v1.0 by @aqilc                                                                    //
// Licence: MIT                                                                            //
// Part of the Cozyweb project.                                                            //
//                                                                                         //
// Simple asynchronous UDP server for games, with full control handed off the user if and  //
// when they want to recieve or send a packet. Allocation is kept to a minimum and usually //
// handed off to the user. Important Note: Only packets with data are supported, 0 length  //
// packets are not.                                                                        //
//                                                                                         //
// Options:                                                                                //
//   UDP_MAX_BUFFERED_PACKETS: Maximum power of 2 number of packets that can be buffered   //
//                             before being sent.                                          //
//   UDP_DEFAULT_PACKET_ALLOCATION: Default size of the server's buffer for read packets.  //
//   UDP_CONN_MESSAGES: On Windows, you can get messages such as a client disconnecting.   //
//                      This is very unreliable, so make sure to have a timeout check on   //
//                      top if you rely on it.                                             //
/////////////////////////////////////////////////////////////////////////////////////////////

/**
Examples
========

Client:

    #include <stdio.h>
    #define UDP_IMPLEMENTATION
    #include "udp.h"
    int main() {
        // Start a UDP socket to send packets.
        udp_conn* client = udp_connect(udp_resolve_host("localhost", "30000", true, &(udp_addr){}), false);
        if(client->error) {
            printf("Error %d: %s\n", client->error, udp_error_str(client->error));
            return 1;
        }

        // Send a packet to the server.
        udp_send(client, "Hello from client!", sizeof("Hello from clie16!"));
        
        while(!udp_recv(client)); // Wait for a response from the server.
        printf("Received \"%.*s\"\n", (int) client->data_len, (char*) client->data);

        udp_close_n_free(client);

        // Or do all of the above in one function call:
        udp_send_oneshot("localhost", "30000", "Hello from client!", sizeof("Hello from clie16!"));
    }

Server:
  
    #include <stdio.h>
    #define UDP_IMPLEMENTATION
    #include "udp.h"
    
    int main() {
        // Start a UDP socket to listen for incoming packets.
        udp_conn* server = udp_serve(30000);
        if(server->error) {
            printf("Error %d: %s\n", server->error, udp_error_str(server->error));
            return 1;
        }

        // Utilities to stringify addresses for convenience.
        printf("Listening on %s\n", udp_addr_str(&server->from, (char[30]) {0}, 30));

        // Wait until a packet arrives by doing nothing. In your game, this could be a part of the event loop.
        udp_addr* resp;
        while(!udp_recv_from(server));
        
        printf("Received from %s: \"%.*s\"\n", udp_addr_str(&server->from, (char[23]) {0}, 23),
            (int) server->data_len, (char*) server->data);

        // Can send a packet back to a specific address
        udp_send_to(server, &server->from, "Hello from server!", sizeof("Hello from serv16!"));
        sleep(1000);
        udp_send_to(server, &server->from, "lolz", sizeof("lol16));

        udp_close_n_free(server);
    }

**/



#ifndef UDP_H
#define UDP_H
#include <stdbool.h>
#include <stdint.h>


#ifndef UDP_MAX_BUFFERED_PACKETS
#define UDP_MAX_BUFFERED_PACKETS 8 // HAS TO BE A POWER OF 2
#endif

#ifndef UDP_DEFAULT_PACKET_ALLOCATION
#define UDP_DEFAULT_PACKET_ALLOCATION 1024
#endif

#define UDP_IPV4(a, b, c, d) (a | b << 8 | c << 16 | d << 24)

#ifdef UDP_CONN_MESSAGES
#define UDP_ERROR_TYPE : uint16_t
#define UDP_ERROR_DEFS enum udp_error error; enum udp_conn_msg msg;

enum udp_conn_msg: uint16_t {
  UDP_CLIENT_NO_MSG = 0,
  UDP_CLIENT_DISCONNECTED
};
#else
#define UDP_ERROR_TYPE 
#define UDP_ERROR_DEFS enum udp_error error;
#endif

enum udp_error UDP_ERROR_TYPE {
  UDP_ERR_NONE = 0,
  UDP_ERR_SOCKET_CREATION_FAILED,
  UDP_ERR_SEND_FAILED,
  UDP_ERR_BIND_FAILED,
  UDP_ERR_CONNECT_FAILED,
  UDP_ERR_STARTUP_FAILED,
  UDP_ERR_ASYNCIFY_FAILED,
  UDP_ERR_GETADDRINFO_FAILED,
  UDP_ERR_RECV_FAILED,
  UDP_ERR_POLL_FAILED,
  UDP_ERR_FAILED_TO_READ_IO_LEN,
  UDP_ERR_INVALID_ADDR,
};

enum udp_send_result {
  UDP_SEND_OK = 0,
  UDP_SEND_BUFFERED,
  UDP_SEND_FAILED,
};

typedef struct udp_addr udp_addr;
typedef struct udp_conn udp_conn;
typedef union udp_ipv4_addr udp_ipv4_addr;
typedef unsigned char udp_ipv6_addr[16];
union udp_ipv4_addr {
  uint32_t addr_long;
  unsigned char addr[4];
};
struct udp_addr {
  union {
    char storage[28]; // Storage for the address struct
    unsigned short family; // First two bytes are always the address family
  };
  int addrlen;
};
struct udp_conn {
  uintptr_t sockhwnd;
  void* data;

  udp_addr from;
  UDP_ERROR_DEFS
  unsigned long data_len;
  unsigned long internal_max_packet_size;

  unsigned long packet_buf_len;
  struct udp_packet {
    udp_addr* to;
    void* data;
    uint16_t len;
    uint16_t internal_max_len;
  } packet_buf[UDP_MAX_BUFFERED_PACKETS];
};
udp_conn* udp_serve(unsigned short port);
udp_conn* udp_connect(udp_addr* addr, bool local);
void udp_close_n_free(udp_conn* server);
bool udp_recv(udp_conn* server);
bool udp_recv_from(udp_conn* server);
bool udp_recv_from_all(udp_conn* server[], uint32_t len);
enum udp_send_result udp_send(udp_conn* server, void* data, uint16_t len);
enum udp_send_result udp_send_to(udp_conn* server, udp_addr* addr, void* data, uint16_t len);
udp_addr* udp_resolve_host(const char* hostname, const char* port, bool ipv4, udp_addr* returnaddr);
enum udp_error udp_send_oneshot(const char* hostname, const char* port, void* data, uint16_t len);
bool udp_addr_same(udp_addr* addr_a, udp_addr* addr_b);
bool udp_valid_addr(udp_addr* addr);
char* udp_addr_str(udp_addr* addr, char* buf, uint32_t len);
char* udp_error_str(enum udp_error err);

#ifdef _WIN32
udp_ipv4_addr udp_external_ipv4_addr();
#endif

#endif

#define UDP_IMPLEMENTATION
#ifdef UDP_IMPLEMENTATION
#include <stdlib.h>

#ifdef _WIN32
// https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// #include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <mswsock.h>
#include <time.h>
#include <malloc.h>
// #include "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um\WinDNS.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
typedef SOCKET socket_t;
#define ioctl ioctlsocket
#define close closesocket

// Note to all users experiencing a very niche issue: https://daniel.haxx.se/blog/2012/10/10/wsapoll-is-broken/
#define poll WSAPoll
#define INITWINSOCK if(!session_started && WSAStartup(0x0002, &(struct WSAData){0}))

#ifdef _MSC_VER
#define _Thread_local __declspec(thread)
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

_Thread_local static bool session_started = false;
#define UDP_SOCKET_ERROR WSAGetLastError()

#else
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#define INVALID_SOCKET -1
#define INITWINSOCK if(0) // Code gets completely ignored(not compiled) because compilers are smart
#define UDP_SOCKET_ERROR errno
#endif

// https://stackoverflow.com/a/2862176/10013227
// Best size to send udp packets is less than 1400 bytes.

// Resources
// https://www.codeproject.com/articles/11740/a-simple-udp-time-server-and-client-for-beginners

char* udp_error_str(enum udp_error err) {
  switch(err) {
    case UDP_ERR_NONE: return "No error";
    case UDP_ERR_SOCKET_CREATION_FAILED: return "Failed to create socket";
    case UDP_ERR_SEND_FAILED: return "Failed to send packet";
    case UDP_ERR_BIND_FAILED: return "Failed to bind socket";
    case UDP_ERR_STARTUP_FAILED: return "Failed to start Winsock";
    case UDP_ERR_ASYNCIFY_FAILED: return "Failed to make socket non-blocking";
    case UDP_ERR_GETADDRINFO_FAILED: return "Failed to get address info";
    case UDP_ERR_RECV_FAILED: return "Failed to receive packet";
    case UDP_ERR_POLL_FAILED: return "Failed to poll sockets";
    case UDP_ERR_FAILED_TO_READ_IO_LEN: return "Failed to read IO length";
    case UDP_ERR_INVALID_ADDR: return "Invalid address";
    default: return "Unknown error";
  }
}

char* udp_addr_str(udp_addr* addr, char* buf, uint32_t len) {
  INITWINSOCK return NULL;
  char resport[INET_ADDRSTRLEN];
  getnameinfo((struct sockaddr*) &addr->storage, addr->addrlen, buf, len - 1, resport, sizeof(resport), NI_DGRAM);
  return strncat(strncat(buf, ":", len - 1), resport, len - 1);
}

bool udp_addr_same(udp_addr* addr_a, udp_addr* addr_b) {
  return addr_a->addrlen == addr_b->addrlen && !memcmp(addr_a->storage, addr_b->storage, addr_a->addrlen);
}

bool udp_valid_addr(udp_addr* addr) {
  return addr->addrlen > 0;
}

// Creates a socket and then calls bind or connect based on the local parameter, then sets the socket to nonblocking.
udp_conn* udp_connect(udp_addr* addr, bool local) {
  udp_conn* const server = calloc(sizeof(udp_conn), 1);
  if(addr->addrlen == 0 && (server->error = UDP_ERR_INVALID_ADDR)) return server;
  INITWINSOCK {
    server->error = UDP_ERR_STARTUP_FAILED;
    return server;
  }
  
  server->data = malloc(UDP_DEFAULT_PACKET_ALLOCATION);
  server->internal_max_packet_size = UDP_DEFAULT_PACKET_ALLOCATION;
  int sock = INVALID_SOCKET;
  
  sock = socket(addr->family, SOCK_DGRAM, IPPROTO_UDP);
  if(sock == INVALID_SOCKET && (server->error = UDP_ERR_SOCKET_CREATION_FAILED)) goto fail;
  if((local ? bind : connect)(sock, (struct sockaddr*) &addr->storage, addr->addrlen) < 0 &&
     (server->error = local ? UDP_ERR_BIND_FAILED : UDP_ERR_CONNECT_FAILED)) goto fail;

#ifdef _WIN32
  if(ioctl(sock, FIONBIO, &(DWORD) {1}) < 0 && (server->error = UDP_ERR_ASYNCIFY_FAILED)) goto fail;
#ifndef UDP_CONN_MESSAGES
  if(WSAIoctl(sock, SIO_UDP_CONNRESET, &(BOOL) {FALSE}, sizeof(BOOL), NULL, 0, &(DWORD) {0}, NULL, NULL) < 0 &&
    (server->error = UDP_ERR_ASYNCIFY_FAILED)) goto fail;
#endif
#else
  if(fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) < 0 &&
    (server->error = UDP_ERR_ASYNCIFY_FAILED)) goto fail;
#endif
  
  // if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char const*)&(DWORD){0}, sizeof(DWORD)) && (server->error = UDP_ERR_ASYNCIFY_FAILED)) goto fail;
  memcpy(&server->from, addr, sizeof(udp_addr));
  server->sockhwnd = sock;
  return server;
fail:
  free(server->data);
  if(sock != INVALID_SOCKET) close(sock);
  return server;
}

udp_conn* udp_serve(unsigned short port) {
  return udp_connect(memcpy(&(udp_addr) { .addrlen = sizeof(struct sockaddr_in) }, &(struct sockaddr_in) {
    .sin_family = AF_INET,
    .sin_port = htons(port),
    .sin_addr.s_addr = INADDR_ANY
  }, sizeof(struct sockaddr_in)), true);
}

// Allocates a big block for the addresses of packets, since the packets are constant size so there's less fragmentation.
static void udp_queue_alloc_tos(udp_conn* server) {
  if(server->packet_buf[0].to) return;
  void* bigalloc = calloc(UDP_MAX_BUFFERED_PACKETS, sizeof(udp_addr));
  for(int i = 0; i < UDP_MAX_BUFFERED_PACKETS; i++) server->packet_buf[i].to = bigalloc + i * sizeof(udp_addr);
}

static enum udp_send_result udp_queue_packet(udp_conn* server, udp_addr* addr, void* data, uint16_t len) {
  udp_queue_alloc_tos(server);
  struct udp_packet* packet = &server->packet_buf[server->packet_buf_len++ & (UDP_MAX_BUFFERED_PACKETS - 1)];
  
  if(packet->internal_max_len) {
    if(packet->internal_max_len < len) {
      free(packet->data);
      packet->data = malloc(len);
      packet->internal_max_len = len;
    }
    
    memcpy(packet->data, data, len);
    packet->len = len;
    
    if(addr) memcpy(packet->to, addr, sizeof(udp_addr));
    else packet->to->addrlen = 0;
  } else {
    *packet = (struct udp_packet) {
      .data = memcpy(malloc(len), data, len),
      .len = len, .internal_max_len = len, .to = packet->to
    };
    if(addr) memcpy(packet->to, addr, sizeof(udp_addr));
    else packet->to->addrlen = 0;
  }
  
  return UDP_SEND_BUFFERED;
}

// Sending to multiple addresses in one sendto call:
// https://stackoverflow.com/a/45296984/10013227
// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-sendto#:~:text=The%20to%20parameter%20can,becoming%20a%20group%20member).
// Could definitely be useful for serverside.
static bool udp_try_flush_queue(udp_conn* server) {
  if(!server->packet_buf_len || server->error) return false;
  
  int start = server->packet_buf_len > UDP_MAX_BUFFERED_PACKETS ?
              server->packet_buf_len - UDP_MAX_BUFFERED_PACKETS : 0;
  
  for(int i = start; i < server->packet_buf_len; i++) {
    struct udp_packet* packet = &server->packet_buf[i & (UDP_MAX_BUFFERED_PACKETS - 1)];
    if(!packet->len) continue;
    
    int ret;
    if(packet->to->addrlen)
      ret = sendto(server->sockhwnd, packet->data, packet->len, 0, (struct sockaddr*) &packet->to->storage, packet->to->addrlen);
    else ret = send(server->sockhwnd, packet->data, packet->len, 0);
    
    if(ret < 0) {
      if(UDP_SOCKET_ERROR == EWOULDBLOCK) return true;
      server->error = UDP_ERR_SEND_FAILED;
      return false;
    }
    packet->len = 0;
  }
  server->packet_buf_len = 0;
  return false;
}

enum udp_send_result udp_send(udp_conn* server, void* data, uint16_t len) {
  if(udp_try_flush_queue(server)) return udp_queue_packet(server, NULL, data, len); // This can error so place it before error checks
  if(server->error) return UDP_SEND_FAILED;
  
  if(send(server->sockhwnd, data, len, 0) < 0) {
    if(UDP_SOCKET_ERROR == EWOULDBLOCK)
      return udp_queue_packet(server, NULL, data, len);
    server->error = UDP_ERR_SEND_FAILED;
    return UDP_SEND_FAILED;
  }
  return UDP_SEND_OK;
}

enum udp_send_result udp_send_to(udp_conn* server, udp_addr* addr, void* data, uint16_t len) {
  if(udp_try_flush_queue(server)) return udp_queue_packet(server, NULL, data, len);
  if(server->error) return UDP_SEND_FAILED;
  
  if(sendto(server->sockhwnd, data, len, 0, (struct sockaddr*) &addr->storage, addr->addrlen) < 0) {
    if(UDP_SOCKET_ERROR == EWOULDBLOCK)
      return udp_queue_packet(server, addr, data, len);
    // printf("Send Error: %d\n", UDP_SOCKET_ERROR);
    server->error = UDP_ERR_SEND_FAILED;
    return UDP_SEND_FAILED;
  }
  return UDP_SEND_OK;
}

static bool udp_ready_to_recv(udp_conn* server) {
  if(server->error) return false;
  if(ioctl(server->sockhwnd, FIONREAD, &server->data_len) < 0) {
    server->error = UDP_ERR_FAILED_TO_READ_IO_LEN;
    return false;
  }
  if(!server->data_len) return false;
  udp_try_flush_queue(server);
  if(server->data_len > server->internal_max_packet_size) {
    free(server->data); // Since previous data is discarded, free and malloc is much faster than realloc.
    server->data = malloc(server->data_len);
    server->internal_max_packet_size = server->data_len;
  }
  return true;
}

bool udp_recv(udp_conn* server) {
  if(!udp_ready_to_recv(server)) return false;
  
  server->data_len = recv(server->sockhwnd, server->data, server->data_len, 0);
  if(server->data_len == -1) {
#if defined(UDP_CONN_MESSAGES) && defined(_WIN32)
    if(UDP_SOCKET_ERROR == WSAECONNRESET) {
      server->msg = UDP_CLIENT_DISCONNECTED;
      return UDP_SEND_OK;
    }
#endif
    server->data_len = 0;
    server->error = UDP_ERR_RECV_FAILED;
    return false;
  }
  return true;
}

bool udp_recv_from(udp_conn* server) {
  if(!udp_ready_to_recv(server)) return false;
  
  int addrlen;
  server->from.addrlen = sizeof(server->from.storage);
  
  // Shouldn't ever block since we check if there's something to be read with ioctl already.
  server->data_len = recvfrom(server->sockhwnd, server->data, server->data_len, 0,
                              (struct sockaddr*) &server->from.storage, &server->from.addrlen);
  if(server->data_len == -1) {
#if defined(UDP_CONN_MESSAGES) && defined(_WIN32)
    if(UDP_SOCKET_ERROR == WSAECONNRESET) {
      server->msg = UDP_CLIENT_DISCONNECTED;
      return UDP_SEND_OK;
    }
#endif
    server->data_len = 0;
    server->error = UDP_ERR_RECV_FAILED;
    // printf("Recv Error: %d\n", UDP_SOCKET_ERROR);
    return false;
  }
  return true;
}

bool udp_recv_from_all(udp_conn* server[], uint32_t len) {
  if(len == 0) return false;
  struct pollfd* fds = alloca(len * sizeof(struct pollfd));

  // Skip servers that have outstanding errors
  for(int i = 0, idx; i < len; i++) {
    if(server[i]->error) continue;
    fds[idx].fd = server[idx]->sockhwnd;
    fds[idx].events = POLLIN;
    idx ++;
  }
  if(poll(fds, len, 0) < 0) {
    for(int i = 0; i < len; i++)
      server[i]->error = UDP_ERR_POLL_FAILED;
    return true;
  }

  for(int i = 0, lastidx = 0; i < len; i++, lastidx++)
    if(fds[i].revents & POLLIN) {
      while(fds[i].fd != server[lastidx]->sockhwnd && lastidx < len) lastidx++; // Since we skipped servers before, advance till we find the exact socket.
      udp_recv_from(server[lastidx]);
    }

  return false;
}

udp_addr* udp_local_addr(unsigned short port, udp_addr* returnaddr) {
  returnaddr->addrlen = sizeof(struct sockaddr_in);
  memcpy(&returnaddr->storage, &(struct sockaddr_in) {
    .sin_family = AF_INET,
    .sin_port = htons(port),
    .sin_addr.s_addr = INADDR_ANY
  }, sizeof(struct sockaddr_in));
  return returnaddr;
}

udp_addr* udp_resolve_host(const char* hostname, const char* port, bool ipv4, udp_addr* returnaddr) {
  INITWINSOCK return returnaddr;
  if(port == NULL) port = "0";
  struct addrinfo hints = {
    .ai_family = ipv4 ? AF_INET : AF_INET6,
    .ai_protocol = IPPROTO_UDP,
    .ai_flags = AI_PASSIVE,
    .ai_socktype = SOCK_DGRAM,
  };
  struct addrinfo* res = NULL;
  if(getaddrinfo(hostname, port, &hints, &res)) {
    returnaddr->addrlen = 0;
    // printf("Failed to resolve %s:%s because %s\n", hostname, port, gai_strerror(errno));
    return returnaddr;
  }
  memcpy(&returnaddr->storage, res->ai_addr, res->ai_addrlen);
  returnaddr->addrlen = res->ai_addrlen;
  freeaddrinfo(res);
  return returnaddr;
}

enum udp_error udp_send_oneshot(const char* address, const char* port, void* data, uint16_t len) {
  INITWINSOCK return UDP_ERR_STARTUP_FAILED;
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(sock == INVALID_SOCKET) return UDP_ERR_SOCKET_CREATION_FAILED;
  udp_addr* res = udp_resolve_host(address, port, false, &(udp_addr) {});
  if((len = sendto(sock, data, len, 0, (struct sockaddr*) &res->storage, res->addrlen)) < 0 && (close(sock) | 1)) return UDP_ERR_SEND_FAILED;
  return UDP_ERR_NONE;
}

void udp_close_n_free(udp_conn* server) {
  close(server->sockhwnd);
  free(server->data);
  free(server);
}

#ifdef _WIN32
// Get list of network interfaces/adapters
// SIO_ADDRESS_LIST_QUERY:
//   https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls#sio_address_list_query-opcode-setting-o-t1
//   https://learn.microsoft.com/en-us/windows/win32/winsock/sio-address-list-query
//   https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-socket_address_list
// https://tangentsoft.com/wskfaq/examples/getifaces.html   # ifaces in windows using WSAIoctl(SIO_GET_INTERFACE_LIST)

// https://stackoverflow.com/questions/65348174/c-get-external-ip-address
// https://stackoverflow.com/a/9628315/10013227    # Use DnsQueryA with undocumented MS API.

// Gets your router's IP address 😈
udp_ipv4_addr udp_external_ipv4_addr() {
  IP4_ARRAY arr = {
    .AddrCount = 1,
    .AddrArray = { UDP_IPV4(208, 67, 222, 222) } // inet_addr("208.67.222.222") but windows was bitching
  };
  PDNS_RECORD records;
  if(DnsQuery("myip.opendns.com", DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, &arr, &records, NULL)) return (udp_ipv4_addr) { .addr_long = 0 };
  udp_ipv4_addr ret = { .addr_long = records->Data.A.IpAddress };
  // printf("External IP: %s\n", inet_ntoa(*(struct in_addr*) &records->Data.A.IpAddress));
  DnsRecordListFree(records, DnsFreeRecordListDeep);
  return ret;
}
#endif

#endif
