#include <stdio.h>
#define UDP_IMPLEMENTATION
#include "../udp.h"

// int main() {
//   int err = udp_send_oneshot("localhost", "30000", "hiiiiiiiiiii!!!!!", sizeof("hiiiiiiiiiii!!!!!"));
//   if(err) printf("sendfailed %d %d\n", err, GetLastError());
// }


int main() {
  udp_conn* server = udp_serve(30000);
  if(server->error) {
    printf("Error %d: %s\n", server->error, udp_error_str(server->error));
    return 1;
  }
  printf("Listening on %s\n", udp_addr_str(&server->from, (char[30]) {0}, 30));
  while(!udp_recv_from(server));
  printf("Received from %s: \"%.*s\"\n", udp_addr_str(&server->from, (char[23]) {0}, 23),
    (int) server->data_len, (char*) server->data);
  if(udp_send_to(server, &server->from, "Hello from server!", sizeof("Hello from server!"))) {
    printf("Error %d: %s\n", server->error, udp_error_str(server->error));
    return 1;
  }
  Sleep(1000);
  udp_send_to(server, &server->from, "lolz", sizeof("lolz"));
  udp_close_n_free(server);
}



// int main() {
//   udp_external_ipv4_addr();
// }
