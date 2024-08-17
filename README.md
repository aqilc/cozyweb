<div align="center">
	<h1>cozyweb</h1>
	<p>Single file C99 header networking libraries.</p>
</div>

| Library | Description | LOC | Latest Version |
|---------|-------------|-----|----------------|
| **[udp.h](udp.h)** | Asynchronous Server and Client on a UDP connection, useful for VOIP and game servers. | 573 | 1.0.0 |
| **[https.h](https.h)** | Asynchronous HTTPS and HTTP Client using 1 function call to issue a GET request. | 435 | 1.0.0 |

Usage
-----

Check out the 200 line cross platform UDP VOIP Server and Client in the [voip](voip) directory!

There are examples inside the header file sources, but here's a simple introduction to each of the libraries:

### udp.h

```c
#include <stdio.h>

#define UDP_IMPLEMENTATION
#include "udp.h"

int main() {
		udp_conn* client = udp_connect(udp_resolve_host("localhost", "30000", true, &(udp_addr){}), false);
		if(client->error) return !!printf("Error %d: %s\n", client->error, udp_error_str(client->error));

		udp_send(client, "Hello from client!", sizeof("Hello from clie16!"));
		
		while(!udp_recv(client)); // Wait for a response from the server.
		printf("Received \"%.*s\"\n", (int) client->data_len, (char*) client->data);

		udp_close_n_free(client);
}
```

### https.h

```c
#include <stdio.h>

#define HTTPS_IMPLEMENTATION
#include "include/https.h"

int main() {
		https_req* req = https_get("https://picsum.photos/600/800");
		while(req->state == HTTPS_PENDING);// Sleep(20);

		if(req->state != HTTPS_COMPLETE) {
				printf("Failed to get response\nStatus Code: %d\nReason: %s", req->status_code, req->req_failed_reason);
				https_free(req);
				return 1;
		}

		printf("Status: %d\n", req->status_code);
		printf("Response Size: %u\n", req->data_len);
		printf("Response: %.256s\n", (char const*) req->data);
		https_free(req);
}
```

Examples
--------

There are applicable examples in the [voip](voip) and [examples](examples) directories. Notable ones are the VOIP application and the HTTPS client.

License
-------

These libraries are all dual licenced under the MIT Licence and Public Domain. You can choose the licence that suits your project the best. The MIT Licence is a permissive licence that is short and to the point. The Public Domain licence is a licence that makes the software available to the public for free and with no copyright.

FAQ
---

> - ***There are many alternatives like cute_headers' cute_tls and cute_net. Why should I use cozyweb?***

When I was personally using cute_headers and similar single header libraries for interfacing with the web, the libraries had a lot of function calls and strict notions about how their libraries are meant to be used. I want to remove that as much as possible from my libraries and make them easy for beginners while giving them as much control as possible.

> - ***These libraries don't fit my need. What are some others?***

- [cute_headers](https://github.com/RandyGaul/cute_headers)
- [http.h](https://github.com/mattiasgustavsson/libs/blob/main/docs/http.md)
- [enet](https://github.com/lsalzman/enet)
- [SDL_net](https://github.com/libsdl-org/SDL_net)
