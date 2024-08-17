<div align="center">
	<h1>cozyweb</h1>
	<p>Single file C99 header cross-platform networking libraries.</p>
</div>

| Library | Description | LOC | Latest Version |
|---------|-------------|-----|----------------|
| **[udp.h](udp.h)** | Asynchronous Server and Client on a UDP connection, useful for VOIP and game servers. | 573 | 1.0.0 |
| **[https.h](https.h)** | Asynchronous HTTPS and HTTP Client using 1 function call to issue a GET request. | 435 | 1.0.0 |

Usage
-----

All you need to do to use this library is download it and put it in the same directory as your source code, and then look into it for the function it defines at the top (the exports) and the provided example! Put this at the top of where you want to use it:
```c
#define UDP_IMPLEMENTATION // or HTTPS_IMPLEMENTATION
#include "udp.h" // or "https.h"
```
or optionally, put that by itself in a source file and build it separately.

Here's a simple introduction to each of the libraries:

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
		https_req* req = https_get("https://picsum.photos/600/800"); // both https and http work!
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

Check out the 200 line cross platform UDP VOIP Server and Client in the [voip](voip) directory!

There are more examples in the [examples](examples) directory. Notable ones are the UDP server and the HTTPS client.

Performance
-----------

These libraries are designed to be efficient and easy to use at the same time. Benchmarks coming soon™.

#### UDP

The UDP library is just a wrapper around the native system calls, which makes it as fast as any other UDP library.

#### HTTPS

The HTTPS library is as fast as cURL, and supports many concurrent requests with almost no overhead.

Supported Platforms
-------------------

`udp.h` supports all systems with BSD sockets, it uses no Linux or Windows specific functions. `https.h` is currently a wrapper around WinHTTP, so only Windows is supported, but cURL support is coming soon.

License
-------

These libraries are all dual licenced under the MIT Licence and Public Domain. You can choose the licence that suits your project the best. The MIT Licence is a permissive licence that is short and to the point. The Public Domain licence is a licence that makes the software available to the public for free and with no copyright.

FAQ
---

> - ***There are many alternatives like cute_headers' cute_tls and cute_net. Why should I use cozyweb?***

My experiences using cURL, cute_headers and many other solutions for interfacing with the web in C was not fun, especially in casual programs and games. Most of the libraries had a ton of boilerplate and enforced a ton of restrictions even for making a simple HTTP request. I was looking for a simple solution that didn't have me distracted trying to figure out the semantics of the library and the web every time I wanted to do something simple, and coming from other languages with simple HTTPS APIs I saw much room for improvement. `cozyweb` is going to be the simplest set of C libraries you can use to interface with the web to get resources or files for your games or casual programs.

> - ***These libraries don't fit my need. What are some others?***

- [cute_headers](https://github.com/RandyGaul/cute_headers)
- [http.h](https://github.com/mattiasgustavsson/libs/blob/main/docs/http.md)
- [enet](https://github.com/lsalzman/enet)
- [SDL_net](https://github.com/libsdl-org/SDL_net)
