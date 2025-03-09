<div align="center">
  <h1>cozyweb</h1>
  <p>Single file C99 header cross-platform networking libraries.</p>
</div>

| Library | Purpose | Description | LOC | Version |
|---------|---------|-------------|-----|---------|
| **[udp.h](udp.h)** | Real-time communication | Non-blocking UDP client/server for games, VOIP, and other low-latency applications | 573 | 1.0.0 |
| **[https.h](https.h)** | Web resources | Simple HTTP/HTTPS client with one-function GET requests and asynchronous processing | 438 | 1.0.0 |


Why cozyweb?
------------

- **Minimal API surface** - Simple functions that do exactly what you need
- **Zero dependencies** - No external libraries required
- **Non-blocking by default** - Perfect for game loops and UI applications
- **Single-file implementation** - Just include and go
- **Battle-tested** - Powers real applications including a complete VOIP system


Getting Started
---------------

Include a library in your project with just two lines:

```c
#define UDP_IMPLEMENTATION  // or HTTPS_IMPLEMENTATION
#include "udp.h"            // or "https.h"
```

Or include it in a separate source file if you prefer to build it separately.


The Libraries
-------------

### 📡 udp.h

A lightweight UDP library for building real-time networked applications:

- Asynchronous, non-blocking I/O
- Simple client and server implementations
- Designed for game networking and voice applications
- Cross-platform with minimal OS-specific code

```c
// UDP client example
udp_conn* client = udp_connect(udp_resolve_host("localhost", "30000", true, &(udp_addr){}), false);
udp_send(client, "Hello!", 7);
    
// Non-blocking poll based receive - perfect for game loops
while(!udp_recv(client));

printf("Got: %.*s\n", (int)client->data_len, (char*)client->data);
```

### 🌐 https.h

A straightforward HTTP/HTTPS client that makes web requests painless:

- One function call for GET requests
- Asynchronous by default
- Minimal memory footprint
- Clean API for handling responses

```c
// Simple HTTP/HTTPS GET request
https_req* req = https_get("https://api.example.com/data");
while(req->state == HTTPS_PENDING); // Busy sleep while request resolves in another thread

// Check if complete (non-blocking)
if(req->state == HTTPS_COMPLETE) {
  printf("Response (Status: %d): %.*s\n", req->status_code, (int)req->data_len, (char*)req->data);
  https_free(req);
}
```

Real-World Examples
-------------------

- **[VOIP Application](voip)**: A complete cross-platform voice chat system in just 200 lines of code in [`voip.c`](voip/voip.c).
- **[Examples Directory](examples)**: Sample code for UDP servers and HTTP clients

Performance
-----------

These libraries prioritize efficiency alongside ease of use:

- **`udp.h`**: Direct wrapper around native socket APIs for minimal overhead
- **`https.h`**: Performance comparable to cURL with support for concurrent requests

Platform Support
----------------

- **`udp.h`**: Any system with BSD sockets (Windows, macOS, Linux, etc.)
- **`https.h`**: Currently Windows-only (WinHTTP), with cURL support coming soon

License
-------

Dual-licensed under MIT and Public Domain. Choose the license that best suits your project:

- **MIT**: Simple permissive license
- **Public Domain**: No copyright, completely free for any use

FAQ
---

### How does cozyweb compare to alternatives?

My aim was to remove all of the boilerplate and complexity that comes with interfacing with the web in C. I hated dealing with threads, learning about edge cases and library internals and having to know the HTTP/s protocol to even make a basic FETCH request. This is easy in languages like Javascript, so why not C? I couldn't find the answer to that, so I engineered a solution myself.

In short, `cozyweb` is the simplest set of web libraries you will ever come across for C. While I may not offer every possible feature, I guarantee an exceptional developer experience and top-tier performance.

### Are there alternatives?

If cozyweb doesn't meet your needs, consider:
- [cute_headers](https://github.com/RandyGaul/cute_headers)
- [http.h](https://github.com/mattiasgustavsson/libs/blob/main/docs/http.md)
- [enet](https://github.com/lsalzman/enet)
- [SDL_net](https://github.com/libsdl-org/SDL_net)


Starter Code
------------

This is provided for me and others, so anyone can easily just copy paste and start a project with **cozyweb**.

### udp.h

```c
#include <stdio.h>

#define UDP_IMPLEMENTATION
#include "udp.h"

int main() {
    udp_conn* client = udp_connect(udp_resolve_host("localhost", "30000", true, &(udp_addr){}), false);
    if(client->error) {
      printf("Error %d: %s\n", client->error, udp_error_str(client->error));
      return 1;
    }

    udp_send(client, "Hello from client!", sizeof("Hello from client!"));
    
    while(!udp_recv(client)); // Wait for a response from the server.
    printf("Received \"%.*s\"\n", (int) client->data_len, (char*) client->data);

    udp_close_n_free(client);
}
```

### https.h

```c
#include <stdio.h>

#define HTTPS_IMPLEMENTATION
#include "https.h"

int main() {
    https_req* req = https_get("https://picsum.photos/600/800"); // http works too!
    while(req->state == HTTPS_PENDING);// Sleep(20); // Wait for the request to complete.

    if(req->state != HTTPS_COMPLETE) {
        printf("Failed to get response\nStatus Code: %d\nReason: %s", req->status_code,
               req->req_failed_reason);
        https_free(req);
        return 1;
    }

    printf("Response (Status: %d): %.*s\n", req->status_code, (int)req->data_len, (char*)req->data);
    https_free(req);
}
```
