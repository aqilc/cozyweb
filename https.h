/////////////////////////////////////////////////////////////////////////////////////////////
// https.h v1.0 by @aqilc                                                                  //
// Licence: MIT                                                                            //
// Part of the Cozyweb project.                                                            //
//                                                                                         //
// Initiates **asynchronous** HTTPS requests in a really easy way, aims to be cross        //
// platform but only Windows is currently implemented. Implemented on Windows without      //
// using threads.                                                                          //
//                                                                                         //
// Inspired by http.h at https://github.com/mattiasgustavsson/libs/blob/main/docs/http.md  //
//                                                                                         //
// Define HTTPS_IMPLEMENTATION to include implementation in file.                          //
// Define HTTPS_PRIVATE to make implementation private(static).                            //
// Define HTTPS_APPLICATION_NAME in impl file as string according to the name of your app. //
// Define HTTPS_SKIP_CERT_VALIDATION to disable critical security features.                //
/////////////////////////////////////////////////////////////////////////////////////////////

/**

Example:
--------

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

*/

#ifndef HTTPS_H
#define HTTPS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef HTTPS_PRIVATE
#define HTTPS_EXPORT static
#else
#define HTTPS_EXPORT 
#endif

typedef struct https_req https_req;

enum https_state {
    HTTPS_PENDING,
    HTTPS_COMPLETE,
    HTTPS_CONN_ERROR,
};
enum https_errors {
    HTTPS_ERR_CANNOT_CONNECT,
    HTTPS_ERR_CHUNKED_ENCODING_HEADER_SIZE_OVERFLOW,
    HTTPS_ERR_CLIENT_AUTH_CERT_NEEDED,
    HTTPS_ERR_CONNECTION_ERROR,
    HTTPS_ERR_HEADER_COUNT_EXCEEDED,
    HTTPS_ERR_HEADER_SIZE_OVERFLOW,
    HTTPS_ERR_INTERNAL_ERROR,
    HTTPS_ERR_INVALID_SERVER_RESPONSE,
    HTTPS_ERR_INVALID_URL,
    HTTPS_ERR_LOGIN_FAILURE,
    HTTPS_ERR_NAME_NOT_RESOLVED,
    HTTPS_ERR_OPERATION_CANCELLED,
    HTTPS_ERR_REDIRECT_FAILED,
    HTTPS_ERR_RESEND_REQUEST,
    HTTPS_ERR_RESPONSE_DRAIN_OVERFLOW,
    HTTPS_ERR_SECURE_FAILURE,
    HTTPS_ERR_TIMEOUT,
    HTTPS_ERR_UNRECOGNIZED_SCHEME,
    HTTPS_ERR_OUT_OF_MEMORY
};

enum https_status_codes {
    HTTPS_STATUS_CONTINUE = 100,
    HTTPS_STATUS_SWITCH_PROTOCOLS = 101,
    HTTPS_STATUS_OK = 200,
    HTTPS_STATUS_CREATED = 201,
    HTTPS_STATUS_ACCEPTED = 202,
    HTTPS_STATUS_PARTIAL = 203,
    HTTPS_STATUS_NO_CONTENT = 204,
    HTTPS_STATUS_RESET_CONTENT = 205,
    HTTPS_STATUS_PARTIAL_CONTENT = 206,
    HTTPS_STATUS_WEBDAV_MULTI_STATUS = 207,
    HTTPS_STATUS_AMBIGUOUS = 300,
    HTTPS_STATUS_MOVED = 301,
    HTTPS_STATUS_REDIRECT = 302,
    HTTPS_STATUS_REDIRECT_METHOD = 303,
    HTTPS_STATUS_NOT_MODIFIED = 304,
    HTTPS_STATUS_USE_PROXY = 305,
    HTTPS_STATUS_REDIRECT_KEEP_VERB = 307,
    HTTPS_STATUS_BAD_REQUEST = 400,
    HTTPS_STATUS_DENIED = 401,
    HTTPS_STATUS_PAYMENT_REQ = 402,
    HTTPS_STATUS_FORBIDDEN = 403,
    HTTPS_STATUS_NOT_FOUND = 404,
    HTTPS_STATUS_BAD_METHOD = 405,
    HTTPS_STATUS_NONE_ACCEPTABLE = 406,
    HTTPS_STATUS_PROXY_AUTH_REQ = 407,
    HTTPS_STATUS_REQUEST_TIMEOUT = 408,
    HTTPS_STATUS_CONFLICT = 409,
    HTTPS_STATUS_GONE = 410,
    HTTPS_STATUS_LENGTH_REQUIRED = 411,
    HTTPS_STATUS_PRECOND_FAILED = 412,
    HTTPS_STATUS_REQUEST_TOO_LARGE = 413,
    HTTPS_STATUS_URI_TOO_LONG = 414,
    HTTPS_STATUS_UNSUPPORTED_MEDIA = 415,
    HTTPS_STATUS_RETRY_WITH = 449,
    HTTPS_STATUS_SERVER_ERROR = 500,
    HTTPS_STATUS_NOT_SUPPORTED = 501,
    HTTPS_STATUS_BAD_GATEWAY = 502,
    HTTPS_STATUS_SERVICE_UNAVAIL = 503,
    HTTPS_STATUS_GATEWAY_TIMEOUT = 504,
    HTTPS_STATUS_VERSION_NOT_SUP = 505,
};

struct https_req {
    const char* content_type;
    const char* headers;
    const char* req_failed_reason;

    // Guaranteed to be NULL terminated, for easy printing of strings.
    void* data;
    uint32_t data_len;
    uint32_t status_code;
    enum https_state state;
    enum https_errors error;
};


HTTPS_EXPORT https_req* https_get(const char* url);
HTTPS_EXPORT https_req* https_post(const char* url, const char* data, uint32_t data_len);
HTTPS_EXPORT void https_set_header(https_req* req, const char* header);
HTTPS_EXPORT void https_free(https_req* req);
HTTPS_EXPORT char const* https_error_string(enum https_errors error);

#endif

// #define HTTPS_IMPLEMENTATION
#ifdef HTTPS_IMPLEMENTATION

// References:
// https://github.com/kimtg/WinHttpExample/blob/master/WinHttpExample.cpp
// https://learn.microsoft.com/en-us/archive/msdn-magazine/2008/august/windows-with-c-asynchronous-winhttp
// https://gist.github.com/whoshuu/2dc858b8730079602044 // easy curl req example

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
// #pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "kernel32.lib")
#else
#error "Unsupported platform"
#endif

#ifndef HTTPS_APPLICATION_NAME
#define HTTPS_APPLICATION_NAME "httpsh/1.1"
#endif

#define HTTPS_MIN_DATA_BUF_SIZE 1024
#define HTTPS_CONCAT2(a, b) a##b
#define HTTPS_CONCAT(a, b) HTTPS_CONCAT2(a, b)

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

// #define HTTPS_USER_AGENT "https.h v1.0"

struct https_internal {
    https_req req;
    const char* url;
    bool tls;
    bool default_port;
    HINTERNET hConnect;
    HINTERNET hRequest;
    WCHAR hostname[256];
    WCHAR path[256];
    char port[8];
};


static inline enum https_errors https_winhttp_to_https_errors(DWORD winhttp_error) {
    switch(winhttp_error) {
    case ERROR_WINHTTP_CANNOT_CONNECT:                        return HTTPS_ERR_CANNOT_CONNECT;
    case ERROR_WINHTTP_CHUNKED_ENCODING_HEADER_SIZE_OVERFLOW: return HTTPS_ERR_CHUNKED_ENCODING_HEADER_SIZE_OVERFLOW;
    case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED:               return HTTPS_ERR_CLIENT_AUTH_CERT_NEEDED;
    case ERROR_WINHTTP_CONNECTION_ERROR:                      return HTTPS_ERR_CONNECTION_ERROR;
    case ERROR_WINHTTP_HEADER_COUNT_EXCEEDED:                 return HTTPS_ERR_HEADER_COUNT_EXCEEDED;
    case ERROR_WINHTTP_HEADER_SIZE_OVERFLOW:                  return HTTPS_ERR_HEADER_SIZE_OVERFLOW;
    case ERROR_WINHTTP_INCORRECT_HANDLE_STATE:                return HTTPS_ERR_INTERNAL_ERROR;
    case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE:                 return HTTPS_ERR_INTERNAL_ERROR;
    case ERROR_WINHTTP_INTERNAL_ERROR:                        return HTTPS_ERR_INTERNAL_ERROR;
    case ERROR_WINHTTP_INVALID_SERVER_RESPONSE:               return HTTPS_ERR_INVALID_SERVER_RESPONSE;
    case ERROR_WINHTTP_INVALID_URL:                           return HTTPS_ERR_INVALID_URL;
    case ERROR_WINHTTP_LOGIN_FAILURE:                         return HTTPS_ERR_LOGIN_FAILURE;
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:                     return HTTPS_ERR_NAME_NOT_RESOLVED;
    case ERROR_WINHTTP_OPERATION_CANCELLED:                   return HTTPS_ERR_OPERATION_CANCELLED;
    case ERROR_WINHTTP_REDIRECT_FAILED:                       return HTTPS_ERR_REDIRECT_FAILED;
    case ERROR_WINHTTP_RESEND_REQUEST:                        return HTTPS_ERR_RESEND_REQUEST;
    case ERROR_WINHTTP_RESPONSE_DRAIN_OVERFLOW:               return HTTPS_ERR_RESPONSE_DRAIN_OVERFLOW;
    case ERROR_WINHTTP_SECURE_FAILURE:                        return HTTPS_ERR_SECURE_FAILURE;
    case ERROR_WINHTTP_TIMEOUT:                               return HTTPS_ERR_TIMEOUT;
    case ERROR_WINHTTP_UNRECOGNIZED_SCHEME:                   return HTTPS_ERR_UNRECOGNIZED_SCHEME;
    case ERROR_NOT_ENOUGH_MEMORY:                             return HTTPS_ERR_OUT_OF_MEMORY;
    default:                                                  return HTTPS_ERR_INTERNAL_ERROR;
    }
}

HTTPS_EXPORT char const* https_error_string(enum https_errors error) {
    switch(error) {
    case HTTPS_ERR_CANNOT_CONNECT:                        return "Cannot connect";
    case HTTPS_ERR_CHUNKED_ENCODING_HEADER_SIZE_OVERFLOW: return "Chunked encoding header size overflow";
    case HTTPS_ERR_CLIENT_AUTH_CERT_NEEDED:               return "Client auth cert needed";
    case HTTPS_ERR_CONNECTION_ERROR:                      return "Connection error";
    case HTTPS_ERR_HEADER_COUNT_EXCEEDED:                 return "Header count exceeded";
    case HTTPS_ERR_HEADER_SIZE_OVERFLOW:                  return "Header size overflow";
    case HTTPS_ERR_INTERNAL_ERROR:                        return "Internal error";
    case HTTPS_ERR_INVALID_SERVER_RESPONSE:               return "Invalid server response";
    case HTTPS_ERR_INVALID_URL:                           return "Invalid URL";
    case HTTPS_ERR_LOGIN_FAILURE:                         return "Login failure";
    case HTTPS_ERR_NAME_NOT_RESOLVED:                     return "Name not resolved";
    case HTTPS_ERR_OPERATION_CANCELLED:                   return "Operation cancelled";
    case HTTPS_ERR_REDIRECT_FAILED:                       return "Redirect failed";
    case HTTPS_ERR_RESEND_REQUEST:                        return "Resend request";
    case HTTPS_ERR_RESPONSE_DRAIN_OVERFLOW:               return "Response drain overflow";
    case HTTPS_ERR_SECURE_FAILURE:                        return "Secure failure";
    case HTTPS_ERR_TIMEOUT:                               return "Timeout";
    case HTTPS_ERR_UNRECOGNIZED_SCHEME:                   return "Unrecognized scheme";
    case HTTPS_ERR_OUT_OF_MEMORY:                         return "Out of memory";
    default:                                              return "Unknown error";
    }
}



// static inline double get_precise_time() {
// 	LARGE_INTEGER t, f;
// 	QueryPerformanceCounter(&t);
// 	QueryPerformanceFrequency(&f);
// 	return (double)t.QuadPart/(double)f.QuadPart;
// }

static bool https_parse_url(struct https_internal* st) {
    const uint32_t len = strlen(st->url);
    const char* protocol_end = strstr(st->url, "://");
    if(!protocol_end || protocol_end - st->url < 4) return false;

    // Only supports https and http
    if(!strncmp(st->url, "https", 5)) st->tls = true;
    else if(!strncmp(st->url, "http", 4)) st->tls = false;
    else return false;

    // Look for / and : before that
    protocol_end += 3;
    const char* hostname_end = strchr(protocol_end, '/');
    const char* port_end = strchr(protocol_end, ':');
    if(!hostname_end) {
        if(port_end) {
            mbstowcs(st->hostname, protocol_end, port_end - protocol_end - 1);
            st->hostname[port_end - protocol_end - 1] = '\0';
            strcpy(st->port, port_end + 1);
        } else {
            mbstowcs(st->hostname, protocol_end, len - (protocol_end - st->url) - 1);
            st->default_port = true;
            st->port[0] = '\0';
        }
        mbstowcs(st->path, "/", 1);
        return true;
    }

    if(port_end && port_end < hostname_end) {
        mbstowcs(st->hostname, protocol_end, port_end - protocol_end - 1);
        st->hostname[port_end - protocol_end - 1] = '\0';
        strncpy(st->port, port_end + 1, hostname_end - port_end - 1);
        st->port[hostname_end - port_end - 1] = '\0';
    } else {
        mbstowcs(st->hostname, protocol_end, hostname_end - protocol_end);
        st->hostname[hostname_end - protocol_end] = '\0';
        st->default_port = true;
        st->port[0] = '\0';
    }

    const uint32_t path_len = min(len - (hostname_end - st->url), sizeof(st->path) / sizeof(st->path[0]) - 1);
    mbstowcs(st->path, hostname_end, path_len);
    st->path[path_len] = '\0';
    return true;
}

static struct https_internal* https_new(const char* url) {
    struct https_internal* st = malloc(sizeof(struct https_internal));
    st->url = url;
    st->req.data = malloc(HTTPS_MIN_DATA_BUF_SIZE);
    st->req.data_len = 0;
    st->req.status_code = 0;
    return st;
}

static void https_finish_res(struct https_internal* st) {
    st->req.state = HTTPS_COMPLETE;
    ((char*) st->req.data)[st->req.data_len] = '\0';
    WinHttpCloseHandle(st->hRequest);
    WinHttpCloseHandle(st->hConnect);
    // printf("finished, read %d data\n", st->req.data_len);
}

static void https_req_error(struct https_internal* st, enum https_errors error) {
    st->req.state = HTTPS_CONN_ERROR;
    if(!error) st->req.error = https_winhttp_to_https_errors(GetLastError());
    else       st->req.error = error;
    st->req.req_failed_reason = https_error_string(st->req.error);
    st->req.data_len = 0;
    WinHttpCloseHandle(st->hRequest);
    WinHttpCloseHandle(st->hConnect);
}

__stdcall static void https_winhttp_req_cb(HINTERNET hInternet, DWORD_PTR ctx, DWORD code, LPVOID info, DWORD length) {
    struct https_internal* st = (struct https_internal*)ctx;
    switch(code) {
    case WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE:
        WinHttpReceiveResponse(hInternet, NULL);
        break;
    case WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE:;
        DWORD size;
        WinHttpQueryHeaders(st->hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                            &st->req.status_code, &size, WINHTTP_NO_HEADER_INDEX);
        WinHttpQueryDataAvailable(st->hRequest, NULL);
        break;
    case WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE:;
        DWORD data_len = *((LPDWORD) info);
        if(!data_len) return https_finish_res(st);
        if(st->req.data_len + data_len > HTTPS_MIN_DATA_BUF_SIZE - 1 && !(st->req.data = realloc(st->req.data, st->req.data_len + data_len + 1)))
            https_req_error(st, HTTPS_ERR_OUT_OF_MEMORY);
        WinHttpReadData(st->hRequest, (LPVOID)(st->req.data + st->req.data_len), data_len, NULL);
        break;
    case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
        st->req.data_len += length;
        WinHttpQueryDataAvailable(st->hRequest, NULL);
        break;
    case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR: https_req_error(st, 0); break;
    default: break;
    }
}

// https://github.com/pierrecoll/winhttpasyncdemo/blob/master/AsyncDemo.cpp
static bool https_request(struct https_internal* st, LPWSTR type) {
    static HINTERNET hSession = NULL;
    if(!hSession) {
        hSession = WinHttpOpen(HTTPS_CONCAT(L, HTTPS_APPLICATION_NAME), WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
        if(!hSession) return false;
        if(WinHttpSetStatusCallback(hSession, (WINHTTP_STATUS_CALLBACK) https_winhttp_req_cb,
                                    WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS, 0) == WINHTTP_INVALID_STATUS_CALLBACK)
            return false;
    }

    st->hConnect = WinHttpConnect(hSession, st->hostname, st->default_port ? INTERNET_DEFAULT_PORT : atoi(st->port), 0);
    if(!st->hConnect) return false;

    st->hRequest = WinHttpOpenRequest(st->hConnect, type, st->path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     (st->tls ? WINHTTP_FLAG_SECURE : 0));
    if(!st->hRequest) { WinHttpCloseHandle(st->hConnect); return false; }

#ifdef HTTPS_SKIP_CERT_VALIDATION
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(st->hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
#endif
    return true;
}

HTTPS_EXPORT https_req* https_get(const char* url) {
    struct https_internal* st = https_new(url);
    if(!https_parse_url(st) && (st->req.error = HTTPS_ERR_INVALID_URL)) goto fail;
    puts(url);
    if(!https_request(st, L"GET") && (st->req.error = https_winhttp_to_https_errors(GetLastError()))) goto fail;
    if(!WinHttpSendRequest(st->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, (DWORD_PTR) st)) {
        WinHttpCloseHandle(st->hRequest);
        WinHttpCloseHandle(st->hConnect);
        st->req.error = https_winhttp_to_https_errors(GetLastError());
        goto fail;
    }
    st->req.state = HTTPS_PENDING;
    return &st->req;
fail:
    st->req.state = HTTPS_CONN_ERROR;
    st->req.req_failed_reason = https_error_string(st->req.error);
    return &st->req;
}

HTTPS_EXPORT https_req* https_post(const char* url, const char* data, uint32_t data_len) {
    struct https_internal* st = https_new(url);
    if(!https_parse_url(st) && (st->req.error = HTTPS_ERR_INVALID_URL)) goto fail;
    if(!https_request(st, L"POST") && (st->req.error = https_winhttp_to_https_errors(GetLastError()))) goto fail;
    if(!WinHttpSendRequest(st->hRequest, L"Content-Type: application/x-www-form-urlencoded", -1, (LPVOID)data, data_len, data_len, (DWORD_PTR) st)) {
        WinHttpCloseHandle(st->hRequest);
        WinHttpCloseHandle(st->hConnect);
        st->req.error = https_winhttp_to_https_errors(GetLastError());
        goto fail;
    }
    st->req.state = HTTPS_PENDING;
    return &st->req;
fail:
    st->req.state = HTTPS_CONN_ERROR;
    st->req.req_failed_reason = https_error_string(st->req.error);
    return &st->req;
}

// void https_set_header(https_req* req, const char* header) {
//     struct https_internal* st = (struct https_internal*)req;
//     WinHttpAddRequestHeaders(st->hRequest, header, -1, WINHTTP_ADDREQ_FLAG_ADD);
// }

HTTPS_EXPORT void https_free(https_req* req) {
    struct https_internal* st = (struct https_internal*)req;
    free(st->req.data);
    free(st);
}


#endif
