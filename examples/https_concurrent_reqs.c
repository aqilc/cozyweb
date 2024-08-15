#include <stdio.h>
// #include <windows.h>
// #include <winhttp.h>

// int main(void)
// {
//     BOOL bResults = FALSE;
//     HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

//     printf("go\n");

//     hSession = WinHttpOpen(L"abc",
//                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
//                            WINHTTP_NO_PROXY_NAME,
//                            WINHTTP_NO_PROXY_BYPASS, 0);
//     printf("hSession %08x\n", hSession);

//     if (hSession)
//         hConnect = WinHttpConnect(hSession, L"google.com",
//                                   INTERNET_DEFAULT_HTTPS_PORT, 0);
//     printf("hConnect %08x\n", hConnect);

//     if (hConnect)
//         hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/",
//                                       NULL, WINHTTP_NO_REFERER,
//                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
//                                       WINHTTP_FLAG_SECURE);
//     printf("hRequest %08x\n", hRequest);

//     if (hRequest)
//     {
//         DWORD dwFlags =
//             SECURITY_FLAG_IGNORE_UNKNOWN_CA |
//             SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
//             SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
//             SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
//         WinHttpSetOption(
//             hRequest,
//             WINHTTP_OPTION_SECURITY_FLAGS,
//             &dwFlags,
//             sizeof(dwFlags));

//         bResults = WinHttpSendRequest(hRequest,
//                                       WINHTTP_NO_ADDITIONAL_HEADERS,
//                                       0, WINHTTP_NO_REQUEST_DATA, 0,
//                                       0, 0);
//     }
//     if (bResults)
//     {
//         if (WinHttpReceiveResponse(hRequest, NULL))
//         {
//             DWORD dwDownloaded, dwSize;
//             do
//             {
//                 if (!WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize)
//                     break;
//                 char *buf = malloc(dwSize);
//                 if (!buf)
//                     break;
//                 WinHttpReadData(hRequest, (LPVOID)buf, dwSize, &dwDownloaded);
//                 fwrite(buf, sizeof(char), dwSize, stdout);
//                 free(buf);
//                 if (!dwDownloaded)
//                     break;
//             } while (dwSize > 0);
//         }
//     }
//     else
//         printf("Error %d has occurred.\n", GetLastError());

//     if (hRequest)
//         WinHttpCloseHandle(hRequest);
//     if (hConnect)
//         WinHttpCloseHandle(hConnect);
//     if (hSession)
//         WinHttpCloseHandle(hSession);

//     return 0;
// }

















// #define HTTP_IMPLEMENTATION
// #include "include/http.h"


// int main() {
//   http_t* res = http_get("http://www.google.com/", NULL);
//   if(!res) {
//     printf("Failed to create request\n");
//     return 1;
//   }

  
//   while(res->status == HTTP_STATUS_PENDING) {
//     Sleep(10);
//     http_process(res);
//   }

//   if(res->status == HTTP_STATUS_FAILED) {
//     printf("Failed to get response\nStatus Code: %d\nReason: %s", res->status_code, res->reason_phrase);
//     http_release(res);
//     return 1;
//   }

//   printf("Status: %d\n", res->status);
//   printf("Response Size: %u\n", res->response_size);
//   printf("Response: %.256s\n", (char const*) res->response_data);
//   http_release(res);
// }












#define HTTPS_IMPLEMENTATION
#include "../https.h"


int main() {
  // double start = get_precise_time();
  https_req* req = https_get("http://picsum.photos/600/800");
  https_req* req2 = https_get("https://www.bing.com/");
  https_req* req3 = https_get("https://www.yahoo.com/");
  https_req* req4 = https_get("https://you.com/");
  https_req* req5 = https_get("https://duckduckgo.com/");
  https_req* req6 = https_get("https://search.brave.com/");
  https_req* req7 = https_get("https://komo.ai/");
  https_req* req8 = https_get("https://yep.com/");
  // double opentime = get_precise_time();
  // printf("Total https_get Time: %f\n", opentime - start);
  while(req->state == HTTPS_PENDING/* || req2->state == HTTPS_PENDING || req3->state == HTTPS_PENDING || req4->state == HTTPS_PENDING ||
        req5->state == HTTPS_PENDING || req6->state == HTTPS_PENDING || req7->state == HTTPS_PENDING || req8->state == HTTPS_PENDING*/);// Sleep(20);
  // printf("End Time: %f\n", get_precise_time() - opentime);

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
