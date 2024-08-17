/**

No dependencies VOIP client! Compile with:
  gcc net/voip/voip.c -o voip -lm
  clang-cl /MDd /Z7 /EHsc /Fo"./bin/" net/voip/voip.c

Usage:
  There's a "server" and a "client". You can run the server with `voip` and the client with `voip <server_ip>`.
  The server should be run before the client although it doesn't matter, and the clients immediately start recording when ran.

*/

#include <stdio.h>

#define UDP_IMPLEMENTATION
#include "../udp.h"

// #define MA_DEBUG_OUTPUT
#define MA_NO_GENERATION
#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio.h"

#include "util.c"

// Windows smh
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef _WIN32
#define Sleep sleep
#endif

struct voice_packet {
  uint16_t id; // Session ID for client, Voice ID for Server
  uint16_t len;
  uint32_t seq;
  uint8_t data[];
};

struct voice {
  uint16_t id;
  uint16_t session_id;
  uint32_t packet_seq;
  uint16_t packet_len;
  uint16_t packet_played_len;
  uint32_t packet_allocated;
  char* packet_data;
  union {
    udp_addr* addr;
    ma_mutex writing_packet;
  };
}* voices = NULL;
int voices_len = 0;
uint16_t session_id;

void capture_callback(ma_device* pDevice, void* pOutput, const void* pInput, ma_uint32 frameCount) {
  static uint32_t seq = 0;
  int data_len = frameCount * 2; // 2 bytes per sample
  
  struct voice_packet* pack = alloca(sizeof(struct voice_packet) + data_len);
  pack->id = session_id;
  pack->len = data_len;
  pack->seq = ++seq;
  memcpy(pack->data, pInput, data_len);

  udp_send((udp_conn*)pDevice->pUserData, (void*)pack, data_len + sizeof(struct voice_packet));
}

void playback_callback(ma_device* pDevice, void* pOutput, const void* pInput, ma_uint32 frameCount) {
  
  // Mix all voices
  for(int i = 0; i < voices_len; i++) {
    struct voice* voice = voices + i;

    if(voice->packet_played_len < voice->packet_len) {
      ma_mutex_lock(&voice->writing_packet);
      int len = min(voice->packet_len - voice->packet_played_len, frameCount * sizeof(short)) / sizeof(short);

      for(int j = 0; j < len; j ++)
        ((short*) pOutput)[j] = (short) min(max((int) ((short*) pOutput)[j] + (int) ((short*) ((char*)voice->packet_data + voice->packet_played_len))[j], -32768), 32767);
      
      voice->packet_played_len += len * sizeof(short);
      ma_mutex_unlock(&voice->writing_packet);
    }
  }
}

struct voice* push_voice_serv(udp_addr* addr, uint16_t session_id) {
  voices = realloc(voices, sizeof(struct voice) * (++voices_len));
  voices[voices_len - 1] = (struct voice) {
    .addr = memcpy(malloc(sizeof(udp_addr)), addr, sizeof(udp_addr)),
    .id = voices_len, .session_id = session_id
  };
  printf("Client #%d(@%d) connected from %s.\n", voices_len, session_id, udp_addr_str(addr, (char[150]) {}, 150));
  return voices + voices_len - 1;
}

struct voice* push_voice_cli(int id) {
  voices = realloc(voices, sizeof(struct voice) * (++voices_len));
  voices[voices_len - 1] = (struct voice) { .id = id, .packet_data = malloc(1024), .packet_allocated = 1024 };
  ma_mutex_init(&voices[voices_len - 1].writing_packet);
  printf("Peer with ID %d connected.\n", id);
  return voices + voices_len - 1;
}

int main(const int argc, const char** argv) {
  bool is_server = argc == 1;
  ma_device capture_device;
  ma_device playback_device;
  
  udp_conn* conn = is_server ? udp_serve(30000) : udp_connect(udp_resolve_host(argv[1], "30000", true, &(udp_addr) {}), false);
  if(conn->error) {
    printf("Error establishing a connection: %s\n", udp_error_str(conn->error));
    return 1;
  }


  if(!is_server) {
    printf("Connected to %s.\n", udp_addr_str(&conn->from, (char[150]) {}, 150));
    srand(time(NULL));
    session_id = rand();
    
    ma_device_config conf_capture    = ma_device_config_init(ma_device_type_capture);
    ma_device_config conf_playback   = ma_device_config_init(ma_device_type_playback);
    conf_playback.playback.format    = conf_capture.capture.format     = ma_format_s16;
    conf_playback.playback.channels  = conf_capture.capture.channels   = 1;
    conf_playback.sampleRate         = conf_capture.sampleRate         = 48000;
    conf_playback.periodSizeInFrames = conf_capture.periodSizeInFrames = 512;
    conf_capture.dataCallback        = capture_callback;
    conf_capture.pUserData           = conn;
    conf_playback.dataCallback       = playback_callback;
    conf_playback.pUserData          = NULL;

    if(ma_device_init(NULL, &conf_capture, &capture_device) || ma_device_init(NULL, &conf_playback, &playback_device) ||
       ma_device_start(&capture_device) || ma_device_start(&playback_device)) {
      printf("Failed to connect to capture and/or playback devices.\n");
      return 1;
    }
  } else printf("Listening to %s.\n", udp_addr_str(&conn->from, (char[150]) {}, 150));
  
  puts("Press enter to quit.");
  voices = calloc(1, sizeof(struct voice));

  while(true) {
    while(!(is_server ? udp_recv_from : udp_recv)(conn))
      if(conn->error || (_kbhit() && getchar())) goto done; // Lets you quit by pressing enter
    
    struct voice_packet* packet = (struct voice_packet*) conn->data;    
    struct voice* voice = NULL;
    
    if(is_server) {
      for(int i = 0; i < voices_len; i++) {
        if(udp_addr_same(voices[i].addr, &conn->from)) {
          voice = voices + i;

          // Reset the session if the client is reconnecting
          if(packet->id != voice->session_id) {
            voice->session_id = packet->id;
            voice->packet_seq = 0;
            printf("Client #%d reconnected.\n", voice->id);
          }
          break;
        }
      }

      if(!voice) voice = push_voice_serv(&conn->from, packet->id);
      if(packet->seq <= voice->packet_seq) continue;

      packet->id = voice->id;
      for(int i = 0; i < voices_len; i++) // Broadcast packet
        if(voice->id != voices[i].id) udp_send_to(conn, voices[i].addr, conn->data, conn->data_len);
      
    } else {
      for(int i = 0; i < voices_len; i++)
        if(voices[i].id == packet->id) { voice = voices + i; break; }
 
      if(!voice) voice = push_voice_cli(packet->id);
      if(packet->seq <= voice->packet_seq) continue;

      ma_mutex_lock(&voice->writing_packet);
      
      // If there was unplayed audio, move it to the beginning of the buffer so it can still be played
      uint32_t buf_start = 0;
      if(voice->packet_played_len < voice->packet_len) {
        buf_start = min(voice->packet_len - voice->packet_played_len, 20480); // Limit the buffer size to ~20KB

        if(voice->packet_played_len > 0) // Don't need to move anything if there was nothing played lol
          memmove(voice->packet_data, voice->packet_data + voice->packet_played_len, buf_start);
      }
      
      voice->packet_len = packet->len + buf_start;
      voice->packet_played_len = 0;
      if(voice->packet_allocated < voice->packet_len) {
        voice->packet_allocated = voice->packet_len;
        voice->packet_data = realloc(voice->packet_data, voice->packet_len);
      }
      memcpy(voice->packet_data + buf_start, packet->data, packet->len);
      ma_mutex_unlock(&voice->writing_packet);
    }

    voice->packet_seq = packet->seq;
  }

done:
  if(conn->error) printf("Error: %s\n", udp_error_str(conn->error));
  if(!is_server) {
    ma_device_uninit(&capture_device);
    ma_device_uninit(&playback_device);
  }
  udp_close_n_free(conn);
  return 0;
}
