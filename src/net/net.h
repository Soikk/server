#ifndef NET_H
#define NET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
//#include <netinet/in.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>
#include <time.h>
#include "str/str.h"
#include "list/list.h"
#include "dir/dir.h"
#include "log/log.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <poll.h>
#include <fcntl.h>
#ifdef __linux__
#include <sys/sendfile.h>
#endif


enum http_method {
	GET,
	POST,
	PUT,
	DELETE
};

enum response_header {
	CONTENT_LENGTH,
	CONTENT_TYPE,
	TRANSFER_ENCODING,
};

enum mime_type {
	AVIF, BMP, CSS, CSV, GZ, GIF, HTML,
	ICO, JPG, JPEG, JS, JSON, MIDI, MP3,
	MP4, MPEG, PNG, PDF, PHP, RAR, TIFF, TS,
	TXT, WAV, WEBA, WEBM, WEBP, XML, ZIP,
	_7Z,
};


struct uri {
	struct str path;
	struct str query;
};

struct uri_mod {
	struct str pattern;
	struct uri output;
};

struct header {
	struct str name;
	struct str value;
};

#define MAX_HEADERS 16


struct http_message {
	union {
		struct str method;
		struct str resp_ver;
	};
	union {
		struct str uri;
		struct str status;
	};
	union {
		struct str req_ver;
		struct str reason;
	};
	int hlen;
	struct header headers[MAX_HEADERS];
	struct str body;
};

typedef struct http_server {
	struct str port;
	int backlog;
	int ssocket;
} http_server;

typedef ssize_t (*recv_func)(int,void*,size_t,int);
typedef int (*ssl_recv_func)(SSL*,void*,int);
typedef struct http_worker {
	int ssocket;
	int csocket;
	int secure;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	recv_func receive;
	ssl_recv_func ssl_receive;
} http_worker;

#define MAX_RESPONSE_SIZE 0x0FFFFFFF
#define MAX_BODY_SIZE (MAX_RESPONSE_SIZE - 0x0FFF)

#define insert_header(hm, h) \
	(hm).headers[(hm).hlen++] = (h)


http_server *setup_http_server(struct str port, int backlog);

void destroy_http_server(http_server **hs);

http_worker *setup_http_worker(int ssocket, int secure, struct str certfile, struct str keyfile);

void destroy_http_worker(http_worker **hw);

void reset_worker_ssl(http_worker *hw);

int accept_connection(http_worker *hw, char ip[INET_ADDRSTRLEN]);

int receive_request(http_worker *hw, struct str *request);

struct file generate_resource(struct uri resource, struct str url);

char *handlePOST(char *request);

void build_http_message(char *request, int len, struct http_message *hm);

enum http_method get_http_method(struct str method);

struct uri sanitize_uri(struct str uri);

void send_file(http_worker *hw, struct str filename);

int read_uri_rewrites(char *map, uint64_t size);

void free_uri_rewrites(void);

#endif
