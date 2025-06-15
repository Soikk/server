#ifndef IPC_H
#define IPC_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "str/str.h"
#include "log/log.h"
#include "types/types.h"


typedef struct ipc_sender {
	str addr;
	int ssocket;
} ipc_sender;

typedef struct ipc_listener {
	str saddr;
	int csocket;
} ipc_listener;

typedef enum ipc_type {
	NONE,
	SOCKET,
	REWRITES, // do away with this?
	BUNDLE, CERT, KEY,
	RESTART,
	RELOAD,
	HTTP,
	HTTPS,
	LOG,
	UNLOG,
} ipc_type;

#define MAX_IPC_MSG_LEN 1024
typedef struct ipc_msg {
	ipc_type type;
	str msg;
} ipc_msg;

ipc_sender *setup_ipc_sender(str addr, int backlog);
void destroy_ipc_sender(ipc_sender **is);

ipc_listener *setup_ipc_listener(str saddr);
void destroy_ipc_listener(ipc_listener **il);

int send_ipc_message(int to, ipc_type type, str msg);
ipc_msg receive_ipc_message(ipc_listener *il);
void free_ipc_message(ipc_msg *im);

#endif
