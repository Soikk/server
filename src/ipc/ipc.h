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
	struct str addr;
	int ssocket;
} ipc_sender;

typedef struct ipc_listener {
	struct str saddr;
	int csocket;
} ipc_listener;

#define MAX_IPC_MSG_LEN 1024
typedef struct ipc_message {
	struct str key;
	struct str val;
} ipc_message;

ipc_sender *setup_ipc_sender(struct str addr, int backlog);
void destroy_ipc_sender(ipc_sender **is);

ipc_listener *setup_ipc_listener(struct str saddr);
void destroy_ipc_listener(ipc_listener **il);

void free_ipc_message(ipc_message im);
int send_ipc_message(int to, ipc_message msg);
ipc_message receive_ipc_message(ipc_listener *il);

#endif
