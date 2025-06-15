#include "ipc.h"


ipc_sender *setup_ipc_sender(str addr, int backlog){
	ipc_sender *is = calloc(1, sizeof(ipc_sender));
	is->addr = dup_str(addr);
	is->ssocket = socket(AF_UNIX, SOCK_STREAM, 0);
	if(is->ssocket == -1){
		log_error("%s: socket: %s", __FUNCTION__, strerror(errno));
		goto error;
	}
	struct sockaddr_un sockaddr = { .sun_family = AF_UNIX };
	memcpy(sockaddr.sun_path, is->addr.ptr, is->addr.len);
	sockaddr.sun_path[is->addr.len] = '\0';
	unlink(is->addr.ptr);
	if(bind(is->ssocket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1){
		log_error("%s: bind: %s", __FUNCTION__, strerror(errno));
		goto error;
	}
	if(listen(is->ssocket, backlog) == -1){
		log_error("%s: listen: %s", __FUNCTION__, strerror(errno));
		goto error;
	}

	if(0){
error:
		destroy_ipc_sender(&is);
	}
	return is;
}

void destroy_ipc_sender(ipc_sender **is){
	if(*is != NULL){
		close((*is)->ssocket);
		(*is)->ssocket = -1;
		unlink((*is)->addr.ptr);
		free_str(&(*is)->addr);
		free(*is);
		*is = NULL;
	}
}

ipc_listener *setup_ipc_listener(str saddr){
	ipc_listener *il = calloc(1, sizeof(ipc_listener));
	il->saddr = dup_str(saddr);
	il->csocket = socket(AF_UNIX, SOCK_STREAM, 0);
	if(il->csocket == -1){
		log_error("%s: socket: %s", __FUNCTION__, strerror(errno));
		goto error;
	}
	struct sockaddr_un socksaddr = { .sun_family = AF_UNIX };
	memcpy(socksaddr.sun_path, il->saddr.ptr, il->saddr.len);
	socksaddr.sun_path[il->saddr.len] = '\0';
	if(connect(il->csocket, (struct sockaddr *)&socksaddr, sizeof(socksaddr)) == -1){
		log_error("%s: connect: %s", __FUNCTION__, strerror(errno));
		goto error;
	}

	if(0){
error:
		destroy_ipc_listener(&il);
	}
	return il;
}

void destroy_ipc_listener(ipc_listener **il){
	if(*il != NULL){
		close((*il)->csocket);
		(*il)->csocket = -1;
		free_str(&(*il)->saddr);
		free(*il);
		*il = NULL;
	}
}

int send_ipc_message(int to, ipc_type type, str msg){
	if(send(to, &type, sizeof(uint8_t), 0) -1){
		log_error("Can't send message type to socket %d: %s", to, strerror(errno));
		return 1;
	}
	msg.len++;
	if(send(to, &msg.len, sizeof(msg.len), 0) == -1){
		log_error("Can't send message length to socket %d: %s", to, strerror(errno));
		return 1;
	}
	if(send(to, msg.ptr, msg.len, 0) == -1){
		log_error("Can't send message to socket %d: %s", to, strerror(errno));
		return 1;
	}
	send(to, "\0", 1, 0);
	char ack[3];
	if(recv(to, ack, 3, 0) == -1){
		log_error("Receiving ACK from listener");
		return 1;
	}
	if(strncmp(ack, "ACK", 3) != 0){
		log_error("Received '%.3s' from listener instead of 'ACK'", ack);
		return 1;
	}
	return 0;
}

ipc_msg receive_ipc_message(ipc_listener *il){
	ipc_msg msg = {0};
	if(recv(il->csocket, &msg.type, sizeof(uint8_t), 0) == -1){
		log_error("Can't receive message type from socket %d: %s", il->csocket, strerror(errno));
		goto end;
	}
	if(recv(il->csocket, &msg.msg.len, sizeof(msg.msg.len), 0) == -1){
		log_error("Can't receive message length from socket %d: %s", il->csocket, strerror(errno));
		goto end;
	}
	msg.msg.cap = msg.msg.len;
	msg.msg.ptr = calloc(msg.msg.len, sizeof(char));
	if(recv(il->csocket, msg.msg.ptr, msg.msg.len, 0) == -1){
		log_error("Can't receive message from socket %d: %s", il->csocket, strerror(errno));
		free_ipc_message(&msg);
		goto end;
	}
end:
	if(send(il->csocket, "ACK", slen("ACK"), 0) == -1){
		log_error("Sending 'ACK' to sender");
	}
	return msg;
}

void free_ipc_message(ipc_msg *msg){
	msg->type = NONE;
	free_str(&msg->msg);
}

