#include "ipc.h"


ipc_sender *setup_ipc_sender(struct str addr, int backlog){
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

ipc_listener *setup_ipc_listener(struct str saddr){
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

void free_ipc_message(ipc_message im){
	free_str(&im.key);
	free_str(&im.val);
}

static inline struct str ipc_message_to_str(ipc_message msg){
	struct str smsg = nstr(msg.key.len + msg.val.len + 2*sizeof(u32));
	memcpy(smsg.ptr+smsg.len, &msg.key.len, sizeof(msg.key.len));
	smsg.len += sizeof(msg.key.len);
	copy_str(smsg, msg.key);
	memcpy(smsg.ptr+smsg.len, &msg.val.len, sizeof(msg.val.len));
	smsg.len += sizeof(msg.val.len);
	copy_str(smsg, msg.val);
	return smsg;
}

int send_ipc_message(int to, ipc_message msg){
	struct str smsg = ipc_message_to_str(msg);
	if(send(to, smsg.ptr, smsg.len, 0) == -1){
		log_error("cant send message to socket %d: %s", to, strerror(errno));
		free_str(&smsg);
		return 1;
	}
	free_str(&smsg);
	char buf[2];
	if(recv(to, buf, 2, 0) == -1){
		log_error("receiving OK from listener");
		return 1;
	}
	if(strncmp(buf, "OK", 2) != 0){
		log_error("received '%s' from listener instead of 'OK'", buf);
		return 1;
	}
	return 0;
}

static inline ipc_message str_to_ipc_message(struct str smsg){
	struct ipc_message msg;
	u32 l;
	memcpy(&l, smsg.ptr, sizeof(l));
	smsg.ptr += sizeof(l);
	msg.key = nstr(l);
	msg.key.len = l;
	memcpy(msg.key.ptr, smsg.ptr, l);
	smsg.ptr += l;
	memcpy(&l, smsg.ptr, sizeof(l));
	smsg.ptr += sizeof(l);
	msg.val = nstr(l);
	msg.val.len = l;
	memcpy(msg.val.ptr, smsg.ptr, l);
	return msg;
}

ipc_message receive_ipc_message(ipc_listener *il){
	struct str smsg = nstr(MAX_IPC_MSG_LEN); // we are gonna have to poll btw
	ipc_message msg = {0};
	smsg.len = recv(il->csocket, smsg.ptr, smsg.cap, 0);
	if(smsg.len == -1){
		log_error("cant receive message from socket %d: %s", il->csocket, strerror(errno));
	}else{
		msg = str_to_ipc_message(smsg);
	}
	if(send(il->csocket, "OK", slen("OK"), 0) == -1){
		log_error("sending 'OK' to sender");
	}
	return msg;
}

