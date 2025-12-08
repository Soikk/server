#include "net.h"


enum header_enum {
	CONTENT_LENGTH,
	CONTENT_TYPE,
	TRANSFER_ENCODING
};
str response_headers[] = {
	sstr("Content-Length"),
	sstr("Content-Type"),
	sstr("Transfer-Encoding"),
};

static int pleasesslgivemetheerror(int ssl_get_error){
	char *error;
	switch(ssl_get_error){
		case SSL_ERROR_NONE: error = "SSL_ERROR_NONE"; break;
		case SSL_ERROR_ZERO_RETURN: error = "SSL_ERROR_ZERO_RETURN"; break;
		case SSL_ERROR_WANT_READ: error = "SSL_ERROR_WANT_READ"; break;
		case SSL_ERROR_WANT_WRITE: error = "SSL_ERROR_WANT_WRITE"; break;
		case SSL_ERROR_WANT_CONNECT: error = "SSL_ERROR_WANT_CONNECT"; break;
		case SSL_ERROR_WANT_ACCEPT: error = "SSL_ERROR_WANT_ACCEPT"; break;
		case SSL_ERROR_WANT_X509_LOOKUP: error = "SSL_ERROR_WANT_X509_LOOKUP"; break;
		case SSL_ERROR_WANT_ASYNC: error = "SSL_ERROR_WANT_ASYNC"; break;
		case SSL_ERROR_WANT_ASYNC_JOB: error = "SSL_ERROR_WANT_ASYNC_JOB"; break;
		case SSL_ERROR_WANT_CLIENT_HELLO_CB: error = "SSL_ERROR_WANT_CLIENT_HELLO_CB"; break;
		case SSL_ERROR_SYSCALL: error = "SSL_ERROR_SYSCALL"; break;
		case SSL_ERROR_SSL: error = "SSL_ERROR_SSL"; break;
	}
	int err = ERR_get_error();
	log_error("%s (%d): %s", error, err, ERR_error_string(err, NULL));
	return ssl_get_error;
}

http_server *setup_http_server(str port, int backlog){
	http_server *hs = calloc(1, sizeof(http_server));
	hs->port = dup_str(port);
	hs->backlog = backlog;
	hs->ssocket = -1;
	hs->csocket = -1;

	int ec, val = 1;
	struct addrinfo *res, hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_flags = AI_PASSIVE };

	if((ec = getaddrinfo(NULL, hs->port.ptr, &hints, &res)) != 0){
		log_error("getaddrinfo: %s", gai_strerror(ec));
		goto error;
	}
	if((hs->ssocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1){
		log_error("socket: %s", strerror(errno));
		goto error;
	}

	if(setsockopt(hs->ssocket, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val))){
		log_error("server: SO_REUSEPORT: %s", strerror(errno));
		goto error;
	}
	
	if(bind(hs->ssocket, res->ai_addr, res->ai_addrlen) == -1){
		log_error("server: bind: %s", strerror(errno));
		goto error;
	}
	
	if(listen(hs->ssocket, backlog) == -1){
		log_error("server: listen: %s", strerror(errno));
		goto error;
	}

	if(0){
error:
		destroy_http_server(&hs);
	}
	freeaddrinfo(res);

	return hs;
}

void destroy_http_server(http_server **hs){
	if(*hs != NULL){
		free_str(&(*hs)->port);
		(*hs)->backlog = 0;
		close((*hs)->ssocket);
		(*hs)->ssocket = -1;
		close((*hs)->csocket);
		(*hs)->csocket = -1;
		free(*hs);
		*hs = NULL;
	}
}

int setup_https(http_server *hs, str certfile, str keyfile){
	if(certfile.len == 0){
		log_error("Missing certificate file");
		return 1;
	}
	if(keyfile.len == 0){
		log_error("Missing private key file");
		return 1;
	}

	if(hs->ssl != NULL){
		SSL_free(hs->ssl);
	}
	if(hs->ssl_ctx != NULL){
		SSL_CTX_free(hs->ssl_ctx);
	}

	hs->ssl_ctx = SSL_CTX_new(TLS_server_method());
	// need to compile openssl with ktls on for this (v) to work
	SSL_CTX_set_options(hs->ssl_ctx, SSL_OP_ENABLE_KTLS | SSL_OP_IGNORE_UNEXPECTED_EOF);
	if(hs->ssl_ctx == NULL){
		return 1;
	}
	//SSL_CTX_set_verify(hs->ssl_ctx, SSL_VERIFY_PEER, NULL);
	/*if(SSL_CTX_load_verify_locations(hs->ssl_ctx, "ssl/mkarchive.net/ca_bundle.crt", NULL) <= 0){
		log_error("Verifying certificate locations");
		return 1;
	}*/
	if(SSL_CTX_use_certificate_file(hs->ssl_ctx, certfile.ptr, SSL_FILETYPE_PEM) <= 0){
		log_error("Error while trying to set up certificate file");
		return 1;
	}
	if(SSL_CTX_use_PrivateKey_file(hs->ssl_ctx, keyfile.ptr, SSL_FILETYPE_PEM) <= 0 ){
		log_error("Error while trying to set up key file");
		return 1;
	}
	hs->ssl = SSL_new(hs->ssl_ctx);
	if(hs->ssl == NULL){
		log_error("Creating SSL*");
		return 1;
	}
	SSL_set_accept_state(hs->ssl);
	hs->secure = 1;

	return 0;
}

void reset_https(http_server *hs){
	if(hs != NULL){
		close(hs->csocket);
		if(hs->ssl != NULL){
			SSL_free(hs->ssl);
		}
		hs->ssl = SSL_new(hs->ssl_ctx);
		SSL_set_accept_state(hs->ssl);
	}
}

void terminate_https(http_server *hs){
	if(hs != NULL){
		hs->secure = 0;
		if(hs->ssl != NULL){
			SSL_free(hs->ssl);
			hs->ssl = NULL;
		}
		if(hs->ssl_ctx != NULL){
			SSL_CTX_free(hs->ssl_ctx);
			hs->ssl_ctx = NULL;
		}
	}
}

int accept_connection(http_server *hs, char ip[INET_ADDRSTRLEN]){
	struct sockaddr_storage caddr;
	int casize = sizeof(caddr);
	log_info("Waiting...");
	if((hs->csocket = accept(hs->ssocket, (struct sockaddr *)&caddr, (socklen_t*)&casize)) == -1){
		log_error("Couldnt't accept connection: %s", strerror(errno));
		return -1;
	}
	inet_ntop(caddr.ss_family, &(((struct sockaddr_in*)&caddr)->sin_addr), ip, INET_ADDRSTRLEN);
	log_info("accepted");
	if(hs->secure){
		int err = 0;
		if((err = SSL_set_fd(hs->ssl, hs->csocket)) != 1){
			log_error("Error setting SSL's fd %d", hs->csocket);
			return pleasesslgivemetheerror(SSL_get_error(hs->ssl, err));
		}
		if((err = SSL_accept(hs->ssl)) != 1){
			log_error("SSL couldnt accept");
			return pleasesslgivemetheerror(SSL_get_error(hs->ssl, err));
		}
	}
	return 0;
}

static inline int server_read(http_server *hs, str *buf){
	return hs->secure ?
		SSL_read(hs->ssl, buf->ptr+buf->len, buf->cap-buf->len) :
		recv(hs->csocket, buf->ptr+buf->len, buf->cap-buf->len, 0);
}

int receive_request(http_server *hs, str *request){
	// SSL_has_pending can return 0 if you havent read any bytes yet (https://stackoverflow.com/questions/6616976/why-does-this-ssl-pending-call-always-return-zero)
	struct pollfd pfd[1] = { {.fd = hs->csocket, .events = POLLIN } };
	while(poll(pfd, 1, 100)){
		if(pfd[0].revents & POLLIN){
			int rb = 0;
			if(hs->secure){
				if(SSL_has_pending(hs->ssl)){
					rb = server_read(hs, request);
					if(rb == 0){
						return pleasesslgivemetheerror(SSL_get_error(hs->ssl, rb));
					}
				}
			}else{
				rb = server_read(hs, request);
				if(rb == 0){
					return request->len;
				}else if(rb < 0){
					return rb;
				}
			}
			request->len += rb;
			if(request->len == request->cap){
				log_debug("gotta resize buffer");
				if(resize_str(request, request->cap*2) != 0){
					log_error("Not enough memory in reply str");
					return -1;
				}
			}
		}else{
			log_error("Socket returned revents '%d'", pfd[0].revents);
		}
	}
	return request->len;
}

str generate_resource(url resource, str rurl){
	/*
		generate if all of these are true
		1) no file specified (aka we need index.html)
		2) theres an index.html.php
		3) index.html isnt cached (future)
	*/
	str phpfile = dup_strs(resource.path, sstr(".php"));
	if(access(phpfile.ptr, F_OK) == 0){
		// we need a str_copy or something
		str command = dup_strs(command,
			sstr("REQUEST_URI='"), resource.path, sstr("' QUERY_STRING='"), resource.query,
			sstr("' URL='"), rurl,
			sstr("' php -c ./ "), phpfile, sstr(" > "), resource.path
		);
		log_warn("command: %s", command.ptr);
		system(command.ptr);
		free_str(&command);
	}
	free_str(&phpfile);
	str file = dup_str(resource.path);
/*
	if(uri.query.len > 0){
		if(access(uri.path.ptr, F_OK) != 0){
			file.name.ptr = calloc(slen("localc/404/index.html")+1, sizeof(char));
			copy_str(file.name, sstr("localc/404/index.html"));
			return file;
		}

		str pid = utostr(getpid(), 10);
		file.name.ptr = calloc(uri.path.len + pid.len + 1, sizeof(char));
		copy_strs(file.name, uri.path, pid);

		str command = {0};
		command.ptr = calloc(
			slen("REQUEST_URI='") + uri.path.len + slen("' REQUEST_QUERY='") + uri.query.len +
			slen("' php -c ./ ") + uri.path.len + slen(" > ") + file.name.len,
			sizeof(char)
		);
		copy_strs(command,
			sstr("REQUEST_URI='"), uri.path, sstr("' REQUEST_QUERY='"), uri.query,
			sstr("' php -c ./ "), uri.path, sstr(" > "), file.name
		);
		log_warn("command: %s", command.ptr);
		system(command.ptr);
		file.temp = true;

		free_str(&pid);
		free_str(&command);
	}else{
		file.name.ptr = calloc(uri.path.len+1, sizeof(char));
		copy_strs(file.name, uri.path);
	}*/
	
	return file;
}

// TODO: REVISE; return 201/204
char *handlePOST(char *request/*str uri, str body*/){
/*
	char *resource = malloc(1), *uri = getURI(request), *params = getPOSTParams(request);

	if(isPost(uri)){
		rlen = attachBlock(&resource, rlen, HOMEFOLDER, strlen(HOMEFOLDER));
		rlen = attachBlock(&resource, rlen, uri, ulen);
		if(uri[ulen-1] != '/'){
			rlen = attachBlock(&resource, rlen, "/", len("/"));
		}
		generatePagefile(resource, rlen, uri, ulen, params, prlen);

		rlen = attachBlock(&resource, rlen, PAGEFILE, len(PAGEFILE));
	}
	resource[rlen] = '\0';
	free(uri);
	free(params);
	return resource;
*/
	return NULL;
}

static uint32_t request_line_len(char *request){
	uint32_t len = 0;
	while(request[len] && request[len] != '\r') len++;
	return len;
}

// why is this done like this??
void build_http_message(char *request, int rlen, struct http_message *hm){
	char *end = request + rlen;
	memset(hm, 0, sizeof(struct http_message));
	
	hm->method.ptr = request;
	while(request < end && *request != ' ') hm->method.len++, request++;
	if(++request >= end) return;

	hm->url.ptr = request;
	while(request < end && *request != ' ') hm->url.len++, request++;
	if(++request >= end) return;

	hm->req_ver.ptr = request;
	while(request < end && request[hm->req_ver.len] != '\r') hm->req_ver.len++;
	request += hm->req_ver.len + 2;
	if(request > end) return;

	uint32_t llen = 0;
	while((llen = request_line_len(request)) != 0){
		hm->headers[hm->hlen].name.ptr = request;
		while(
			hm->headers[hm->hlen].name.len < llen &&
			request[hm->headers[hm->hlen].name.len] != ':'
		) hm->headers[hm->hlen].name.len++;
		
		request += hm->headers[hm->hlen].name.len + 2;
		if(request > end) return;
		hm->headers[hm->hlen].value.ptr = request;
		hm->headers[hm->hlen].value.len = llen - hm->headers[hm->hlen].name.len - 2;
		request += hm->headers[hm->hlen].value.len + 2;
		hm->hlen++;
		if(request > end) return;
	}
	request += 2;
	if(request > end) return;

	hm->body.ptr = request;
	while(request < end && request[hm->body.len] != '\0') hm->body.len++;
}

// TODO: check if endianness affects this
__attribute__ ((optimize(3))) http_method get_http_method(str method){
	uint64_t m;
	memmove(&m, method.ptr, sizeof(uint64_t));
	if(((m & 0x0000000000FFFFFF) - 0x0000000000544547) == 0){
		return GET;
	}else if(((m & 0x00000000FFFFFFFF) - 0x0000000054534F50) == 0){
		return POST;
	}else if(((m & 0x0000000000FFFFFF) - 0x0000000000545550) == 0){
		return PUT;
	}else if(((m & 0x0000FFFFFFFFFFFF) - 0x00004554454C4544) == 0){
		return DELETE;
	}
	return GET;
}

static uint64_t http_len(struct http_message *hm){
	uint64_t len = 0;
	len += hm->method.len + hm->url.len + hm->req_ver.len + 5 + 2;
	for(int i = 0; i < hm->hlen; ++i){
		len += hm->headers[i].name.len + hm->headers[i].value.len + 4;
	}
	return len;
}

/*static str assemble_with_body(struct http_message *hm, FILE *body, uint64_t len){
	str s = {0};
	s.ptr = calloc(http_len(hm) + len + 1, sizeof(char));
	copy_strs(s, hm->method, sstr(" "), hm->uri, sstr(" "), hm->req_ver, sstr("\r\n"));

	for(int i = 0; i < hm->hlen; i++){
		copy_strs(s, hm->headers[i].name, sstr(": "), hm->headers[i].value, sstr("\r\n"));
	}
	copy_str(s, sstr("\r\n"));

	fread(s.ptr+s.len, sizeof(char), len, body);
	s.len += len;
	//copy_str(s, sstr("\r\n"));

	return s;
}*/

static str http_header_to_str(struct http_message *hm){
	str s = {0};
	s.ptr = calloc(http_len(hm) + 1, sizeof(char));
	copy_strs(s, hm->method, sstr(" "), hm->url, sstr(" "), hm->req_ver, sstr("\r\n"));
	for(int i = 0; i < hm->hlen; i++){
		copy_strs(s, hm->headers[i].name, sstr(": "), hm->headers[i].value, sstr("\r\n"));
	}
	copy_str(s, sstr("\r\n"));
	return s;	
}


url sanitize_url(str rurl){
	str srurl = dnstr(rurl.len);
	if(srurl.ptr == NULL) return (url){0};
	int o = 0;
	while(srurl.len+o < rurl.len){
		srurl.ptr[srurl.len] = rurl.ptr[srurl.len+o];
		if(srurl.len > 0 && (
			(rurl.ptr[srurl.len+o] == '/' && rurl.ptr[srurl.len+o-1] == '/') ||
			(rurl.ptr[srurl.len+o] == '.' && rurl.ptr[srurl.len+o-1] == '.') ||
			(rurl.ptr[srurl.len+o] == '/' && srurl.len+o+1 == rurl.len) ||
			rurl.ptr[srurl.len+o] == '%')
		){
			++o;
		}else{
			srurl.len++;
		}
	}
	log_debug("before:\t'%.*s'", rurl.len, rurl.ptr);
	log_debug("after:\t'%.*s'", srurl.len, srurl.ptr);
	url u = url_check(srurl);
	free_str(&srurl);
	return u;
}

static inline int server_write(http_server *hs, str buf){
	return hs->secure ?
		SSL_write(hs->ssl, buf.ptr, buf.len) :
		send(hs->csocket, buf.ptr, buf.len, 0);
}

// use sendfile(2). reason:
// "sendfile() copies data between one file descriptor and another.
// Because this copying is done within the kernel, sendfile() is
// more efficient than the combination of read(2) and write(2),
// which would require transferring data to and from user space."
void send_file(http_server *hs, str filename){
	log_info("requested '%.*s' -> ", filename.len, filename.ptr);
	uint64_t fsize = get_file_size(filename.ptr);
	if(fsize == 0){
		// we should free it or something here idk maybe not
		filename = sstr("localc/404/index.html");
		fsize = get_file_size(filename.ptr);
	}
	log_info("sending '%.*s'", filename.len, filename.ptr);

	str ext = dsstr(get_extension(filename.ptr));
	str type = get_mime_type(ext);
	if(type.len == 0) type = sstr("text/plain");

	struct http_message hm = {
		.resp_ver = sstr("HTTP/1.1"), .status = sstr("200"), .reason = sstr("OK"),
		.hlen = 2, .headers = {
			{ .name = response_headers[CONTENT_TYPE], .value = type },
			{ .name = response_headers[CONTENT_LENGTH], .value = utostr(fsize, 10) }
		},
		.body = {0},
	};

	str header = http_header_to_str(&hm);
	free_str(&hm.headers[1].value);
	int sent = server_write(hs, header);
	if(sent != header.len){
		if(hs->secure){
			pleasesslgivemetheerror(SSL_get_error(hs->ssl, sent));
		}else{
			log_error("send_file: %s", strerror(errno));
		}
	}
	free_str(&header);

	// make sure system is 64bits before compiling with O_LARGEFILE
	// use fopen maybe?
	int fd = open(filename.ptr, O_RDONLY | /*O_LARGEFILE |*/ O_NONBLOCK);
	while(fsize > 0){
		// CYGWIN DOESNT HAVE SENDFILE OR SPLICE FOR
		// SOME REASON WHEN THIS IS A REAL PROGRAM
		// RUNNING ON LINUX USE SENDFILE (<sys/sendfile.h>)
		// AND COMPILE OPENSSL TO USE KTLS
		// sent = using_ssl ?
		// 	SSL_sendfile(ssl, fd, 0, fsize, 0) :
		// 	sendfile(socket, fd, NULL, fsize);

		// we're ignoring MAX_BODY_SIZE
		str fuckcygwinineedsendfile = fd_to_nstr(fd, fsize);
		sent = server_write(hs, fuckcygwinineedsendfile);
		free_str(&fuckcygwinineedsendfile);

		if(sent > 0){ fsize -= sent;
		}else if(sent == 0){ break;
		}else{
			if(hs->secure){
				pleasesslgivemetheerror(SSL_get_error(hs->ssl, sent));
			}else{
				perror("send_file (fuck cygwin btw)");
			}
		}
		log_info("sent %d more bytes", sent);
	}
	close(fd);
}
