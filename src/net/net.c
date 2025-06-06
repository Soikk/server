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

struct {
	str fmt;
	str type;
} mime_types[] = {
	{.fmt = sstr("avif"), .type = sstr("image/avif")},
	{.fmt = sstr("bmp"), .type = sstr("image/bmp")},
	{.fmt = sstr("css"), .type = sstr("text/css")},
	{.fmt = sstr("csv"), .type = sstr("text/csv")},
	{.fmt = sstr("eot"), .type = sstr("application/vnd.ms-fontobject")},
	{.fmt = sstr("gz"), .type = sstr("application/gzip")},
	{.fmt = sstr("gif"), .type = sstr("image/gif")},
	{.fmt = sstr("html"), .type = sstr("text/html")},
	{.fmt = sstr("ico"), .type = sstr("image/vnd.microsoft.icon")},
	{.fmt = sstr("jpg"), .type = sstr("image/jpeg")},
	{.fmt = sstr("jpeg"), .type = sstr("image/jpeg")},
	{.fmt = sstr("js"), .type = sstr("text/javascript")},
	{.fmt = sstr("json"), .type = sstr("application/json")},
	{.fmt = sstr("midi"), .type = sstr("audio/midi")},
	{.fmt = sstr("mp3"), .type = sstr("audio/mpeg")},
	{.fmt = sstr("mp4"), .type = sstr("video/mp4")},
	{.fmt = sstr("mpeg"), .type = sstr("video/mpeg")},
	{.fmt = sstr("png"), .type = sstr("image/png")},
	{.fmt = sstr("pdf"), .type = sstr("application/pdf")},
	{.fmt = sstr("php"), .type = sstr("application/x-httpd-php")},
	{.fmt = sstr("rar"), .type = sstr("application/vnd.rar")},
	{.fmt = sstr("svg"), .type = sstr("image/svg+xml")},
	{.fmt = sstr("tiff"), .type = sstr("image/tiff")},
	{.fmt = sstr("ts"), .type = sstr("video/mp2t")},
	{.fmt = sstr("ttf"), .type = sstr("font/ttf")},
	{.fmt = sstr("txt"), .type = sstr("text/plain")},
	{.fmt = sstr("wav"), .type = sstr("audio/wav")},
	{.fmt = sstr("weba"), .type = sstr("audio/webm")},
	{.fmt = sstr("webm"), .type = sstr("video/webm")},
	{.fmt = sstr("webp"), .type = sstr("image/webp")},
	{.fmt = sstr("woff"), .type = sstr("font/woff")},
	{.fmt = sstr("woff2"), .type = sstr("font/woff2")},
	{.fmt = sstr("xml"), .type = sstr("application/xml")},
	{.fmt = sstr("zip"), .type = sstr("application/zip")},
	{.fmt = sstr("7z"), .type = sstr("application/x-7z-compressed")},
};

LIST(struct uri_mod) uri_rewrites = NULL;

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

	if(setsockopt(hs->ssocket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))){
		log_error("server: SO_REUSEADDR: %s", strerror(errno));
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
		free(*hs);
		*hs = NULL;
	}
}

http_worker *setup_http_worker(int ssocket, int secure, str certfile, str keyfile){
	http_worker *hw = calloc(1, sizeof(http_worker));
	hw->ssocket = ssocket;
	hw->csocket = -1;
	hw->secure = secure;

	if(secure){
		if(setup_https(hw, certfile, keyfile) != 0){
			log_error("Setting up HTTPS");
			terminate_https(hw);
			destroy_http_worker(&hw);
		}
	}

	return hw;
}

void destroy_http_worker(http_worker **hw){
	if(*hw != NULL){
		(*hw)->ssocket = -1;
		close((*hw)->csocket);
		(*hw)->csocket = -1;
		(*hw)->secure = 0;
		terminate_https(*hw);
		free(*hw);
		*hw = NULL;
	}
}

int setup_https(http_worker *hw, str certfile, str keyfile){
	if(certfile.len == 0){
		log_error("Missing certificate file");
		return 1;
	}
	if(keyfile.len == 0){
		log_error("Missing private key file");
		return 1;
	}

	if(hw->ssl != NULL){
		SSL_free(hw->ssl);
	}
	if(hw->ssl_ctx != NULL){
		SSL_CTX_free(hw->ssl_ctx);
	}

	hw->ssl_ctx = SSL_CTX_new(TLS_server_method());
	// need to compile openssl with ktls on for this (v) to work
	SSL_CTX_set_options(hw->ssl_ctx, SSL_OP_ENABLE_KTLS | SSL_OP_IGNORE_UNEXPECTED_EOF);
	if(hw->ssl_ctx == NULL){
		return 1;
	}
	//SSL_CTX_set_verify(hw->ssl_ctx, SSL_VERIFY_PEER, NULL);
	/*if(SSL_CTX_load_verify_locations(hw->ssl_ctx, "ssl/mkarchive.net/ca_bundle.crt", NULL) <= 0){
		log_error("Verifying certificate locations");
		return 1;
	}*/
	if(SSL_CTX_use_certificate_file(hw->ssl_ctx, certfile.ptr, SSL_FILETYPE_PEM) <= 0){
		log_error("Using certificate file");
		return 1;
	}
	if(SSL_CTX_use_PrivateKey_file(hw->ssl_ctx, keyfile.ptr, SSL_FILETYPE_PEM) <= 0 ){
		log_error("Using private key file");
		return 1;
	}
	hw->ssl = SSL_new(hw->ssl_ctx);
	if(hw->ssl == NULL){
		log_error("Creating SSL*");
		return 1;
	}
	SSL_set_accept_state(hw->ssl);
	hw->secure = 1;

	return 0;
}

void reset_https(http_worker *hw){
	if(hw != NULL){
		close(hw->csocket);
		if(hw->ssl != NULL){
			SSL_free(hw->ssl);
		}
		hw->ssl = SSL_new(hw->ssl_ctx);
		SSL_set_accept_state(hw->ssl);
	}
}

void terminate_https(http_worker *hw){
	if(hw != NULL){
		hw->secure = 0;
		if(hw->ssl != NULL){
			SSL_free(hw->ssl);
			hw->ssl = NULL;
		}
		if(hw->ssl_ctx != NULL){
			SSL_CTX_free(hw->ssl_ctx);
			hw->ssl_ctx = NULL;
		}
	}
}

int accept_connection(http_worker *hw, char ip[INET_ADDRSTRLEN]){
	struct sockaddr_storage caddr;
	int casize = sizeof(caddr);
	log_info("Waiting...");
	if((hw->csocket = accept(hw->ssocket, (struct sockaddr *)&caddr, (socklen_t*)&casize)) == -1){
		log_error("accept_socket() -> accept(): %s", strerror(errno));
		return -1;
	}
	log_info("accepted");
	if(hw->secure){
		int err = SSL_set_fd(hw->ssl, hw->csocket);
		if(err != 1){
			log_error("setting fd %d", hw->csocket);
			return pleasesslgivemetheerror(SSL_get_error(hw->ssl, err));
		}
		if((err = SSL_accept(hw->ssl)) != 1){
			log_error("couldnt accept");
			return pleasesslgivemetheerror(SSL_get_error(hw->ssl, err));
		}
	}
	inet_ntop(caddr.ss_family, &(((struct sockaddr_in*)&caddr)->sin_addr), ip, INET_ADDRSTRLEN);
	return 0;
}

static inline int worker_read(http_worker *hw, str *buf){
	return hw->secure ?
		SSL_read(hw->ssl, buf->ptr+buf->len, buf->cap-buf->len) :
		recv(hw->csocket, buf->ptr+buf->len, buf->cap-buf->len, 0);
}

int receive_request(http_worker *hw, str *request){
	// SSL_has_pending can return 0 if you havent read any bytes yet (https://stackoverflow.com/questions/6616976/why-does-this-ssl-pending-call-always-return-zero)
	struct pollfd pfd[1] = { {.fd = hw->csocket, .events = POLLIN } };
	while((hw->secure && SSL_has_pending(hw->ssl)) || poll(pfd, 1, 100)){
		int new = worker_read(hw, request);
		if(new < 0 || (hw->secure && new == 0)){
			int error = new;
			if(hw->secure) error = pleasesslgivemetheerror(SSL_get_error(hw->ssl, new));
			else log_error("http (no s) error: %s", strerror(errno));
			return error;
		}
		request->len += new;
		if(request->len == request->cap){
			log_info("gotta resize buffer");
			if(resize_str(request, request->cap*2) != 0){
				log_error("Not enough memory in reply str");
				return -1;
			}
		}
	}
	return 0;
}

struct file generate_resource(struct uri resource, str url){
	struct file file = {0};
	/*
		generate if all of these are true
		1) no file specified (aka we need index.html)
		2) theres an index.html.php
		3) index.html isnt cached (future)
	*/
	str phpfile = dnstr(resource.path.len + slen(".php"));
	copy_strs(phpfile, resource.path, sstr(".php"));
	if(access(phpfile.ptr, F_OK) == 0){
		// we need a str_copy or something
		str command = dnstr(
			slen("REQUEST_URI='") + resource.path.len + slen("' QUERY_STRING='") + resource.query.len +
			slen("' URL='") + url.len +
			slen("' php -c ./ ") + phpfile.len + slen(" > ") + resource.path.len
		);
		copy_strs(command,
			sstr("REQUEST_URI='"), resource.path, sstr("' QUERY_STRING='"), resource.query,
			sstr("' URL='"), url,
			sstr("' php -c ./ "), phpfile, sstr(" > "), resource.path
		);
		log_warn("command: %s", command.ptr);
		system(command.ptr);
		free_str(&command);
	}
	free_str(&phpfile);
	file.name = dup_str(resource.path);
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

	hm->uri.ptr = request;
	while(request < end && *request != ' ') hm->uri.len++, request++;
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
	len += hm->method.len + hm->uri.len + hm->req_ver.len + 5 + 2;
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
	copy_strs(s, hm->method, sstr(" "), hm->uri, sstr(" "), hm->req_ver, sstr("\r\n"));
	for(int i = 0; i < hm->hlen; i++){
		copy_strs(s, hm->headers[i].name, sstr(": "), hm->headers[i].value, sstr("\r\n"));
	}
	copy_str(s, sstr("\r\n"));
	return s;	
}

/*
	Given two strings p and u, and a uri (a struct with two strings) o
	where p is a pattern, u is a url that is gonna checked for the pattern
	and o is the uri output blueprint that must be returned should u follow p

	There is a tokens array where tokens found in the url can be stored (up to 9 tokens)

	In p:
		<X> optionally matches a character X and stores it in the tokens array 
		^ optionally matches any character and stores it in the tokens array
		* optionally matches a string of character until another match is found
		  or the url to match ends, and stores it in the tokens array

	In o:
		$1 through $9 reference the tokens in the token array (I could make it 10 tokens tbh)
		Both the strings in the uri can access these tokens
		Referencing a token writes it to the output uri
		If theres a token before a <X>, say $3<a> that means that the character
		between the less than and greater than signs will only be written
		to the output if the token number 3 in the array exists (has length > 0)
		All other characters get outputted normally
*/
static struct uri uri_rewrite(str p, str u, struct uri o){
	int i = 0, j = 0, in = 0, ti = 0;
	str tokens[9] = {0};
	for(; j < p.len; i += 1){
		if(i < u.len && p.ptr[j+in] == '<' && p.ptr[j+in+1] == u.ptr[i]){
			if(ti < 9) tokens[ti++] = (str){.ptr = u.ptr+i, .len = 1};
			j += 3+in, in = 0;
		}else if(i < u.len && (p.ptr[j+in] == '^' || p.ptr[j+in] == u.ptr[i])){
			if(p.ptr[j] == '^' && ti < 9) tokens[ti++] = (str){.ptr = u.ptr+i, .len = 1};
			j += 1+in, in = 0;
		}else if(i < u.len && p.ptr[j] == '*'){
			if(!in){
				if(ti < 9) tokens[ti++] = (str){.ptr = u.ptr+i, .len = 0};
				in = 1;
			}
			if(ti-in < 9) tokens[ti-in].len++;
		}else{
			if(i >= u.len && p.ptr[j] == '*') j++;
			else if(i >= u.len && p.ptr[j] == '<') j += 3;
			else return (struct uri){0};
		}
	}
	if(i < u.len) return (struct uri){0};

	struct uri r = {0};
	str *no = &o.path, *nr = &r.path;
	for(int k = 0, rlen = 0; k < 2; k++, no = &o.query, nr = &r.query){
		for(int i = 0; i < no->len; i++, rlen++){
			if(no->ptr[i] == '$') rlen += tokens[no->ptr[++i]-'1'].len-1;
		}
		nr->ptr = calloc(rlen+1, sizeof(char));
		if(nr->ptr == NULL){
			if(r.path.ptr != NULL) free(r.path.ptr);
			return (struct uri){0};
		}

		for(int i = 0; i < no->len; i++){
			if(no->ptr[i] == '$'){
				if(++i+1 < no->len && no->ptr[i+1] == '<'){
					if(tokens[no->ptr[i]-'1'].len > 0) i++;
					else while(no->ptr[++i] != '>');
				}else{
					copy_str((*nr), tokens[no->ptr[i]-'1']);
				}
			}else{
				if(no->ptr[i] != '>') nr->ptr[nr->len++] = no->ptr[i];
			}
		}
	}

	return r;
}

struct uri sanitize_uri(str uri){
	str suri = {.ptr = calloc(uri.len+1, sizeof(char)), .len = 0};
	if(suri.ptr == NULL) return (struct uri){0};
	int i = 0, o = 0;
	while(i+o < uri.len){
		suri.ptr[i] = lowerchar(uri.ptr[i+o]);
		if(i > 0 && (
			(uri.ptr[i+o] == '/' && uri.ptr[i+o-1] == '/') ||
			(uri.ptr[i+o] == '.' && uri.ptr[i+o-1] == '.') ||
			(uri.ptr[i+o] == '/' && i+o+1 == uri.len) ||
			uri.ptr[i+o] == '%')
		){
			++o;
		}else{
			++i;
		}
	}
	suri.ptr[suri.len = i] = '\0';
	
	struct uri u = {0};
	for(int i = 0; i < list_size(uri_rewrites); i++){
		u = uri_rewrite(uri_rewrites[i].pattern, suri, uri_rewrites[i].output);
		if(u.path.len > 0) break;
	}
	free_str(&suri);
	if(u.path.len == 0){
		u.path = dstr("localc/404/index.html");
		free_str(&u.query);
	}
	return u;
}

static inline int worker_write(http_worker *hw, str buf){
	return hw->secure ?
		SSL_write(hw->ssl, buf.ptr, buf.len) :
		send(hw->csocket, buf.ptr, buf.len, 0);
}

// use sendfile(2). reason:
// "sendfile() copies data between one file descriptor and another.
// Because this copying is done within the kernel, sendfile() is
// more efficient than the combination of read(2) and write(2),
// which would require transferring data to and from user space."
void send_file(http_worker *hw, str filename){
	log_info("requested '%.*s' -> ", filename.len, filename.ptr);
	uint64_t fsize = get_file_size(filename.ptr);
	if(fsize == 0){
		// we should free it or something here idk maybe not
		filename = sstr("localc/404/index.html");
		fsize = get_file_size(filename.ptr);
	}
	log_info("sending '%.*s'", filename.len, filename.ptr);

	enum mime_type type = TXT;
	str fmt = get_file_format(filename);
	for(int i = 0; i < sizeof(mime_types)/sizeof(mime_types[0]); i++){
		if(strncmp(fmt.ptr, mime_types[i].fmt.ptr, fmt.len) == 0){
			type = i;
			break;
		}
	}
	free_str(&fmt);

	struct http_message hm = {
		.resp_ver = sstr("HTTP/1.1"), .status = sstr("200"), .reason = sstr("OK"),
		.hlen = 2, .headers = {
			{ .name = response_headers[CONTENT_TYPE], .value = mime_types[type].type },
			{ .name = response_headers[CONTENT_LENGTH], .value = utostr(fsize, 10) }
		},
		.body = {0},
	};

	str header = http_header_to_str(&hm);
	free_str(&hm.headers[1].value);
	int sent = worker_write(hw, header);
	if(sent != header.len){
		if(hw->secure){
			pleasesslgivemetheerror(SSL_get_error(hw->ssl, sent));
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
		str fuckcygwinineedsendfile;
		fd_to_str(&fuckcygwinineedsendfile, fd, fsize);
		sent = worker_write(hw, fuckcygwinineedsendfile);
		free_str(&fuckcygwinineedsendfile);

		if(sent > 0){ fsize -= sent;
		}else if(sent == 0){ break;
		}else{
			if(hw->secure){
				pleasesslgivemetheerror(SSL_get_error(hw->ssl, sent));
			}else{
				perror("send_file (fuck cygwin btw)");
			}
		}
		log_info("sent %d more bytes", sent);
	}
	close(fd);
}

// this shouldnt be here
int read_uri_rewrites(char *map, uint64_t size){
	uint64_t i = 0;
	if(strncmp(map, "rewrites", slen("rewrites")) != 0) return 1;
	i += slen("rewrites");
	while(charisspace(map[i])) i++;
	if(map[i++] != '{') return 1;
	list_free(uri_rewrites);
	init_nlist(uri_rewrites);
	while(i < size && map[i] != '}'){
		struct uri_mod um = {0};
		i += ({sread_delim_f(map+i, charisspace, false);}).len;
		i += ({um.pattern = read_delim_f(map+i, charisspace, true);}).len;
		i += ({sread_delim_f(map+i, charisblank, false);}).len;
		i += ({um.output.path = read_delim_f(map+i, charisspace, true);}).len;
		i += ({sread_delim_f(map+i, charisblank, false);}).len;
		i += ({um.output.query = read_delim_f(map+i, charisspace, true);}).len;
		i += ({sread_delim(map+i, '\n');}).len + 1;
		list_push(uri_rewrites, um);
	}
	return 0;
}

void free_uri_rewrites(void){
	for(uint32_t i = 0; i < list_size(uri_rewrites); i++){
		free_str(&uri_rewrites[i].pattern);
		free_str(&uri_rewrites[i].output.path);
		free_str(&uri_rewrites[i].output.query);
	}
	list_free(uri_rewrites);
}

