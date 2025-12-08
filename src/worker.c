#include <stdio.h>
#include <stdlib.h>
#include "str/str.h"
#include "net/net.h"
#include "config/config.h"


struct {
	str path;
	str config_file;
	str self;
} dir;
config conf;
http_server *server;

// remove this or something
int secure = 0;


void deinit(void);

static void quit(int sig, siginfo_t *info, void *ucontext){
	log_info("Terminating due to SIG%s (%s)", sigabbrev_np(sig), sigdescr_np(sig));
	deinit();
	exit(0);
}

static int signal_wait(int sig){
	sigset_t old, new;
	sigemptyset(&new);
	sigaddset(&new, sig);
	if(sigprocmask(SIG_BLOCK, &new, &old) != 0){
		return 1;
	}
	// TODO: try with NULL
	int s;
	if(sigwait(&new, &s) != 0){
		return 1;
	}
	if(sigprocmask(SIG_SETMASK, &old, NULL) != 0){
		return 1;
	}
	return 0;
}

static void reinit(int sig, siginfo_t *info, void *ucontext){
	if(sig == SIGUSR1){
		log_info("Reinitializing worker");
		free_config(&conf);
		destroy_http_server(&server);

		if(signal_wait(SIGCONT) != 0){
			log_error("You should probably look at signal_wait to see wtf is going on");
		}

		conf = read_config(dir.config_file.ptr);
		if(conf.file.ptr == NULL){
			log_error("Unable to read config from '%.*s'", dir.config_file.len, dir.config_file.ptr);
			quit(SIGTERM, NULL, NULL);
		}
		server = setup_http_server(conf.port, conf.backlog);
		if(server == NULL){
			log_error("Error setting up worker server");
			quit(SIGTERM, NULL, NULL);
		}
	}
}

// possibly change name
static int read_server_dir(str name){
	dir.path = dup_strs(sstr("/var/run/"), name, sstr("/"));
	if(!dir_exists(dir.path.ptr)){
		log_error("No server directory in '%.*s'", dir.path.len, dir.path.ptr);
		return 1;
	}
	dir.config_file = dup_strs(dir.path, sstr("configfile"));
	if(!file_exists(dir.config_file.ptr)){
		log_error("No config file in '%.*s'", dir.config_file.len, dir.config_file.ptr);
		return 1;
	}
	// TODO: revise this
	str pid = utostr(getpid(), 10);
	dir.self = dup_strs(dir.path, sstr("workers/"), pid);
	free_str(&pid);
	if(creat(dir.self.ptr, 0777) == -1){
		log_error("Error creating PID record for self in '%.*s': %s", dir.self.len, dir.self.ptr, strerror(errno));
		return 1;
	}
	return 0;
}

// possibly change name
static void remove_server_dir(void){
	if(remove(dir.self.ptr) != 0){
		log_error("Error removing PID record for self in '%.*s': %s", dir.self.len, dir.self.ptr, strerror(errno));
	}
	free_str(&dir.self);
	free_str(&dir.config_file);
	free_str(&dir.path);
}

int init(str name){
	if(read_server_dir(name) != 0){
		log_error("Error reading server directory");
		return 1;
	}
	conf = read_config(dir.config_file.ptr);
	if(conf.file.ptr == NULL){
		log_error("Unable to read config from '%.*s'", dir.config_file.len, dir.config_file.ptr);
		return 1;
	}
	//print_worker_config(config);
	server = setup_http_server(conf.port, conf.backlog);
	if(server == NULL){
		log_error("Error setting up worker server");
		return 1;
	}
	struct sigaction rnit = { .sa_sigaction = reinit, .sa_flags = SA_SIGINFO };
	if(sigaction(SIGUSR1, &rnit, NULL) == -1){
		log_error("Error setting up SIGUSR1 signal handler: %s", strerror(errno));
		return 1;
	}
	struct sigaction qit = { .sa_sigaction = quit, .sa_flags = SA_SIGINFO };
	if(sigaction(SIGTERM, &qit, NULL) == -1){
		log_error("Error setting up SIGTERM signal handler: %s", strerror(errno));
		return 1;
	}
	if(sigaction(SIGQUIT, &qit, NULL) == -1){
		log_error("Error setting up SIGQUIT signal handler: %s", strerror(errno));
		return 1;
	}
	if(sigaction(SIGINT, &qit, NULL) == -1){
		log_error("Error setting up SIGINT signal handler: %s", strerror(errno));
		return 1;
	}
	return 0;
}

void deinit(void){
	destroy_http_server(&server);
	free_config(&conf);
	remove_server_dir();
}


int main(int argc, char **argv){

	if(argc < 2){
		printf("worker [server name]\n");
		return 1;
	}

	int ret = 0;

	if(init(dsstr(argv[1])) != 0){
		ret = 1;
		goto DEINIT;
	}
	log_info("init'd");

	str request = {.cap = 8192, .len = 0, .ptr = alloca(8192)};
	// TODO: lookup shutdown() for sockets
	while(1){
		char cip[INET_ADDRSTRLEN] = {0};
		ret = accept_connection(server, cip);
		if(ret != 0){ // couldnt accept, do something ig
			if(ret == SSL_ERROR_SSL) reset_https(server);
			log_info("continuing\n");
			continue;
		}
		log_info("socket %d accepted with ip %s", server->csocket, cip);
		ret = receive_request(server, &request);
		log_debug("received %d from receive_request", ret);
		if(ret <= 0){
			if(ret == SSL_ERROR_SSL) reset_https(server);
			log_info("continuing\n");
			goto finish_request;
		}

		log_debug("%d: '%.*s'\n", request.len, request.len, request.ptr);

		struct http_message hm = {0};
		build_http_message(request.ptr, request.len, &hm);
		log_info("url before: %.*s", hm.url.len, hm.url.ptr);
		url surl = sanitize_url(hm.url);
		log_info("uri after: '%.*s' ? '%.*s'", surl.path.len, surl.path.ptr, surl.query.len, surl.query.ptr);
		enum http_method method = get_http_method(hm.method);
		switch(method){
			case GET:
				str resource = generate_resource(surl, hm.url);
				send_file(server, resource);
				//if(resource.temp == true) remove(resource.name.ptr);
				free_str(&resource);
				break;
			case POST:
				//handlePOST(request);
				send(server->csocket, "HTTP/1.1 201 Created\r\n\r\n", len("HTTP/1.1 201 Created\r\n\r\n"), 0);
				break;
			case PUT:
				break;
			case DELETE:
				break;
			default:
				break;
		}

finish_request:
		free_url(&surl);
		request.len = 0;

		if(server->secure){
			SSL_clear(server->ssl);
		}
		close(server->csocket);

		//SSL_shutdown(config.ssl); // look into SSL_clear()

		log_debug("end of loop");
	}

DEINIT:
	deinit();
	log_info("Worker %d dieing :(", getpid());

	return ret;
}

/*
struct timespec t_start, t_end;

#define start_timing() clock_gettime(CLOCK_MONOTONIC, &t_start)
#define end_timing() clock_gettime(CLOCK_MONOTONIC, &t_end)

double get_timing(void){
	uint64_t diff = (t_end.tv_sec*1000000000 + t_end.tv_nsec) - (t_start.tv_sec*1000000000 + t_start.tv_nsec);
	return diff/1000000000.0;
}
*/
