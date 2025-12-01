#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "str/str.h"
#include "net/net.h"
#include "config/config.h"


config_w config;
struct {
	str path;
	str socket_path;
	str config_file;
	str self;
} dir;
http_worker *worker;

// remove these or something
int secure = 0;


void deinit(void);

void quit(int sig, siginfo_t *info, void *ucontext){
	log_info("Terminating due to SIG%s (%s)", sigabbrev_np(sig), sigdescr_np(sig));
	deinit();
	exit(0);
}

int signal_wait(int sig){
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

void reinit(int sig, siginfo_t *info, void *ucontext){
	if(sig == SIGUSR1){
		log_info("Reinitializing worker");
		free_worker_config(&config);
		destroy_http_worker(&worker);

		if(signal_wait(SIGCONT) != 0){
			log_error("You should probably look at signal_wait to see wtf is going on");
		}

		config = worker_config(dir.config_file.ptr);
		if(config.file.ptr == NULL){
			log_error("Unable to read config from '%.*s'", dir.config_file.len, dir.config_file.ptr);
			quit(SIGTERM, NULL, NULL);
		}
		int sfd = open(dir.socket_path.ptr, O_RDONLY);
		int ssocket;
		read(sfd, &ssocket, sizeof(int));
		close(sfd);
		worker = setup_http_worker(ssocket, secure, config.cert, config.key);
		if(worker == NULL){
			log_error("Error setting up worker server");
			quit(SIGTERM, NULL, NULL);
		}
	}
}

// possibly change name
int read_server_dir(str name){
	dir.path = dup_strs(sstr("/var/run/"), name, sstr("/"));
	if(!dir_exists(dir.path.ptr)){
		log_error("No server directory in '%.*s'", dir.path.len, dir.path.ptr);
		return 1;
	}
	dir.socket_path = dup_strs(dir.path, sstr("socket"));
	if(!file_exists(dir.socket_path.ptr)){
		log_error("No socket file in '%.*s'", dir.socket_path.len, dir.socket_path.ptr);
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
	if(file_exists(dir.self.ptr)){
		log_error("Error creating PID record for self in '%.*s': it already exists", dir.self.len, dir.self.ptr);
		return 1;
	}
	if(creat(dir.self.ptr, 0777) == -1){
		log_error("Error creating PID record for self in '%.*s': %s", dir.self.len, dir.self.ptr, strerror(errno));
		return 1;
	}
	return 0;
}

int init(str name){
	if(read_server_dir(name) != 0){
		log_error("Error reading server directory");
		return 1;
	}
	config = worker_config(dir.config_file.ptr);
	if(config.file.ptr == NULL){
		log_error("Unable to read config from '%.*s'", dir.config_file.len, dir.config_file.ptr);
		return 1;
	}
	//print_worker_config(config);
	// TODO: remove "successful" messages or add them all	
	log_info("Succesfully read worker config from '%.*s'", dir.config_file.len, dir.config_file.ptr);
	int sfd = open(dir.socket_path.ptr, O_RDONLY);
	int ssocket;
	read(sfd, &ssocket, sizeof(int));
	close(sfd);
	worker = setup_http_worker(ssocket, secure, config.cert, config.key);
	if(worker == NULL){
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

// possibly change name
void remove_server_dir(void){
	if(remove(dir.self.ptr) != 0){
		log_error("Error removing PID record for self in '%.*s': %s", dir.self.len, dir.self.ptr, strerror(errno));
	}
	free_str(&dir.self);
	free_str(&dir.path);
}

void deinit(void){
	free_worker_config(&config);
	remove_server_dir();
	destroy_http_worker(&worker);
}

void print_usage(void){
	printf("worker [server name]\n");
}


int main(int argc, char **argv){

	if(argc < 2){
		print_usage();
		return 1;
	}

	int return_value = 0;

	if(init(dsstr(argv[1])) != 0){
		return_value = 1;
		goto DEINIT;
	}
	log_info("init'd");

	//bool end = false;
	str request = {.cap = 8192, .len = 0, .ptr = alloca(8192)};

	while(1){
		char cip[INET_ADDRSTRLEN] = {0};
		return_value = accept_connection(worker, cip);
		switch(return_value){
			case -1: // couldnt accept, do something ig
				continue;
			case SSL_ERROR_SSL:
				reset_https(worker);
				log_info("continuing\n");
				continue;
		}
		log_info("socket %d accepted with ip %s", worker->csocket, cip);
		return_value = receive_request(worker, &request);
		log_debug("received %d from receive_request", return_value);
		switch(return_value){
			case -1: // couldnt accept, do something ig
				goto finish_request;
				break;
			case SSL_ERROR_SSL:
				reset_https(worker);
				log_info("continuing\n");
				continue;
		}

		printf("%d: '%.*s'\n", request.len, request.len, request.ptr);

		struct http_message hm = {0};
		build_http_message(request.ptr, request.len, &hm);
		log_info("url before: %.*s", hm.url.len, hm.url.ptr);
		url surl = sanitize_url(hm.url);
		log_info("uri after: '%.*s' ? '%.*s'", surl.path.len, surl.path.ptr, surl.query.len, surl.query.ptr);
		enum http_method method = get_http_method(hm.method);

		switch(method){
			case GET:
				str resource = generate_resource(surl, hm.url);
				send_file(worker, resource);
				//if(resource.temp == true) remove(resource.name.ptr);
				free_str(&resource);
				break;
			case POST:
				//handlePOST(request);
				send(worker->csocket, "HTTP/1.1 201 Created\r\n\r\n", len("HTTP/1.1 201 Created\r\n\r\n"), 0);
				break;
			case PUT:
				break;
			case DELETE:
				break;
			default:
				break;
		}

finish_request:
		free_str(&surl.path);
		free_str(&surl.query);
		log_debug("query freed");
		request.len = 0;

		if(worker->secure){
			SSL_clear(worker->ssl);
		}
		close(worker->csocket);

		//SSL_shutdown(config.ssl); // look into SSL_clear()

		log_debug("end of loop");
	}

DEINIT:
	deinit();
	log_info("dieing :(");

	return return_value;
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
