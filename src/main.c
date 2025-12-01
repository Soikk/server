#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <libgen.h>
#include "str/str.h"
#include "list/list.h"
#include "net/net.h"
#include "log/log.h"
#include "config/config.h"


str name;
str orig_config_file;
struct {
	str path;
	str socket_file;
	str config_file;
	str workers;
} dir;
config_m config;
http_server *server;
struct worker {
	pid_t pid;
} *workers;


// TODO: waitpid here?
static void propagate_signal(int sig){
	for(int i = 0; i < list_size(workers); i++){
		kill(workers[i].pid, sig);
	}
}

void deinit(void);

static void quit(int sig, siginfo_t *info, void *ucontext){
	log_info("Terminating due to SIG%s (%s)", sigabbrev_np(sig), sigdescr_np(sig));
	propagate_signal(sig);
	deinit();
	exit(0);
}

static void cleanup_worker(pid_t pid, int cleandir){
	waitpid(pid, NULL, 0);
	list_remove_entry(workers, pid);
	if(cleandir){
		str spid = utostr(pid, 10);
		str workerfile = dup_strs(dir.workers, spid);
		if(remove(workerfile.ptr) != 0){
			log_error("Error cleaning up worker's %d file '%.*s': %s", pid, workerfile.len, workerfile.ptr, strerror(errno));
		}
		free_str(&workerfile);
		free_str(&spid);
	}
}

// TODO: look more into waitpid()
// TODO: make a wrapper for sigabbrev_np
static void worker_undertaker(int sig, siginfo_t *info, void *ucontext){
	if(sig == SIGCHLD && list_entry_exists(workers, info->si_pid)){
		switch(info->si_code){
			case CLD_EXITED:
				cleanup_worker(info->si_pid, 0);
				log_info("Worker process %d exited normally with exit value %d",info->si_pid, info->si_status);
				break;
			case CLD_KILLED:
				cleanup_worker(info->si_pid, 1);
				log_info("Worker process %d was killed by signal SIG%s (%s)",
					info->si_pid, sigabbrev_np(info->si_status), sigdescr_np(info->si_status));
				break;
			case CLD_DUMPED:
				cleanup_worker(info->si_pid, 1);
				log_info("Worker process %d was killed by signal SIG%s (%s) and produced a core dump",
					info->si_pid, sigabbrev_np(info->si_status), sigdescr_np(info->si_status));
				break;
			case CLD_TRAPPED:
				log_info("Worker process %d was trapped by signal %d", info->si_pid, info->si_status);
				break;
			case CLD_STOPPED:
				log_info("Worker process %d was stopped by signal %d", info->si_pid, info->si_status);
				break;
			case CLD_CONTINUED:
				log_info("Worker process %d was continued by signal %d", info->si_pid, info->si_status);
				break;
			default:
				cleanup_worker(info->si_pid, 1);
				log_info("Received SIGCHLD for process %d for some reason, with exit code/signal %d", info->si_pid, info->si_status);
				break;
		}
		log_debug("Now workers size is %d", list_size(workers));
	}
}

static int create_server_dir(str name){
	dir.path = dup_strs(sstr("/var/run/"), name, sstr("/"));
	if(!dir_exists(dir.path.ptr)){
		if(mkdir(dir.path.ptr, 0777) != 0){
			log_error("Error creating server directory in '%.*s': %s", dir.path.len, dir.path.ptr, strerror(errno));
			return 1;
		}
	}
	dir.socket_file = dup_strs(dir.path, sstr("socket"));
	dir.config_file = dup_strs(dir.path, sstr("configfile"));
	dir.workers = dup_strs(dir.path, sstr("workers/"));
	if(!dir_exists(dir.workers.ptr)){
		if(mkdir(dir.workers.ptr, 0777) != 0){
			log_error("Error creating workers directory in '%.*s': %s", dir.workers.len, dir.workers.ptr, strerror(errno));
			return 1;
		}
	}
	return 0;
}

static int copy_config_file(str configfile, str dest){
	str cff = map_file(configfile.ptr);
	if(cff.ptr == NULL){
		log_error("Error opening config file '%.*s'", configfile.len, configfile.ptr);
		return 1;
	}
	FILE *cfp = fopen(dest.ptr, "w");
	if(cfp == NULL){
		log_error("Error creating config file in '%.*s': %s", dest.len, dest.ptr, strerror(errno));
		unmap_file(&cff);
		return 1;
	}
	str_to_fp(cff, cfp);
	fclose(cfp);
	unmap_file(&cff);
	return 0;
}

static int write_server_socket(str socket_file, int ssocket){
	// TODO: how to reattach to socket? how to leave socket reattachable? look at ptrace(2)
	log_debug("Creating socket file in %.*s", socket_file.len, socket_file.ptr);
	int sfd = creat(socket_file.ptr, 0777);
	if(sfd == -1){
		log_error("Error creating socket file in '%.*s': %s", socket_file.len, socket_file.ptr, strerror(errno));
		return 1;
	}
	write(sfd, &ssocket, sizeof(ssocket));
	if(close(sfd) == -1){
		log_error("Error closing the socket file '%.*s': %s", socket_file.len, socket_file.ptr, strerror(errno));
		return 1;
	}
	return 0;
}

static void reinit(int sig, siginfo_t *info, void *ucontext){
	if(sig == SIGUSR1){
		log_info("Reinitializing server");
		propagate_signal(sig);
		free_master_config(&config);
		destroy_http_server(&server);

		if(copy_config_file(orig_config_file, dir.config_file)){
			log_error("Unable to create configuration file in server directory");
			quit(SIGTERM, NULL, NULL);
		}
		config = master_config(dir.config_file.ptr);
		if(config.file.ptr == NULL){
			log_error("Unable to read config from '%.*s'", dir.config_file.len, dir.config_file.ptr);
			quit(SIGTERM, NULL, NULL);
		}
		server = setup_http_server(config.port, config.backlog);
		if(server == NULL){
			log_error("Unable to set up socket server");
			quit(SIGTERM, NULL, NULL);
		}
		if(write_server_socket(dir.socket_file, server->ssocket)){
			log_error("Unable to write socket to socket file");
			quit(SIGTERM, NULL, NULL);
		}

		propagate_signal(SIGCONT);
	}
}

int init(char *configfile){
	name = dsstr(basename(configfile));
	orig_config_file = dsstr(configfile);
	if(create_server_dir(name) != 0){
		log_error("Unable to create server directory");
		return 1;
	}
	if(copy_config_file(orig_config_file, dir.config_file) != 0){
		log_error("Unable to create configuration file in server directory");
		return 1;
	}
	config = master_config(dir.config_file.ptr);
	if(config.file.ptr == NULL){
		log_error("Unable to read config from '%.*s'", dir.config_file.len, dir.config_file.ptr);
		return 1;
	}
	log_info("Succesfully read master config from '%.*s'", dir.config_file.len, dir.config_file.ptr);
	// decouple so the whole net.c doesnt get linked?
	server = setup_http_server(config.port, config.backlog);
	if(server == NULL){
		log_error("Unable to set up socket server");
		return 1;
	}
	if(write_server_socket(dir.socket_file, server->ssocket)){
		log_error("Unable to write socket to socket file");
		return 1;
	}
	init_list(workers);
	struct sigaction rnit = { .sa_sigaction = reinit, .sa_flags = SA_SIGINFO };
	if(sigaction(SIGUSR1, &rnit, NULL) == -1){
		log_error("Error setting up SIGUSR1 signal handler: %s", strerror(errno));
		return 1;
	}
	struct sigaction chld = { .sa_sigaction = worker_undertaker, .sa_flags = SA_SIGINFO | SA_NOCLDSTOP };
	if(sigaction(SIGCHLD, &chld, NULL) == -1){
		log_error("Error setting up SIGCHLD signal handler: %s", strerror(errno));
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
	}
	return 0;
}

static void remove_server_dir(void){
	if(dir_exists(dir.workers.ptr)){
		if(remove(dir.workers.ptr) != 0){
			log_error("Error removing workers directory in '%.*s': %s", dir.workers.len, dir.workers.ptr, strerror(errno));
		}
	}
	free_str(&dir.workers);
	if(file_exists(dir.config_file.ptr)){
		if(remove(dir.config_file.ptr) != 0){
			log_error("Error removing config file in '%.*s': %s", dir.config_file.len, dir.config_file.ptr, strerror(errno));
		}
	}
	free_str(&dir.config_file);
	if(file_exists(dir.socket_file.ptr)){
		if(remove(dir.socket_file.ptr) != 0){
			log_error("Error removing socket file in '%.*s': %s", dir.socket_file.len, dir.socket_file.ptr, strerror(errno));
		}
	}
	free_str(&dir.socket_file);
	if(dir_exists(dir.path.ptr)){
		if(remove(dir.path.ptr) != 0){
			log_error("Error removing server directory in '%.*s': %s", dir.path.len, dir.path.ptr, strerror(errno));
		}
	}
	free_str(&dir.path);
}

void deinit(void){
	free_master_config(&config);
	remove_server_dir();
	destroy_http_server(&server);
	list_free(workers);
}

void print_usage(void){
	printf("server [config]\n");
}

void show_commands(void){
	printf(
		"(case insensitive)\n"
		"f: fork\n"
		"s: signal\n"
		"l: list\n"
		"c: clear\n"
		"[0-9]: turn off ssl for worker\n"
		"h: help\n"
		"q: quit\n"
	);
}


int main(int argc, char *argv[]){

	if(argc < 2){
		print_usage();
		return 1;
	}

	int return_value = 0;

	if(init(argv[1]) != 0){
		return_value = 1;
		goto DEINIT;
	}

#ifdef SHOW_IP
	system("curl -s http://ipinfo.io/ip && echo");
#endif


/*
	sqlite3 *db = setupDatabase("src/db/db.db");
	if(db == NULL){
		fprintf(stderr, "error setting up database\n");
		return 1;
	}

	if(getNEntries("archive") != getCount(db, FILE_TABLE)){
		int n = getNEntries("archive");
		char **entries = getFiles("archive"); // getFiles deprecated btw
		for(int i = 0; i < n; ++i){
			insertName(db, FILE_TABLE, entries[i]);
		}
		printf("%d, %d\n", getNEntries("archive"), getCount(db, FILE_TABLE));
	}
*/

	// TODO: lookup shutdown() for sockets
	printf("press h for help\n");
	bool end = false;
	while(!end){
		char c = getchar();
		switch(c){
			case 'f': case 'F':
				pid_t nw = fork();
				if(nw == 0){
					char *args[] = {"./worker.exe", name.ptr, "&", NULL};
					execv("./worker.exe", args);
					log_error("Cannot exec worker: %s", strerror(errno));
					return 1;
				}
				struct worker w = { .pid = nw };
				list_push(workers, w);
				break;
			case 'r': case 'R':
				kill(getpid(), SIGUSR1);
				break;
			case 'l': case 'L':
				printf("|-%3d workers working for us rn-|\n", list_size(workers));
				char *faces[] = {
					"(^__^)", "(·__·)", "(>__>)", "(~ _~)", "(T__T)", "(º__º)"
				};
				for(int i = 0; i < list_size(workers); i++){
					int index = rand()%sizeof(faces)/sizeof(faces[0]);
					printf("| %d %s\t\t\t|\n", workers[i].pid, faces[index]);
				}
				printf("|-------------------------------|\n");
				break;
			case 'c': case 'C':
				system("clear");
				break;
			case 'h': case 'H':
				show_commands();
				break;
			case 'q': case 'Q':
				while(list_size(workers) > 0){
					kill(workers[0].pid, SIGTERM); // redo this PLEASE
					waitpid(workers[0].pid, NULL, 0);
				}
				while(wait(NULL) > 0);
				close(server->ssocket);
				end = true;
				log_info("%d children remaining alive (lie)", list_size(workers));
				break;
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				if(list_size(workers) > c-'0'){
					log_info("signaling worker[%d] %d to turn off ssl", c-'0', workers[c-'0'].pid);
					sigqueue(workers[c-'0'].pid, SIGRTMIN, (union sigval){.sival_int = 0});
				}
				break;
		}
	}

DEINIT:
	deinit();
	log_info("Finished cleaning up");

	return return_value;
}

// inspiration: https://www.youtube.com/watch?v=cEH_ipqHbUw (https://github.com/infraredCoding/cerveur)
// thanks to
/*
	https://beej.us/guide/bgnet/
	https://dev.to/lloyds-digital/how-you-can-host-websites-from-home-4pke
	https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
	https://www.favicon.cc
	https://www.cssscript.com/demo/animated-snowfall-effect/
		https://www.cssscript.com/demo/animated-snowfall-effect/PureSnow.js
	https://www.tutorialspoint.com/http/http_requests.htm
	https://codepen.io/afarrar/pen/JRaEjP
*/

