#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <libgen.h>
#include <sys/wait.h>
#include "str/str.h"
#include "log/log.h"
#include "list/list.h"
#include "config/config.h"


struct {
	str name;
	str path;
	str config_file;
	str workers;
} dir;
str orig_config_file;
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

static int create_server_dir(char *configfile){
	str cff = map_file(configfile);
	if(cff.ptr == NULL){
		log_error("Error opening config file '%s'", configfile);
		return 1;
	}
	dir.name = get_key(cff, sstr("name"));
	dir.path = dup_strs(sstr("/var/run/"), dir.name, sstr("/"));
	if(!dir_exists(dir.path.ptr)){
		if(mkdir(dir.path.ptr, 0777) != 0){
			log_error("Error creating server directory in '%.*s': %s", dir.path.len, dir.path.ptr, strerror(errno));
			unmap_file(&cff);
			return 1;
		}
	}
	dir.config_file = dup_strs(dir.path, sstr("configfile"));
	FILE *cfp = fopen(dir.config_file.ptr, "w");
	if(cfp == NULL){
		log_error("Error copying config file to '%.*s': %s", dir.config_file.len, dir.config_file.ptr, strerror(errno));
		unmap_file(&cff);
		return 1;
	}
	str_to_fp(cff, cfp);
	fclose(cfp);
	unmap_file(&cff);
	dir.workers = dup_strs(dir.path, sstr("workers/"));
	if(!dir_exists(dir.workers.ptr)){
		if(mkdir(dir.workers.ptr, 0777) != 0){
			log_error("Error creating workers directory in '%.*s': %s", dir.workers.len, dir.workers.ptr, strerror(errno));
			return 1;
		}
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
	if(dir_exists(dir.path.ptr)){
		if(remove(dir.path.ptr) != 0){
			log_error("Error removing server directory in '%.*s': %s", dir.path.len, dir.path.ptr, strerror(errno));
		}
	}
	free_str(&dir.path);
	free_str(&dir.name);
}

static void reinit(int sig, siginfo_t *info, void *ucontext){
	if(sig == SIGUSR1){
		log_info("Reinitializing server");
		propagate_signal(sig);

		str cff = map_file(orig_config_file.ptr);
		FILE *cfp = fopen(dir.config_file.ptr, "w");
		if(cfp == NULL){
			log_error("Error copying config file to '%.*s': %s", dir.config_file.len, dir.config_file.ptr, strerror(errno));
			unmap_file(&cff);
			quit(SIGTERM, NULL, NULL);
		}
		str_to_fp(cff, cfp);
		fclose(cfp);
		unmap_file(&cff);

		propagate_signal(SIGCONT);
	}
}

int init(char *configfile){
	orig_config_file = dsstr(configfile);
	if(create_server_dir(configfile) != 0){
		log_error("Unable to create server directory");
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

void deinit(void){
	remove_server_dir();
	list_free(workers);
}


int main(int argc, char *argv[]){

	if(argc < 2){
		printf("server [config]\n");
		return 1;
	}

	int ret = 0;

	if(init(argv[1]) != 0){
		ret = 1;
		goto DEINIT;
	}

#ifdef SHOW_IP
	system("curl -s http://ipinfo.io/ip && echo");
#endif

	printf("press h for help\n");
	bool end = false;
	while(!end){
		char c = getchar();
		switch(c){
			case 'f': case 'F':
				pid_t nw = fork();
				if(nw == 0){
					char *args[] = {"./worker.exe", dir.name.ptr, "&", NULL};
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
				char *faces[] = {
					"(^__^)", "(·__·)", "(>__>)", "(~ _~)", "(T__T)", "(º__º)"
				};
				printf("|-%3d workers working for us rn-|\n", list_size(workers));
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
				printf(
					"(case insensitive)\n"
					"f: fork\n"
					"l: list\n"
					"c: clear\n"
					"h: help\n"
					"q: quit\n"
				);
				break;
			case 'q': case 'Q':
				while(list_size(workers) > 0){
					kill(workers[0].pid, SIGTERM); // redo this PLEASE
					waitpid(workers[0].pid, NULL, 0);
				}
				while(wait(NULL) > 0);
				end = true;
				log_info("%d children remaining alive (lie)", list_size(workers));
				break;
		}
	}

DEINIT:
	deinit();
	log_info("Finished cleaning up");

	return ret;
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

