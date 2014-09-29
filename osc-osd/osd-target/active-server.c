/** active-server.c
 *
 * process active task requests. comm. via shared memory.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

struct active_request {
	int ready;
	int result;
	char command[0];
};

static int quit;
static struct active_request *data;
static char *exe;
static FILE *output;

static void process_request(void)
{
	int ret = 0;

	while (1) {
		if (quit)
			break;

		if (!data->ready) {
			usleep(5000);	/* 500 ms */
			continue;
		}

		fprintf(output, "\n## request: %s\n", data->command);

		ret = system(data->command);
		data->result = ret;

		fprintf(output, "\n## result = %d\n", data->result);

		data->ready = 0;

	}
}

static void sighandler(int num)
{
	quit = 1;
}

static void usage(void)
{
}

int main(int argc, char **argv)
{
	int ret = 0;
	int op;
	int shmid;
	char *mem, *output_path = NULL;
	struct sigaction new_action, old_action;
	struct option opt[] = {
		{.name = "output", .has_arg = 1, .flag = NULL, .val = 'o' },
	};

	exe = argv[0];

	while ((op = getopt_long(argc, argv, "o:", opt, NULL)) != -1) {
		switch (op) {
		case 'o':
			output_path = optarg;
			break;
		default:
			usage();
			break;
		}
	}

	if (output_path) {
		if ((output = fopen(output_path, "a")) == NULL) {
			perror("fopen output");
			ret = -errno;
			goto out;
		}
	}
	else
		output = stdout;

	dup2(fileno(output), fileno(stdout));
	dup2(fileno(output), fileno(stderr));

	setvbuf(output, NULL, _IONBF, 0);
	fprintf(output, "\nserver start: %llu\n",
			(unsigned long long) time(NULL));

	new_action.sa_handler = sighandler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;

	sigaction(SIGINT, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGINT, &new_action, NULL);
	sigaction(SIGHUP, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGHUP, &new_action, NULL);
	sigaction(SIGTERM, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGTERM, &new_action, NULL);

	shmid = open("/tmp/activerequest", O_RDWR);
	if (shmid < 0) {
		perror("open");
		ret = -errno;
		goto out;
	}

	ftruncate(shmid, 1024);

	mem = mmap(NULL, 1024, PROT_READ|PROT_WRITE, MAP_SHARED, shmid, 0);
	if (mem == (void *) -1) {
		perror("mmap");
		ret = errno;
		goto out;
	}

	data = (struct active_request *) mem;

	process_request();

	if (quit)
		fprintf(output, "signal received, terminating..\n");

	munmap(mem, 1024);
	close(shmid);

out:
	fclose(output);
	return ret;
}

