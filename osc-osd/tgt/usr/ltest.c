#include <stdio.h>
#include <stdlib.h>

#include "list.h"

struct job {
	int id;
	struct list_head list;
};

static LIST_HEAD(job_list);
static LIST_HEAD(free_list);

static int count = 10;

static struct job *fetch_job(void)
{
	struct job *job;

	if (list_empty(&job_list))
		return NULL;

	job = list_first_entry(&job_list, struct job, list);
	list_del(&job->list);

	return job;
}

static struct job *alloc_job(void)
{
	struct job *job;

	if (list_empty(&free_list))
		return malloc(sizeof(struct job));

	job = list_first_entry(&free_list, struct job, list);
	list_del(&job->list);
	INIT_LIST_HEAD(&job->list);

	return job;
}

static void free_job(struct job *job)
{
	list_add_tail(&job->list, &free_list);
}

int main(int argc, char **argv)
{
	int i;
	struct job *job;
	struct list_head *pos;

	if (argc == 2)
		count = atoi(argv[1]);

	for (i = 0; i < count; i++) {
		job = alloc_job();
		job->id = i;
		INIT_LIST_HEAD(&job->list);

		list_add_tail(&job->list, &job_list);
	}

	for (i = 0; i < count / 2; i++) {
		job = fetch_job();
		job->id += 100;

		free_job(job);
	}

	while (!list_empty(&free_list)) {
		job = alloc_job();
		printf("%d\n", job->id);

		list_add_tail(&job->list, &job_list);
	}

	for (i = 0; i < count/2; i++) {
		job = fetch_job();

		free_job(job);
	}

	printf("\n\njob list ==\n");

	list_for_each(pos, &job_list) {
		job = list_entry(pos, struct job, list);
		printf("%d\n", job->id);
	}

	printf("free list ==\n");

	list_for_each(pos, &free_list) {
		job = list_entry(pos, struct job, list);
		printf("%d\n", job->id);
	}

	while (!list_empty(&job_list)) {
		job = fetch_job();
		free(job);
	}

	while (!list_empty(&free_list)) {
		job = alloc_job();
		free(job);
	}

	return 0;
}

