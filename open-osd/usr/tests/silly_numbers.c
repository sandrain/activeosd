/** silly_numbers.c
 */
#define	_BSD_SOURCE
#define	_XOPEN_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>

/** This will generate 8GB output */
#define DEFAULT_OUTCOUNT	(1024*1024*1024)

static unsigned long nr_numbers = DEFAULT_OUTCOUNT;
static double *numbers;
static char *outdir;
static char *foutall;
static char *fouthalf;

extern int errno;

static void populate_numbers(void)
{
	unsigned long i;

	for (i = 0; i < nr_numbers; i++)
		numbers[i] = rand() % 10000;
}

static int write_file(void)
{
	int res = 0;
	unsigned long i;
	FILE *fp;

	fp = fopen(foutall, "w");
	if (!fp)
		return -1;

	for (i = 0; i < nr_numbers; i++) {
		res = fwrite(&numbers[i], sizeof(double), 1, fp);
		if (res != 1) {
			fclose(fp);
			return -1;
		}
#if 0
		fprintf(fp, "%.0lf\n", numbers[i]);
#endif
	}
	res = 0;

	fflush(fp);
	if (fsync(fileno(fp)) < 0)
		res = -1;

	fclose(fp);

	return res;
}

/** For now, this finds numbers <= 5000 (the first half of the original range)
 * And writes to another file.
 */
static int analyze_numbers(void)
{
	int res = 0;
	FILE *fp;
	FILE *fph;
	unsigned long i;

	fp = fopen(foutall, "r");
	if (!fp)
		return -1;
	fph = fopen(fouthalf, "w");
	if (!fph) {
		fclose(fp);
		return -1;
	}

	for (i = 0; i < nr_numbers; i++) {
		double tmp;
		res = fread(&tmp, sizeof(double), 1, fp);
		if (res != 1)
			break;

		if (tmp < 5000)
			continue;

		res = fwrite(&tmp, sizeof(double), 1, fph);
		if (res != 1)
			break;
	}
	res = 0;

	fflush(fph);
	if (fsync(fileno(fph)) < 0)
		res = -1;

	fclose(fph);
	fclose(fp);
	return res;
}

static void usage(const char *exe)
{
	fprintf(stderr, "%s [-n <count>] <output dir>\n", exe);
}

int main(int argc, char **argv)
{
	int res;
	int opt;
	struct timeval t1, t2, t3, t4;

	while ((opt = getopt(argc, argv, "n:")) != -1) {
		switch (opt) {
		case 'n':
			nr_numbers = atoll(optarg);
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (optind >= argc) {
		usage(argv[0]);
		return 1;
	}
	outdir = argv[optind];

	foutall = malloc(sizeof(outdir) + sizeof("all.dat"));
	fouthalf = malloc(sizeof(outdir) + sizeof("half.dat"));
	if (!foutall || !fouthalf) {
		perror("malloc failed");
		return 2;
	}

	numbers = malloc(sizeof(double) * nr_numbers);
	if (!numbers) {
		perror("malloc failed");
		return 3;
	}

	sprintf(foutall, "%s/all.dat", outdir);
	sprintf(fouthalf, "%s/half.dat", outdir);

	srand(time(NULL));

	/** populate numbers */
	gettimeofday(&t1, NULL);

	populate_numbers();

	gettimeofday(&t2, NULL);

	/** write to a file */
	res = write_file();
	if (res) {
		perror("file write failed");
		return -errno;
	}

	gettimeofday(&t3, NULL);

	/** re-read and process it */
	analyze_numbers();

	gettimeofday(&t4, NULL);

	/** print timestamp */
	printf("computing start: %lu.%lu\n", t1.tv_sec, t1.tv_usec);
	printf("computing end:   %lu.%lu\n", t2.tv_sec, t2.tv_usec);
	printf("output end:      %lu.%lu\n", t3.tv_sec, t3.tv_usec);
	printf("processing end:  %lu.%lu\n", t4.tv_sec, t4.tv_usec);

	free(fouthalf);
	free(foutall);
	free(numbers);

	return 0;
}

