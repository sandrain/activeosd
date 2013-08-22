#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "scsiexe.h"

unsigned char sense_buffer[SENSE_LEN];
unsigned char data_buffer[BLOCK_LEN*256];

void show_hdr_outputs(struct sg_io_hdr * hdr) {
	printf("status:%d\n", hdr->status);
	printf("masked_status:%d\n", hdr->masked_status);
	printf("msg_status:%d\n", hdr->msg_status);
	printf("sb_len_wr:%d\n", hdr->sb_len_wr);
	printf("host_status:%d\n", hdr->host_status);
	printf("driver_status:%d\n", hdr->driver_status);
	printf("resid:%d\n", hdr->resid);
	printf("duration:%d\n", hdr->duration);
	printf("info:%d\n", hdr->info);
}

void show_sense_buffer(struct sg_io_hdr * hdr) {
	unsigned char * buffer = hdr->sbp;
	int i;
	for (i=0; i<hdr->mx_sb_len; ++i) {
		putchar(buffer[i]);
	}
}

void show_vendor(struct sg_io_hdr * hdr) {
	unsigned char * buffer = hdr->dxferp;
	int i;
	printf("vendor id:");
	for (i=8; i<16; ++i) {
		putchar(buffer[i]);
	}
	putchar('\n');
}

void show_product(struct sg_io_hdr * hdr) {
	unsigned char * buffer = hdr->dxferp;
	int i;
	printf("product id:");
	for (i=16; i<32; ++i) {
		putchar(buffer[i]);
	}
	putchar('\n');
}

void show_product_rev(struct sg_io_hdr * hdr) {
	unsigned char * buffer = hdr->dxferp;
	int i;
	printf("product ver:");
	for (i=32; i<36; ++i) {
		putchar(buffer[i]);
	}
	putchar('\n');
}

void test_execute_Inquiry(char * path, int evpd, int page_code) {

	struct sg_io_hdr * p_hdr = init_io_hdr();

	set_xfer_data(p_hdr, data_buffer, BLOCK_LEN*256);
	set_sense_data(p_hdr, sense_buffer, SENSE_LEN);

	int status = 0;

	int fd = open(path, O_RDWR);
	if (fd>0) {
		status = execute_Inquiry(fd, page_code, evpd, p_hdr);
		printf("the return status is %d\n", status);
		if (status!=0) {
			show_sense_buffer(p_hdr);
		} else{
			show_vendor(p_hdr);
			show_product(p_hdr);
			show_product_rev(p_hdr);
		}
	} else {
		printf("failed to open sg file %s\n", path);
	}
	close(fd);
	destroy_io_hdr(p_hdr);
}

static void test_execute_kernel(const char *path)
{
	int fd;
	int status = 0;
	struct sg_io_hdr * p_hdr = init_io_hdr();

	set_xfer_data(p_hdr, data_buffer, BLOCK_LEN*256);
	set_sense_data(p_hdr, sense_buffer, SENSE_LEN);

	fd = open(path, O_RDWR);
	if (fd>0) {
		status = execute_kernel_test(fd, p_hdr);
		printf("the return status is %d\n", status);
		show_sense_buffer(p_hdr);
	} else {
		printf("failed to open sg file %s\n", path);
	}
	close(fd);
	destroy_io_hdr(p_hdr);
}

int main(int argc, char * argv[]) {

	if (argc != 2) {
		fprintf(stderr, "argument required (sgdev path)\n");
		return 0;
	}

	test_execute_Inquiry(argv[1], 0, 0);
	test_execute_kernel(argv[1]);
	return EXIT_SUCCESS;
}
