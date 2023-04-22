#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>

// many reads to a single file

int main() {
	char filepath[] = "/home/aadhi/Desktop/authos/tests/test1.txt";
	char buffer[100];
	struct timeval tv_before;
	struct timeval tv_after;

	gettimeofday(&tv_before, NULL);
	int fd = openat(0, filepath, O_RDONLY);
	for (int i = 0; i < 100000; i++) {
		if (read(fd, buffer, 100) < 0) {
			perror("read failed");
			return -1;
		}
	}
	gettimeofday(&tv_after, NULL);

	printf ("%f seconds\n",
         (double) (tv_after.tv_usec - tv_before.tv_usec) / 1000000 +
         (double) (tv_after.tv_sec - tv_before.tv_sec));

}
