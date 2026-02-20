#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>

#define FILECOPY_IOC_MAGIC  'F'
#define FILECOPY_IOC_COPY   _IOW(FILECOPY_IOC_MAGIC, 1, struct filecopy_args)

#define FILECOPY_MAX_PATH 256

struct filecopy_args {
    char src[FILECOPY_MAX_PATH];
    char dst[FILECOPY_MAX_PATH];
};

int main(int argc, char *argv[])
{
    int fd;
    struct filecopy_args args;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <source_path> <dest_path>\n", argv[0]);
        return 1;
    }

    fd = open("/dev/filecopy", O_RDWR);
    if (fd < 0) {
        perror("open /dev/filecopy failed");
        return 1;
    }

    strncpy(args.src, argv[1], FILECOPY_MAX_PATH - 1);
    args.src[FILECOPY_MAX_PATH - 1] = '\0';

    strncpy(args.dst, argv[2], FILECOPY_MAX_PATH - 1);
    args.dst[FILECOPY_MAX_PATH - 1] = '\0';

    if (ioctl(fd, FILECOPY_IOC_COPY, &args) < 0) {
        perror("ioctl FILECOPY_IOC_COPY failed");
        close(fd);
        return 1;
    }

    printf("File copied successfully.\n");
    close(fd);
    return 0;
}