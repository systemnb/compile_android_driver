#include <linux/slab.h>
#include <linux/random.h>


typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char* name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;
struct process {
    pid_t process_pid;
	char *process_comm;
};

enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
    OP_HIDE_PROCESS = 0x804,
    OP_PID_HIDE_PROCESS = 0x805,
    OP_GET_PROCESS_PID = 0x806
};

char* get_rand_str(void)
{
	static char string[10];
	int lstr,seed,flag,i;
	char *str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	lstr = strlen(str);
	for (i = 0; i < 6; i++)
	{
		get_random_bytes(&seed, sizeof(int));
		flag = seed % lstr;
		if (flag < 0)
			flag = flag * -1;
		string[i] = str[flag];
	}
	string[6] = '\0';
	return string;
}

int dispatch_open(struct inode *node, struct file *file);
int dispatch_close(struct inode *node, struct file *file);
