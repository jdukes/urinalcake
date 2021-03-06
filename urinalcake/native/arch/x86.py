#!/usr/bin/env python
import ctypes

SYSCALL_NUM = "orig_eax"
SYSCALL_ARG_REGS = ["ebx", "ecx", "edx", "esx", "edi"]
FPREGS_FIELDS = (
    ("cwd", ctypes.c_long),
    ("swd", ctypes.c_long),
    ("twd", ctypes.c_long),
    ("fip", ctypes.c_long),
    ("fcs", ctypes.c_long),
    ("foo", ctypes.c_long),
    ("fos", ctypes.c_long),
    ("st_space", ctypes.c_long * 20))
REGS_FIELDS = (
    ("ebx", ctypes.c_long),
    ("ecx", ctypes.c_long),
    ("edx", ctypes.c_long),
    ("esi", ctypes.c_long),
    ("edi", ctypes.c_long),
    ("ebp", ctypes.c_long),
    ("eax", ctypes.c_long),
    ("xds", ctypes.c_long),
    ("xes", ctypes.c_long),
    ("xfs", ctypes.c_long),
    ("xgs", ctypes.c_long),
    ("orig_eax", ctypes.c_long),
    ("eip", ctypes.c_long),
    ("xcs", ctypes.c_long),
    ("eflags", ctypes.c_long),
    ("esp", ctypes.c_long),
    ("xss", ctypes.c_long))
SYSCALL_TABLE = [{'args': ['int'], 'name': 'sys_exit', 'number': '1'},
                 {'args': ['struct pt_regs'],
                  'name': 'sys_fork',
                  'number': '2'},
                 {'args': ['unsigned int', 'char *', 'size_t'],
                  'name': 'sys_read',
                  'number': '3'},
                 {'args': ['unsigned int', 'const char *', 'size_t'],
                  'name': 'sys_write',
                  'number': '4'},
                 {'args': ['const char *', 'int', 'int'],
                  'name': 'sys_open',
                  'number': '5'},
                 {'args': ['unsigned int'],
                  'name': 'sys_close',
                  'number': '6'},
                 {'args': ['pid_t', 'unsigned int *', 'int'],
                  'name': 'sys_waitpid',
                  'number': '7'},
                 {'args': ['const char *', 'int'],
                  'name': 'sys_creat',
                  'number': '8'},
                 {'args': ['const char *', 'const char *'],
                  'name': 'sys_link',
                  'number': '9'},
                 {'args': ['const char *'],
                  'name': 'sys_unlink',
                  'number': '10'},
                 {'args': ['struct pt_regs'],
                  'name': 'sys_execve',
                  'number': '11'},
                 {'args': ['const char *'],
                  'name': 'sys_chdir',
                  'number': '12'},
                 {'args': ['int *'], 'name': 'sys_time', 'number': '13'},
                 {'args': ['const char *', 'int', 'dev_t'],
                  'name': 'sys_mknod',
                  'number': '14'},
                 {'args': ['const char *', 'mode_t'],
                  'name': 'sys_chmod',
                  'number': '15'},
                 {'args': ['const char *', 'uid_t', 'gid_t'],
                  'name': 'sys_lchown',
                  'number': '16'},
                 {'args': ['char *', 'struct __old_kernel_stat *'],
                  'name': 'sys_stat',
                  'number': '18'},
                 {'args': ['unsigned int', 'off_t', 'unsigned int'],
                  'name': 'sys_lseek',
                  'number': '19'},
                 {'args': [], 'name': 'sys_getpid', 'number': '20'},
                 {'args': ['char *', 'char *', 'char *'],
                  'name': 'sys_mount',
                  'number': '21'},
                 {'args': ['char *'], 'name': 'sys_oldumount', 'number': '22'},
                 {'args': ['uid_t'], 'name': 'sys_setuid', 'number': '23'},
                 {'args': [], 'name': 'sys_getuid', 'number': '24'},
                 {'args': ['int *'], 'name': 'sys_stime', 'number': '25'},
                 {'args': ['long', 'long', 'long', 'long'],
                  'name': 'sys_ptrace',
                  'number': '26'},
                 {'args': ['unsigned int'], 'name': 'sys_alarm', 'number': '27'},
                 {'args': ['unsigned int', 'struct __old_kernel_stat *'],
                  'name': 'sys_fstat',
                  'number': '28'},
                 {'args': [], 'name': 'sys_pause', 'number': '29'},
                 {'args': ['char *', 'struct utimbuf *'],
                  'name': 'sys_utime',
                  'number': '30'},
                 {'args': ['const char *', 'int'],
                  'name': 'sys_access',
                  'number': '33'},
                 {'args': ['int'], 'name': 'sys_nice', 'number': '34'},
                 {'args': [], 'name': 'sys_sync', 'number': '36'},
                 {'args': ['int', 'int'], 'name': 'sys_kill', 'number': '37'},
                 {'args': ['const char *', 'const char *'],
                  'name': 'sys_rename',
                  'number': '38'},
                 {'args': ['const char *', 'int'],
                  'name': 'sys_mkdir',
                  'number': '39'},
                 {'args': ['const char *'],
                  'name': 'sys_rmdir',
                  'number': '40'},
                 {'args': ['unsigned int'],
                  'name': 'sys_dup',
                  'number': '41'},
                 {'args': ['unsigned long *'],
                  'name': 'sys_pipe',
                  'number': '42'},
                 {'args': ['struct tms *'],
                  'name': 'sys_times',
                  'number': '43'},
                 {'args': ['unsigned long'],
                  'name': 'sys_brk',
                  'number': '45'},
                 {'args': ['gid_t'], 'name': 'sys_setgid', 'number': '46'},
                 {'args': [], 'name': 'sys_getgid', 'number': '47'},
                 {'args': ['int', '__sighandler_t'],
                  'name': 'sys_signal',
                  'number': '48'},
                 {'args': [], 'name': 'sys_geteuid', 'number': '49'},
                 {'args': [], 'name': 'sys_getegid', 'number': '50'},
                 {'args': ['const char *'], 'name': 'sys_acct', 'number': '51'},
                 {'args': ['char *', 'int'], 
                  'name': 'sys_umount', 
                  'number': '52'},
                 {'args': ['unsigned int', 'unsigned int', 'unsigned long'],
                  'name': 'sys_ioctl',
                  'number': '54'},
                 {'args': ['unsigned int', 'unsigned int', 'unsigned long'],
                  'name': 'sys_fcntl',
                  'number': '55'},
                 {'args': ['pid_t', 'pid_t'], 
                  'name': 'sys_setpgid', 
                  'number': '57'},
                 {'args': ['struct oldold_utsname *'], 
                  'name': 'sys_olduname', 
                  'number': '59'},
                 {'args': ['int'], 'name': 'sys_umask', 'number': '60'},
                 {'args': ['const char *'], 
                  'name': 'sys_chroot', 
                  'number': '61'},
                 {'args': ['dev_t', 'struct ustat *'], 
                  'name': 'sys_ustat', 
                  'number': '62'},
                 {'args': ['unsigned int', 'unsigned int'],
                  'name': 'sys_dup2',
                  'number': '63'},
                 {'args': [], 'name': 'sys_getppid', 'number': '64'},
                 {'args': [], 'name': 'sys_getpgrp', 'number': '65'},
                 {'args': [], 'name': 'sys_setsid', 'number': '66'},
                 {'args': ['int', 
                           'const struct old_sigaction *',
                           'struct old_sigaction *'],
                  'name': 'sys_sigaction',
                  'number': '67'},
                 {'args': [], 'name': 'sys_sgetmask', 'number': '68'},
                 {'args': ['int'], 'name': 'sys_ssetmask', 'number': '69'},
                 {'args': ['uid_t', 'uid_t'], 
                  'name': 'sys_setreuid', 
                  'number': '70'},
                 {'args': ['gid_t', 'gid_t'], 
                  'name': 'sys_setregid', 
                  'number': '71'},
                 {'args': ['int', 'int', 'old_sigset_t'],
                  'name': 'sys_sigsuspend',
                  'number': '72'},
                 {'args': ['old_sigset_t *'], 
                  'name': 'sys_sigpending', 
                  'number': '73'},
                 {'args': ['char *', 'int'], 
                  'name': 'sys_sethostname', 
                  'number': '74'},
                 {'args': ['unsigned int', 'struct rlimit *'],
                  'name': 'sys_setrlimit',
                  'number': '75'},
                 {'args': ['unsigned int', 'struct rlimit *'],
                  'name': 'sys_getrlimit',
                  'number': '76'},
                 {'args': ['int', 'struct rusage *'], 
                  'name': 'sys_getrusage', 
                  'number': '77'},
                 {'args': ['struct timeval *', 'struct timezone *'],
                  'name': 'sys_gettimeofday',
                  'number': '78'},
                 {'args': ['struct timeval *', 'struct timezone *'],
                  'name': 'sys_settimeofday',
                  'number': '79'},
                 {'args': ['int', 'gid_t *'], 
                  'name': 'sys_getgroups', 
                  'number': '80'},
                 {'args': ['int', 'gid_t *'], 
                  'name': 'sys_setgroups', 
                  'number': '81'},
                 {'args': ['struct sel_arg_struct *'], 
                  'name': 'old_select', 
                  'number': '82'},
                 {'args': ['const char *', 'const char *'],
                  'name': 'sys_symlink',
                  'number': '83'},
                 {'args': ['char *', 'struct __old_kernel_stat *'],
                  'name': 'sys_lstat',
                  'number': '84'},
                 {'args': ['const char *', 'char *', 'int'],
                  'name': 'sys_readlink',
                  'number': '85'},
                 {'args': ['const char *'], 
                  'name': 'sys_uselib', 
                  'number': '86'},
                 {'args': ['const char *', 'int'], 
                  'name': 'sys_swapon', 
                  'number': '87'},
                 {'args': ['int', 'int', 'int', 'void *'],
                  'name': 'sys_reboot',
                  'number': '88'},
                 {'args': ['unsigned int', 'void *', 'unsigned int'],
                  'name': 'old_readdir',
                  'number': '89'},
                 {'args': ['struct mmap_arg_struct *'], 
                  'name': 'old_mmap', 
                  'number': '90'},
                 {'args': ['unsigned long', 'size_t'], 
                  'name': 'sys_munmap', 
                  'number': '91'},
                 {'args': ['const char *', 'unsigned long'],
                  'name': 'sys_truncate',
                  'number': '92'},
                 {'args': ['unsigned int', 'unsigned long'],
                  'name': 'sys_ftruncate',
                  'number': '93'},
                 {'args': ['unsigned int', 'mode_t'], 
                  'name': 'sys_fchmod', 
                  'number': '94'},
                 {'args': ['unsigned int', 'uid_t', 'gid_t'],
                  'name': 'sys_fchown',
                  'number': '95'},
                 {'args': ['int', 'int'], 
                  'name': 'sys_getpriority', 
                  'number': '96'},
                 {'args': ['int', 'int', 'int'], 
                  'name': 'sys_setpriority', 
                  'number': '97'},
                 {'args': ['const char *', 'struct statfs *'],
                  'name': 'sys_statfs',
                  'number': '99'},
                 {'args': ['unsigned int', 'struct statfs *'],
                  'name': 'sys_fstatfs',
                  'number': '100'},
                 {'args': ['unsigned long', 'unsigned long', 'int'],
                  'name': 'sys_ioperm',
                  'number': '101'},
                 {'args': ['int', 'unsigned long *'],
                  'name': 'sys_socketcall',
                  'number': '102'},
                 {'args': ['int', 'char *', 'int'], 
                  'name': 'sys_syslog', 
                  'number': '103'},
                 {'args': ['int', 'struct itimerval *', 'struct itimerval *'],
                  'name': 'sys_setitimer',
                  'number': '104'},
                 {'args': ['int', 'struct itimerval *'],
                  'name': 'sys_getitimer',
                  'number': '105'},
                 {'args': ['char *', 'struct stat *'], 
                  'name': 'sys_newstat', 
                  'number': '106'},
                 {'args': ['char *', 'struct stat *'],
                  'name': 'sys_newlstat',
                  'number': '107'},
                 {'args': ['unsigned int', 'struct stat *'],
                  'name': 'sys_newfstat',
                  'number': '108'},
                 {'args': ['struct old_utsname *'], 
                  'name': 'sys_uname', 
                  'number': '109'},
                 {'args': ['unsigned long'], 
                  'name': 'sys_iopl', 
                  'number': '110'},
                 {'args': [], 'name': 'sys_vhangup', 'number': '111'},
                 {'args': [], 'name': 'sys_idle', 'number': '112'},
                 {'args': ['unsigned long', 'struct vm86plus_struct *'],
                  'name': 'sys_vm86old',
                  'number': '113'},
                 {'args': ['pid_t', 
                           'unsigned long *',
                           'int options', 
                           'struct rusage *'],
                  'name': 'sys_wait4',
                  'number': '114'},
                 {'args': ['const char *'], 
                  'name': 'sys_swapoff', 
                  'number': '115'},
                 {'args': ['struct sysinfo *'], 
                  'name': 'sys_sysinfo', 
                  'number': '116'},
                 {'args': ['uint', 'int', 'int', 'int', 'void *'],
                  'name': 'sys_ipc ',
                  'number': '117'},
                 {'args': ['unsigned int'], 
                  'name': 'sys_fsync', 
                  'number': '118'},
                 {'args': ['unsigned long'], 
                  'name': 'sys_sigreturn', 
                  'number': '119'},
                 {'args': ['struct pt_regs'], 
                  'name': 'sys_clone', 
                  'number': '120'},
                 {'args': ['char *', 'int'], 
                  'name': 'sys_setdomainname', 
                  'number': '121'},
                 {'args': ['struct new_utsname *'], 
                  'name': 'sys_newuname', 
                  'number': '122'},
                 {'args': ['int', 'void *', 'unsigned long'],
                  'name': 'sys_modify_ldt',
                  'number': '123'},
                 {'args': ['struct timex *'], 'name': 'sys_adjtimex', 'number': '124'},
                 {'args': ['unsigned long', 'size_t', 'unsigned long'],
                  'name': 'sys_mprotect',
                  'number': '125'},
                 {'args': ['int', 'old_sigset_t *', 'old_sigset_t *'],
                  'name': 'sys_sigprocmask',
                  'number': '126'},
                 {'args': ['const char *', 'size_t'],
                  'name': 'sys_create_module',
                  'number': '127'},
                 {'args': ['const char *', 'struct module *'],
                  'name': 'sys_init_module',
                  'number': '128'},
                 {'args': ['const char *'],
                  'name': 'sys_delete_module', 
                  'number': '129'},
                 {'args': ['struct kernel_sym *'],
                  'name': 'sys_get_kernel_syms',
                  'number': '130'},
                 {'args': ['int', 'const char *', 'int', 'caddr_t'],
                  'name': 'sys_quotactl',
                  'number': '131'},
                 {'args': ['pid_t'], 'name': 'sys_getpgid', 'number': '132'},
                 {'args': ['unsigned int'], 
                  'name': 'sys_fchdir', 
                  'number': '133'},
                 {'args': ['int', 'long'],
                  'name': 'sys_bdflush', 
                  'number': '134'},
                 {'args': ['int', 'unsigned long', 'unsigned long'],
                  'name': 'sys_sysfs',
                  'number': '135'},
                 {'args': ['unsigned long'], 
                  'name': 'sys_personality', 
                  'number': '136'},
                 {'args': ['uid_t'], 'name': 'sys_setfsuid', 'number': '138'},
                 {'args': ['gid_t'], 'name': 'sys_setfsgid', 'number': '139'},
                 {'args': ['unsigned int',
                           'unsigned long',
                           'unsigned long',
                           'loff_t *',
                           'unsigned int'],
                  'name': 'sys_llseek',
                  'number': '140'},
                 {'args': ['unsigned int', 'void *', 'unsigned int'],
                  'name': 'sys_getdents',
                  'number': '141'},
                 {'args': ['int', 
                           'fd_set *', 
                           'fd_set *', 
                           'fd_set *', 
                           'struct timeval *'],
                  'name': 'sys_select',
                  'number': '142'},
                 {'args': ['unsigned int', 'unsigned int'],
                  'name': 'sys_flock',
                  'number': '143'},
                 {'args': ['unsigned long', 'size_t', 'int'],
                  'name': 'sys_msync',
                  'number': '144'},
                 {'args': ['unsigned long', 
                           'const struct iovec *', 
                           'unsigned long'],
                  'name': 'sys_readv',
                  'number': '145'},
                 {'args': ['unsigned long',
                           'const struct iovec *',
                           'unsigned long'],
                  'name': 'sys_writev',
                  'number': '146'},
                 {'args': ['pid_t'], 
                  'name': 'sys_getsid', 
                  'number': '147'},
                 {'args': ['unsigned int'], 
                  'name': 'sys_fdatasync', 
                  'number': '148'},
                 {'args': ['struct __sysctl_args *'], 
                  'name': 'sys_sysctl', 'number': '149'},
                 {'args': ['unsigned long', 'size_t'], 
                  'name': 'sys_mlock',
                  'number': '150'},
                 {'args': ['unsigned long', 'size_t'], 
                  'name': 'sys_munlock', 
                  'number': '151'},
                 {'args': ['int'], 'name': 'sys_mlockall', 'number': '152'},
                 {'args': [], 'name': 'sys_munlockall', 'number': '153'},
                 {'args': ['pid_t', 'struct sched_param *'],
                  'name': 'sys_sched_setparam',
                  'number': '154'},
                 {'args': ['pid_t', 'struct sched_param *'],
                  'name': 'sys_sched_getparam',
                  'number': '155'},
                 {'args': ['pid_t', 'int', 'struct sched_param *'],
                  'name': 'sys_sched_setscheduler',
                  'number': '156'},
                 {'args': ['pid_t'], 
                  'name': 'sys_sched_getscheduler',
                  'number': '157'},
                 {'args': [], 'name': 'sys_sched_yield',
                  'number': '158'},
                 {'args': ['int'], 
                  'name': 'sys_sched_get_priority_max',
                  'number': '159'},
                 {'args': ['int'], 
                  'name': 'sys_sched_get_priority_min',
                  'number': '160'},
                 {'args': ['pid_t', 'struct timespec *'],
                  'name': 'sys_sched_rr_get_interval',
                  'number': '161'},
                 {'args': ['struct timespec *', 
                           'struct timespec *'],
                  'name': 'sys_nanosleep',
                  'number': '162'},
                 {'args': ['unsigned long', 
                           'unsigned long', 
                           'unsigned long', 
                           'unsigned long'],
                  'name': 'sys_mremap',
                  'number': '163'},
                 {'args': ['uid_t', 'uid_t', 'uid_t'],
                  'name': 'sys_setresuid',
                  'number': '164'},
                 {'args': ['uid_t *', 'uid_t *', 'uid_t *'],
                  'name': 'sys_getresuid',
                  'number': '165'},
                 {'args': ['struct vm86_struct *'], 
                  'name': 'sys_vm86', 
                  'number': '166'},
                 {'args': ['const char *', 
                           'int', 'char *', 
                           'size_t', 
                           'size_t *'],
                  'name': 'sys_query_module',
                  'number': '167'},
                 {'args': ['struct pollfd *', 'unsigned int', 'long'],
                  'name': 'sys_poll',
                  'number': '168'},
                 {'args': ['int', 'void *', 'void *'],
                  'name': 'sys_nfsservctl',
                  'number': '169'},
                 {'args': ['gid_t', 'gid_t', 'gid_t'],
                  'name': 'sys_setresgid',
                  'number': '170'},
                 {'args': ['gid_t *', 'gid_t *', 'gid_t *'],
                  'name': 'sys_getresgid',
                  'number': '171'},
                 {'args': ['int',
                           'unsigned long',
                           'unsigned long',
                           'unsigned long',
                           'unsigned long'],
                  'name': 'sys_prctl',
                  'number': '172'},
                 {'args': ['unsigned long'], 
                  'name': 'sys_rt_sigreturn', 'number': '173'},
                 {'args': ['int', 
                           'const struct sigaction *', 
                           'struct sigaction *', 
                           'size_t'],
                  'name': 'sys_rt_sigaction',
                  'number': '174'},
                 {'args': ['int', 'sigset_t *', 'sigset_t *', 'size_t'],
                  'name': 'sys_rt_sigprocmask',
                  'number': '175'},
                 {'args': ['sigset_t *', 'size_t'],
                  'name': 'sys_rt_sigpending',
                  'number': '176'},
                 {'args': ['const sigset_t *',
                           'siginfo_t *',
                           'const struct timespec *',
                           'size_t'],
                  'name': 'sys_rt_sigtimedwait',
                  'number': '177'},
                 {'args': ['int', 'int', 'siginfo_t *'],
                  'name': 'sys_rt_sigqueueinfo',
                  'number': '178'},
                 {'args': ['sigset_t *', 'size_t'],
                  'name': 'sys_rt_sigsuspend',
                  'number': '179'},
                 {'args': ['unsigned int', 'char *', 'size_t', 'loff_t'],
                  'name': 'sys_pread',
                  'number': '180'},
                 {'args': ['unsigned int', 'const char *', 'size_t', 'loff_t'],
                  'name': 'sys_pwrite',
                  'number': '181'},
                 {'args': ['const char *', 'uid_t', 'gid_t'],
                  'name': 'sys_chown',
                  'number': '182'},
                 {'args': ['char *', 'unsigned long'], 
                  'name': 'sys_getcwd', 'number': '183'},
                 {'args': ['cap_user_header_t', 'cap_user_data_t'],
                  'name': 'sys_capget',
                  'number': '184'},
                 {'args': ['cap_user_header_t', 'const cap_user_data_t'],
                  'name': 'sys_capset',
                  'number': '185'},
                 {'args': ['const stack_t *', 'stack_t *'],
                  'name': 'sys_sigaltstack',
                  'number': '186'},
                 {'args': ['int', 'int', 'off_t *', 'size_t'],
                  'name': 'sys_sendfile',
                  'number': '187'},
                 {'args': ['struct pt_regs'], 
                  'name': 'sys_vfork', 'number': '190'}]

