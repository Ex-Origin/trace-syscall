#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <string.h>
#include <stddef.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/ioctl.h>

// Show more information
#ifdef DEBUG
#define DPRINTF printf
#else
#define DPRINTF(...)
#endif

/**
 * The value must be TRUE, or the program will break down.
 * e.g., the value is thing what the program need to do.
 **/
#define CHECK(value)                                            \
    {                                                           \
        if ((value) == 0)                                       \
        {                                                       \
            fprintf(stderr, "%s:%d: %m\n", __FILE__, __LINE__); \
            abort();                                            \
        }                                                       \
    }

#define TTY_WORKED  1
#define TTY_NONE 2
#define TTY_ERROR 3
int tty_status = 0;

int check_tty()
{
    int result;
    int session_id;

    result = ioctl(STDOUT_FILENO, TIOCGSID, &session_id);
    if(result != -1)
    {
        DPRINTF("[TRACE DEBUG]: TTY terminal\n");
        tty_status = TTY_WORKED;
        result = 0;
    }
    else
    {
        if(errno == ENOTTY)
        {
            DPRINTF("[TRACE DEBUG]: ENOTTY\n");
            tty_status = TTY_NONE;
            result = 0;
        }
        else
        {
            DPRINTF("[TRACE DEBUG]: Error\n");
            fprintf(stderr, "[TRACE ERROR]: ioctl %m  %s:%d\n", __FILE__, __LINE__);
            tty_status = TTY_ERROR;
            result = -1;
        }
    }
    
    return result;
}

#if (defined(TRACE_WRITE) || defined(TRACE_READ))
int handle_file_IO(int pid, struct ptrace_syscall_info *info)
{
    char path_buf[0x1000], path[0x1000], *result;
    int existed, i;
    static char **path_lists = NULL;
    static size_t node_max = 0x400, node_count = 0;

    // Initial
    if (path_lists == NULL)
    {
        path_lists = (char **)malloc(sizeof(char *) * node_max);
        CHECK(path_lists != NULL);
    }

    memset(path_buf, 0, sizeof(path_buf));
    snprintf(path_buf, sizeof(path_buf) - 1, "/proc/%d/fd/%lld", pid, info->entry.args[0]);
    memset(path, 0, sizeof(path));
    if (readlink(path_buf, path, sizeof(path) - 1) != -1)
    {
        existed = 0;
        for (i = 0; existed == 0 && i < node_count; i++)
        {
            if (strcmp(path, path_lists[i]) == 0)
            {
                existed = 1;
            }
        }
        if (existed == 0)
        {
            // Extend
            if (node_count + 1 > node_max)
            {
                result = realloc(path_lists, sizeof(char *) * node_max * 2);
                CHECK(result != NULL);
                node_max = node_max * 2;
                path_lists = (char **)result;
            }
            result = strdup(path);
            CHECK(result != NULL);
            path_lists[node_count] = result;
            node_count++;
            if(tty_status == TTY_WORKED)
            {
                printf("[TRACE INFO]: \033[1;32m%s\033[0m\n", path);
            }
            else
            {
                printf("[TRACE INFO]: %s\n", path);
            }
        }
    }
    else
    {
        fprintf(stderr, "[TRACE ERROR]: pid %5d : readlink(%s) error : %m\n", pid, path_buf);
    }

    return 0;
}
#endif

#ifdef TRACE_EXECVE
int handle_double_quotation(char *out, char *in, int size)
{
    int i = 0, j = 0;

    out[i++] = '"';
    for(j = 0; in[j] && j < size && i < size ; j++)
    {
        switch (in[j])
        {
        case '"':
            if(i < size) out[i++] = '\\';
            if(i < size) out[i++] = in[j];
            break;
        
        default:
            if(i < size) out[i++] = in[j];
            break;
        }
    }

    if(i < size)
    {
        out[i++] = '"';
    }
    else
    {
        return -1;
    }

    return 0;
}
int handle_execve(int pid, struct ptrace_syscall_info *info)
{
    char buf[0x1000];
    int fd, i, j;
    char *mem_addr, *result, chr;
    char **args_lists = NULL;
    size_t node_max = 0x400, node_count = 0;

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf) - 1, "/proc/%d/mem", pid);
    fd = open(buf, O_RDONLY);
    CHECK(fd != -1);

    // Initial
    args_lists = (char **)malloc(sizeof(char *) * node_max);
    CHECK(args_lists != NULL);

    for (i = 1, mem_addr = (char *)info->entry.args[0]; mem_addr; i++)
    {

        if (mem_addr)
        {
            memset(buf, 0, sizeof(buf));
            for (j = 0, chr = -1; chr && j < sizeof(buf) - 1; j++)
            {
                CHECK(pread(fd, &chr, sizeof(chr), (size_t)mem_addr + j * sizeof(chr)) != -1);
                buf[j] = chr;
            }

            if (node_count + 1 > node_max)
            {
                result = realloc(args_lists, sizeof(char *) * node_max * 2);
                CHECK(result != NULL);
                node_max = node_max * 2;
                args_lists = (char **)result;
            }

            if(strchr(buf, ' ') == NULL)
            {
                result = strdup(buf);
                CHECK(result != NULL);
            }
            else
            {
                result = malloc(sizeof(buf));
                CHECK(result != NULL);
                memset(result, 0, sizeof(buf));
                handle_double_quotation(result, buf, sizeof(buf));
            }

            args_lists[node_count] = result;
            node_count++;
        }

        // Next
        if (info->entry.args[1])
        {
            CHECK(pread(fd, &mem_addr, sizeof(char *), info->entry.args[1] + i * sizeof(char *)) != -1);
        }
        else
        {
            mem_addr = NULL;
        }
    }

    // Output command
    for (i = 0; i < node_count; i++)
    {
        if (node_count == 1 && i == 0) // Only one
        {
            if(tty_status == TTY_WORKED)
            {
                printf("[TRACE INFO]: \033[1;32m%s\033[0m\n", args_lists[i]);
            }
            else
            {
                printf("[TRACE INFO]: %s\n", args_lists[i]);
            }
        }
        else if (i == 0) // The head node
        {
            if(tty_status == TTY_WORKED)
            {
                printf("[TRACE INFO]: \033[1;32m%s ", args_lists[i]);
            }
            else
            {
                printf("[TRACE INFO]: %s ", args_lists[i]);
            }
        }
        else if (i + 1 == node_count) // The final node
        {
            if(tty_status == TTY_WORKED)
            {
                printf("%s\033[0m\n", args_lists[i]);
            }
            else
            {
                printf("%s\n", args_lists[i]);
            }
        }
        else // Middle nodes
        {
            printf("%s ", args_lists[i]);
        }

        free(args_lists[i]);
        args_lists[i] = NULL;
    }

    free(args_lists);
    close(fd);

    return 0;
}
#endif

int syscall_monitor(int pid, struct ptrace_syscall_info *info)
{

    switch (info->entry.nr)
    {
#ifdef TRACE_WRITE
    case SYS_write:
    case SYS_writev:
        handle_file_IO(pid, info);
        break;
#endif

#ifdef TRACE_READ
    case SYS_read:
    case SYS_readv:
        handle_file_IO(pid, info);
#endif

#ifdef TRACE_EXECVE
    case SYS_execve:
        handle_execve(pid, info);
#endif

    default:
        break;
    }
    return 0;
}

int execve_with_args(char **argv)
{
    char *env, *item;
    char buf[0x800], path[0x800];

    if (access(argv[0], X_OK) == 0)
    {
        execv(argv[0], argv);
    }

    env = getenv("PATH");
    if (env)
    {
        memset(buf, 0, sizeof(buf));
        strncpy(buf, env, sizeof(buf) - 1);

        for (item = strtok(buf, ":"); item; item = strtok(NULL, ":"))
        {
            memset(path, 0, sizeof(path));
            strncpy(path, item, sizeof(path) - 1);
            if (path[strlen(path) - 1] != '/')
            {
                strncat(path, "/", sizeof(path) - 1);
            }
            strncat(path, argv[0], sizeof(path) - 1);
            if (access(path, X_OK) == 0)
            {
                execv(path, argv);
            }
        }
    }

    fprintf(stderr, "%s:%d:%s: %m\n", __FILE__, __LINE__, "execv");
    exit(EXIT_FAILURE);

    return -1;
}

int handle_trapped_event(int pid, int wstatus)
{
    int event = wstatus >> 16;
    switch (event)
    {
    case 0:
        break;
    case PTRACE_EVENT_FORK:
        DPRINTF("[TRACE DEBUG]: pid %5d : trapped by event PTRACE_EVENT_FORK\n", pid);
        break;
    case PTRACE_EVENT_VFORK:
        DPRINTF("[TRACE DEBUG]: pid %5d : trapped by event PTRACE_EVENT_VFORK\n", pid);
        break;
    case PTRACE_EVENT_CLONE:
        DPRINTF("[TRACE DEBUG]: pid %5d : trapped by event PTRACE_EVENT_CLONE\n", pid);
        break;
    case PTRACE_EVENT_EXEC:
        DPRINTF("[TRACE DEBUG]: pid %5d : trapped by event PTRACE_EVENT_EXEC\n", pid);
        break;
    case PTRACE_EVENT_VFORK_DONE:
        DPRINTF("[TRACE DEBUG]: pid %5d : trapped by event PTRACE_EVENT_VFORK_DONE\n", pid);
        break;
    case PTRACE_EVENT_EXIT:
        DPRINTF("[TRACE DEBUG]: pid %5d : trapped by event PTRACE_EVENT_EXIT\n", pid);
        break;
    case PTRACE_EVENT_SECCOMP:
        DPRINTF("[TRACE DEBUG]: pid %5d : trapped by event PTRACE_EVENT_SECCOMP\n", pid);
        break;
    case PTRACE_EVENT_STOP:
        DPRINTF("[TRACE DEBUG]: pid %5d : trapped by event PTRACE_EVENT_STOP\n", pid);
        break;
    default:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : trapped by unknown event %d (%#x)\n", pid, event, event);
        break;
    }
    return 0;
}

int handle_syscall_info(int pid, int wstatus)
{
    struct ptrace_syscall_info info;

    for(errno = 0; ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) == -1 && errno == ESRCH;)
        ;
    if(errno != 0 && errno != ESRCH)
    {
        fprintf(stderr, "[TRACE ERROR]: pid %5d : ptrace(PTRACE_GET_SYSCALL_INFO) error: %m\n", pid);
        return -1;
    }
    
    switch (info.op)
    {
    case PTRACE_SYSCALL_INFO_NONE:
        DPRINTF("[TRACE DEBUG]: pid %5d : got info PTRACE_SYSCALL_INFO_NONE\n", pid);
        break;
    case PTRACE_SYSCALL_INFO_ENTRY:
        DPRINTF("[TRACE DEBUG]: pid %5d : got info PTRACE_SYSCALL_INFO_ENTRY\n", pid);
        syscall_monitor(pid, &info);
        break;
    case PTRACE_SYSCALL_INFO_EXIT:
        DPRINTF("[TRACE DEBUG]: pid %5d : got info PTRACE_SYSCALL_INFO_EXIT\n", pid);
        break;
    case PTRACE_SYSCALL_INFO_SECCOMP:
        DPRINTF("[TRACE DEBUG]: pid %5d : got info PTRACE_SYSCALL_INFO_SECCOMP\n", pid);
        break;
    default:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : got unknown info %d (%#x)\n", pid, info.op, info.op);
        break;
    }
    return 0;
}

int handle_stopped_signal(int pid, int wstatus)
{
    switch (WSTOPSIG(wstatus))
    {
    case SIGINT:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGINT\n", pid);
        ptrace(PTRACE_KILL, pid);
        break;
    case SIGILL:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGILL\n", pid);
        ptrace(PTRACE_KILL, pid);
        break;
    case SIGABRT:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGABRT\n", pid);
        ptrace(PTRACE_KILL, pid);
        break;
    case SIGFPE:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGFPE\n", pid);
        break;
    case SIGSEGV:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGSEGV\n", pid);
        ptrace(PTRACE_KILL, pid);
        break;
    case SIGTERM:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGTERM\n", pid);
        ptrace(PTRACE_KILL, pid);
        break;
    case SIGHUP:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGHUP\n", pid);
        break;
    case SIGQUIT:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGQUIT\n", pid);
        break;
    case SIGTRAP:
        DPRINTF("[TRACE DEBUG]: pid %5d : stopped by signal SIGTRAP\n", pid);
        handle_trapped_event(pid, wstatus);
        handle_syscall_info(pid, wstatus);
        break;
    case SIGKILL:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGKILL\n", pid);
        break;
    case SIGPIPE:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGPIPE\n", pid);
        break;
    case SIGALRM:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGALRM\n", pid);
        break;
    case SIGPOLL:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGPOLL\n", pid);
        break;
    case SIGCHLD:
        DPRINTF("[TRACE DEBUG]: pid %5d : stopped by signal SIGCHLD\n", pid);
        break;
    case SIGSTKFLT:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGSTKFLT\n", pid);
        break;
    case SIGPWR:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGPWR\n", pid);
        break;
    case SIGBUS:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGBUS\n", pid);
        break;
    case SIGSYS:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGSYS\n", pid);
        break;
    case SIGURG:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGURG\n", pid);
        break;
    case SIGSTOP:
        DPRINTF("[TRACE DEBUG]: pid %5d : stopped by signal SIGSTOP\n", pid);
        break;
    case SIGTSTP:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGTSTP\n", pid);
        break;
    case SIGCONT:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGCONT\n", pid);
        break;
    case SIGTTIN:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGTTIN\n", pid);
        break;
    case SIGTTOU:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGTTOU\n", pid);
        break;
    case SIGXFSZ:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGXFSZ\n", pid);
        break;
    case SIGXCPU:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGXCPU\n", pid);
        break;
    case SIGVTALRM:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGVTALRM\n", pid);
        break;
    case SIGPROF:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGPROF\n", pid);
        break;
    case SIGUSR1:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGUSR1\n", pid);
        break;
    case SIGUSR2:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGUSR2\n", pid);
        break;
    case SIGWINCH:
        printf("[TRACE INFO]: pid %5d : stopped by signal SIGWINCH\n", pid);
        break;
    case SIGTRAP | 0x80:
        /**
         * From ptrace(2), setting PTRACE_O_TRACESYSGOOD has the effect
         * of delivering SIGTRAP | 0x80 as the signal number for syscall
         * stops. This allows easily distinguishing syscall stops from
         * genuine SIGTRAP signals.
         **/
        DPRINTF("[TRACE DEBUG]: pid %5d : stopped by signal SIGTRAP|0x80\n", pid);
        handle_trapped_event(pid, wstatus);
        handle_syscall_info(pid, wstatus);
        break;
    default:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : stopped by unknown signal %d (%#x)\n", pid,
                WSTOPSIG(wstatus), WSTOPSIG(wstatus));
        break;
    }

    return 0;
}

int handle_killed_signal(int pid, int wstatus)
{
    switch (WTERMSIG(wstatus))
    {
    case SIGINT:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGINT\n", pid);
        break;
    case SIGILL:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGILL\n", pid);
        break;
    case SIGABRT:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGABRT\n", pid);
        break;
    case SIGFPE:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGFPE\n", pid);
        break;
    case SIGSEGV:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGSEGV\n", pid);
        break;
    case SIGTERM:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGTERM\n", pid);
        break;
    case SIGHUP:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGHUP\n", pid);
        break;
    case SIGQUIT:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGQUIT\n", pid);
        break;
    case SIGTRAP:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGTRAP\n", pid);
        break;
    case SIGKILL:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGKILL\n", pid);
        break;
    case SIGPIPE:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGPIPE\n", pid);
        break;
    case SIGALRM:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGALRM\n", pid);
        break;
    case SIGPOLL:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGPOLL\n", pid);
        break;
    case SIGCHLD:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGCHLD\n", pid);
        break;
    case SIGSTKFLT:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGSTKFLT\n", pid);
        break;
    case SIGPWR:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGPWR\n", pid);
        break;
    case SIGBUS:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGBUS\n", pid);
        break;
    case SIGSYS:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGSYS\n", pid);
        break;
    case SIGURG:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGURG\n", pid);
        break;
    case SIGSTOP:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGSTOP\n", pid);
        break;
    case SIGTSTP:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGTSTP\n", pid);
        break;
    case SIGCONT:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGCONT\n", pid);
        break;
    case SIGTTIN:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGTTIN\n", pid);
        break;
    case SIGTTOU:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGTTOU\n", pid);
        break;
    case SIGXFSZ:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGXFSZ\n", pid);
        break;
    case SIGXCPU:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGXCPU\n", pid);
        break;
    case SIGVTALRM:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGVTALRM\n", pid);
        break;
    case SIGPROF:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGPROF\n", pid);
        break;
    case SIGUSR1:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGUSR1\n", pid);
        break;
    case SIGUSR2:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGUSR2\n", pid);
        break;
    case SIGWINCH:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal SIGWINCH\n", pid);
        break;
    default:
        fprintf(stderr, "[TRACE ERROR]: pid %5d : killed by signal %d (%#x)\n", pid, WTERMSIG(wstatus), WTERMSIG(wstatus));
        break;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int pid, wstatus, i, result;
    char *result_ptr;
    int newpid;
#define MAXPATH 0x1000
    char *path_buf, *path;
    size_t point_max = 0x400, point_count = 0;
    char **point;

    check_tty();
    setlinebuf(stdout);

    if (argc < 2)
    {
        printf("Usage: %s command\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    path_buf = malloc(MAXPATH);
    CHECK(path_buf != NULL);
    path = malloc(MAXPATH);
    CHECK(path != NULL);

    CHECK((pid = fork()) != -1);

    // Child process
    if (pid == 0)
    {
        CHECK(prctl(PR_SET_PTRACER, getppid()) != -1);
        raise(SIGSTOP);

        DPRINTF("[TRACE DEBUG]: Child pid %d\n", getpid());
        return execve_with_args(argv + 1);
    }

    point = malloc(sizeof(char *) * point_max);
    CHECK(point != NULL);

    CHECK(ptrace(PTRACE_SEIZE, pid, NULL,
                 PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD |
                     PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                     PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                     PTRACE_O_TRACEEXIT) != -1);

    for (wstatus = 0; pid != -1; wstatus = 0)
    {
        if(ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
        {
            // Wait 
            CHECK(errno == ESRCH);
        }

        pid = wait(&wstatus);
        
        if (WIFEXITED(wstatus))
        {
            DPRINTF("[TRACE DEBUG]: pid %5d : exited, status=%d\n", pid, WEXITSTATUS(wstatus));
        }
        else if (WIFSIGNALED(wstatus))
        {
            handle_killed_signal(pid, wstatus);
        }
        else if (WIFSTOPPED(wstatus))
        {
            handle_stopped_signal(pid, wstatus);
        }
        else if (WIFCONTINUED(wstatus))
        {
            DPRINTF("[TRACE DEBUG]: pid %5d : continued\n", pid);
        }
    }

    return 0;
}
