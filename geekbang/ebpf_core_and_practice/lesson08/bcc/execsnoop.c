/* Tracing execve system call. */
// 引入内核头文件
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// 定义参数长度和参数个数常量
#define ARGSIZE 64
#define TOTAL_MAX_ARGS 5
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    int retval;
    unsigned int args_size;
    char argv[FULL_MAX_ARGS_ARR];
};
BPF_PERF_OUTPUT(events);
BPF_HASH(tasks, u32, struct data_t);

// 从用户空间读取字符串
static int __bpf_read_arg_str(struct data_t *data, const char *ptr)
{
    if (data->args_size > LAST_ARG) {
        return -1;
    }

    int ret = bpf_probe_read_user_str(&data->argv[data->args_size], ARGSIZE, (void *)ptr);
    if (ret > ARGSIZE || ret < 0) {
        return -1;
    }

    // increase the args size. the first tailing '\0' is not counted and hence it
    // would be overwritten by the next call.
    data->args_size += (ret - 1);

    return 0;
}

// 定义sys_enter_execve跟踪点处理函数.
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    // 变量定义
    unsigned int ret = 0;
    const char **argv = (const char **)(args->argv);

    // 获取进程PID和进程名称
    struct data_t data = { };
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 获取第一个参数（即可执行文件的名字）
    if (__bpf_read_arg_str(&data, (const char *)argv[0]) < 0) {
        goto out;
    }

    // 获取其他参数（限定最多5个）
    #pragma unrollfor (int i = 1; i < TOTAL_MAX_ARGS; i++) {
        if (__bpf_read_arg_str(&data, (const char *)argv[i]) < 0) {
            goto out;
        }
    }

 out:
    // 存储到哈希映射中
    tasks.update(&pid, &data);
    return 0;
}

// 定义sys_exit_execve跟踪点处理函数.
TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
    // 从哈希映射中查询进程基本信息
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t *data = tasks.lookup(&pid);

    // 填充返回值并提交到性能事件映射中
    if (data != NULL) {
        data->retval = args->ret;
        events.perf_submit(args, data, sizeof(struct data_t));

        // 最后清理进程信息
        tasks.delete(&pid);
    }

    return 0;
}