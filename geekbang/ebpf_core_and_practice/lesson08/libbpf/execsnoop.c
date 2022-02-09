// 引入脚手架头文件
#include "execsnoop.skel.h"

// 性能事件回调函数(向终端中打印进程名、PID、返回值以及参数)
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    const struct event *e = data;
    printf("%-16s %-6d %3d ", e->comm, e->pid, e->retval);
    print_args(e);
    putchar('\n');
}

// 打印参数（替换'\0'为空格）
static void print_args(const struct event *e)
{
    int args_counter = 0;

    for (int i = 0; i < e->args_size && args_counter < e->args_count; i++) {
        char c = e->args[i];
        if (c == '\0') {
            // 把'\0'替换为空格
            args_counter++;
            putchar(' ');
        } else {
            putchar(c);
        }
    }
    if (e->args_count > TOTAL_MAX_ARGS) {
        // 过长的参数输出"..."替代
        fputs(" ...", stdout);
    }
}

// C语言主函数
int main(int argc, char **argv)
{
    // 定义BPF程序和性能事件缓冲区
    struct execsnoop_bpf *skel;
    struct perf_buffer_opts pb_opts;
    struct perf_buffer *pb = NULL;
    int err;

    // 1. 设置调试输出函数
    libbpf_set_print(libbpf_print_fn);

    // 2. 增大 RLIMIT_MEMLOCK（默认值通常太小，不足以存入BPF映射的内容）
    bump_memlock_rlimit();

    // 3. 初始化BPF程序
    skel = execsnoop_bpf__open();

    // 4. 加载BPF字节码
    err = execsnoop_bpf__load(skel);

    // 5. 挂载BPF字节码到跟踪点
    err = execsnoop_bpf__attach(skel);

    // 6. 配置性能事件回调函数
    pb_opts.sample_cb = handle_event;
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, &pb_opts);

    // 7. 从缓冲区中循环读取数据
    while ((err = perf_buffer__poll(pb, 100)) >= 0) ;
}