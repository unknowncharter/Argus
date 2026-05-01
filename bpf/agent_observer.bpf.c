// SPDX-License-Identifier: MIT

#ifndef __BPF_TYPES__
#define __BPF_TYPES__
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
#endif

#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif

struct pt_regs {
	unsigned long r15; unsigned long r14; unsigned long r13; unsigned long r12;
	unsigned long rbp; unsigned long rbx; unsigned long r11; unsigned long r10;
	unsigned long r9;  unsigned long r8;  unsigned long rax; unsigned long rcx;
	unsigned long rdx; unsigned long rsi; unsigned long rdi; unsigned long orig_rax;
	unsigned long rip; unsigned long cs; unsigned long eflags; unsigned long rsp;
	unsigned long ss;
};

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "agent_observer.h"

#define AF_INET  2
#define AF_INET6 10

/* Maps */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} interesting_pids SEC(".maps");

struct ssl_read_ctx_val {
	__u64 buf_ptr;
	__u64 readbytes_ptr;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u32);
	__type(value, struct ssl_read_ctx_val);
} ssl_read_ctx SEC(".maps");

/* pipe()/pipe2() enter: remember user fds pointer per tid for exit */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} pipe_args SEC(".maps");

/* openat_enter stores path by tid for openat_exit */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, char[MAX_PATH]);
} openat_path SEC(".maps");

/* path by tid for statx / faccessat / unlinkat (enter stores, exit emits) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, char[MAX_PATH]);
} statx_path SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, char[MAX_PATH]);
} faccessat_path SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, char[MAX_PATH]);
} unlinkat_path SEC(".maps");

/* read/write/dup/dup2 enter stores fd (or oldfd) by tid for exit */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u32);
} syscall_fd SEC(".maps");

/* getaddrinfo entry: tid -> hostname (for uretprobe to emit pid,hostname,ip) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, __u32);
	__type(value, char[MAX_HOSTNAME]);
} getaddrinfo_hostname SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 4096);
} events SEC(".maps");

static __always_inline __u32 get_pid(void)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	return (__u32)(pid_tgid >> 32);
}

static __always_inline __u32 get_tid(void)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	return (__u32)pid_tgid;
}

static __always_inline int is_interesting(__u32 pid)
{
	return bpf_map_lookup_elem(&interesting_pids, &pid) != NULL;
}

static __always_inline void add_interesting(__u32 pid)
{
	__u8 one = 1;
	bpf_map_update_elem(&interesting_pids, &pid, &one, BPF_ANY);
}

static __always_inline void remove_interesting(__u32 pid)
{
	bpf_map_delete_elem(&interesting_pids, &pid);
}

static __always_inline void *reserve_event(__u32 type, __u32 size)
{
	__u32 total = sizeof(__u32) * 2 + size;
	void *p = bpf_ringbuf_reserve(&events, total, 0);
	if (!p)
		return NULL;
	*(__u32 *)p = type;
	*(__u32 *)(p + 4) = size;
	return p + 8;
}

static __always_inline void submit_event(void *p)
{
	bpf_ringbuf_submit(p - 8, 0);
}

/* sched_process_fork: 8-byte common header then parent_pid at 12, child_pid at 20 (see tracepoint format). */
#define SCHED_FORK_OFF_PARENT_PID 12
#define SCHED_FORK_OFF_CHILD_PID  20

SEC("tracepoint/sched/sched_process_fork")
int tp_sched_process_fork(void *ctx)
{
	__u32 parent_pid = 0;
	__u32 child_pid = 0;
	bpf_probe_read_kernel(&parent_pid, sizeof(parent_pid), (void *)ctx + SCHED_FORK_OFF_PARENT_PID);
	bpf_probe_read_kernel(&child_pid, sizeof(child_pid), (void *)ctx + SCHED_FORK_OFF_CHILD_PID);
	__u64 ts = bpf_ktime_get_ns();

	if (is_interesting(parent_pid) && child_pid != 0)
		add_interesting(child_pid);

	struct fork_event *ev = reserve_event(EVENT_FORK, sizeof(*ev));
	if (!ev)
		return 0;
	ev->parent_pid = parent_pid;
	ev->child_pid = child_pid;
	ev->ts_ns = ts;
	bpf_probe_read_kernel(ev->ctx_dump, 64, ctx);
	submit_event(ev);
	return 0;
}

#define TP_EXEC_OFF_PID  12

SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(void *ctx)
{
	__u32 pid = 0;
	bpf_probe_read_kernel(&pid, sizeof(pid), (void *)ctx + TP_EXEC_OFF_PID);
	if (!is_interesting(pid))
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	struct exec_event *ev = reserve_event(EVENT_EXEC, sizeof(*ev));
	if (!ev)
		return 0;
	ev->pid = pid;
	ev->ts_ns = ts;
	__builtin_memset(ev->comm, 0, sizeof(ev->comm));
	submit_event(ev);
	return 0;
}

#define TP_EXIT_OFF_PID  24

SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(void *ctx)
{
	__u32 pid = 0;
	bpf_probe_read_kernel(&pid, sizeof(pid), (void *)ctx + TP_EXIT_OFF_PID);
	if (!is_interesting(pid))
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	struct exit_event *ev = reserve_event(EVENT_EXIT, sizeof(*ev));
	if (!ev)
		return 0;
	ev->pid = pid;
	ev->exit_code = 0; /* tracepoint does not expose exit code */
	ev->ts_ns = ts;
	submit_event(ev);
	remove_interesting(pid);
	return 0;
}

#define TP_CONNECT_OFF_ARGS1  24

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_sys_enter_connect(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;

	__u64 addr = 0;
	bpf_probe_read_kernel(&addr, sizeof(addr), (void *)ctx + TP_CONNECT_OFF_ARGS1);
	__u16 family = 0;
	bpf_probe_read_user(&family, sizeof(family), (void *)(long)addr);
	int valid_addr = (family == AF_INET || family == AF_INET6);
	if (!valid_addr)
		family = AF_INET;

	__u64 ts = bpf_ktime_get_ns();
	struct connect_event *ev = reserve_event(EVENT_CONNECT, sizeof(*ev));
	if (!ev)
		return 0;
	ev->pid = pid;
	ev->family = family;
	ev->ts_ns = ts;
	__builtin_memset(ev->dst_ip4, 0, sizeof(ev->dst_ip4));
	__builtin_memset(ev->dst_ip6, 0, sizeof(ev->dst_ip6));

	if (valid_addr && addr) {
		if (family == AF_INET) {
			__u16 port_be;
			bpf_probe_read_user(&port_be, sizeof(port_be), (void *)(long)addr + 2);
			ev->dst_port = ((port_be >> 8) & 0xff) | ((port_be & 0xff) << 8);
			bpf_probe_read_user(ev->dst_ip4, 4, (void *)(long)addr + 4);
		} else {
			__u16 port_be;
			bpf_probe_read_user(&port_be, sizeof(port_be), (void *)(long)addr + 2);
			ev->dst_port = ((port_be >> 8) & 0xff) | ((port_be & 0xff) << 8);
			bpf_probe_read_user(ev->dst_ip6, 16, (void *)(long)addr + 8);
		}
	}
	submit_event(ev);
	return 0;
}

/* Signal syscalls: capture when sender sends a signal to a target PID. */
#define SIGNAL_ARGS0 16
#define SIGNAL_ARGS1 24
#define SIGNAL_ARGS2 32

SEC("tracepoint/syscalls/sys_enter_kill")
int tp_sys_enter_kill(void *ctx)
{
	__u32 sender_pid = get_pid();
	if (!is_interesting(sender_pid))
		return 0;

	__u64 target_pid = 0;
	bpf_probe_read_kernel(&target_pid, sizeof(target_pid), (void *)ctx + SIGNAL_ARGS0);

	__s32 sig = 0;
	bpf_probe_read_kernel(&sig, sizeof(sig), (void *)ctx + SIGNAL_ARGS1);

	if (target_pid == 0)
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	struct signal_event *ev = reserve_event(EVENT_SIGNAL, sizeof(*ev));
	if (!ev)
		return 0;
	ev->sender_pid = sender_pid;
	ev->target_pid = (__u32)target_pid;
	ev->signal = sig;
	ev->ts_ns = ts;
	submit_event(ev);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int tp_sys_enter_tgkill(void *ctx)
{
	__u32 sender_pid = get_pid();
	if (!is_interesting(sender_pid))
		return 0;

	/* tgkill(tgid, tid, sig) -> we store tgid as target_pid */
	__u64 target_pid = 0;
	bpf_probe_read_kernel(&target_pid, sizeof(target_pid), (void *)ctx + SIGNAL_ARGS0);

	__s32 sig = 0;
	bpf_probe_read_kernel(&sig, sizeof(sig), (void *)ctx + SIGNAL_ARGS2);

	if (target_pid == 0)
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	struct signal_event *ev = reserve_event(EVENT_SIGNAL, sizeof(*ev));
	if (!ev)
		return 0;
	ev->sender_pid = sender_pid;
	ev->target_pid = (__u32)target_pid;
	ev->signal = sig;
	ev->ts_ns = ts;
	submit_event(ev);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int tp_sys_enter_tkill(void *ctx)
{
	__u32 sender_pid = get_pid();
	if (!is_interesting(sender_pid))
		return 0;

	/* tkill(tid, sig) -> we treat tid as target_pid */
	__u64 target_pid = 0;
	bpf_probe_read_kernel(&target_pid, sizeof(target_pid), (void *)ctx + SIGNAL_ARGS0);

	__s32 sig = 0;
	bpf_probe_read_kernel(&sig, sizeof(sig), (void *)ctx + SIGNAL_ARGS1);

	if (target_pid == 0)
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	struct signal_event *ev = reserve_event(EVENT_SIGNAL, sizeof(*ev));
	if (!ev)
		return 0;
	ev->sender_pid = sender_pid;
	ev->target_pid = (__u32)target_pid;
	ev->signal = sig;
	ev->ts_ns = ts;
	submit_event(ev);
	return 0;
}

/* Capture first and last 2048 bytes so we cover both headers and tail (user msg / tool call) within 4096. */
#define SNIPPET_HEAD_TAIL_HALF 2048

SEC("uprobe/SSL_write")
int uprobe_SSL_write(struct pt_regs *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;

	__u64 buf = PT_REGS_PARM2(ctx);
	__u64 num = PT_REGS_PARM3(ctx);
	__u32 head_len = (__u32)(num <= SNIPPET_HEAD_TAIL_HALF ? num : SNIPPET_HEAD_TAIL_HALF);
	__u32 tail_len = 0;
	__u64 tail_start = 0;
	if (num > SNIPPET_HEAD_TAIL_HALF) {
		tail_len = (__u32)(num - SNIPPET_HEAD_TAIL_HALF);
		if (tail_len > SNIPPET_HEAD_TAIL_HALF)
			tail_len = SNIPPET_HEAD_TAIL_HALF;
		tail_start = num - tail_len;
	}
	if (head_len == 0)
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	struct ssl_event *ev = reserve_event(EVENT_SSL, sizeof(*ev));
	if (!ev)
		return 0;
	ev->pid = pid;
	ev->tid = get_tid();
	ev->ts_ns = ts;
	ev->direction = 1;
	ev->nbytes = (__u32)num;
	ev->snippet_len = head_len + tail_len;
	bpf_probe_read_user(ev->snippet, head_len, (void *)(long)buf);
	if (tail_len > 0)
		bpf_probe_read_user(ev->snippet + head_len, tail_len, (void *)(long)(buf + tail_start));
	submit_event(ev);
	return 0;
}

SEC("uprobe/SSL_write_ex")
int uprobe_SSL_write_ex(struct pt_regs *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;

	__u64 buf = PT_REGS_PARM2(ctx);
	__u64 num = PT_REGS_PARM3(ctx);
	__u32 head_len = (__u32)(num <= SNIPPET_HEAD_TAIL_HALF ? num : SNIPPET_HEAD_TAIL_HALF);
	__u32 tail_len = 0;
	__u64 tail_start = 0;
	if (num > SNIPPET_HEAD_TAIL_HALF) {
		tail_len = (__u32)(num - SNIPPET_HEAD_TAIL_HALF);
		if (tail_len > SNIPPET_HEAD_TAIL_HALF)
			tail_len = SNIPPET_HEAD_TAIL_HALF;
		tail_start = num - tail_len;
	}
	if (head_len == 0)
		return 0;

	__u64 ts = bpf_ktime_get_ns();
	struct ssl_event *ev = reserve_event(EVENT_SSL, sizeof(*ev));
	if (!ev)
		return 0;
	ev->pid = pid;
	ev->tid = get_tid();
	ev->ts_ns = ts;
	ev->direction = 1;
	ev->nbytes = (__u32)num;
	ev->snippet_len = head_len + tail_len;
	bpf_probe_read_user(ev->snippet, head_len, (void *)(long)buf);
	if (tail_len > 0)
		bpf_probe_read_user(ev->snippet + head_len, tail_len, (void *)(long)(buf + tail_start));
	submit_event(ev);
	return 0;
}

SEC("uprobe/SSL_read")
int uprobe_SSL_read_entry(struct pt_regs *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;

	__u32 tid = get_tid();
	__u64 buf = PT_REGS_PARM2(ctx);
	struct ssl_read_ctx_val val = { .buf_ptr = buf, .readbytes_ptr = 0 };
	bpf_map_update_elem(&ssl_read_ctx, &tid, &val, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe_SSL_read_exit(struct pt_regs *ctx)
{
	__u32 tid = get_tid();
	struct ssl_read_ctx_val *val = bpf_map_lookup_elem(&ssl_read_ctx, &tid);
	if (!val)
		return 0;
	__u64 buf_ptr = val->buf_ptr & 0x7fffffffffffULL;
	if (buf_ptr == 0) {
		bpf_map_delete_elem(&ssl_read_ctx, &tid);
		return 0;
	}

	__s64 ret = PT_REGS_RC(ctx);
	if (ret <= 0) {
		bpf_map_delete_elem(&ssl_read_ctx, &tid);
		return 0;
	}

	__u32 pid = get_pid();
	__u32 nread = (__u32)ret;
	__u32 head_len = nread <= SNIPPET_HEAD_TAIL_HALF ? nread : SNIPPET_HEAD_TAIL_HALF;
	__u32 tail_len = 0;
	__u64 tail_start = 0;
	if (nread > SNIPPET_HEAD_TAIL_HALF) {
		tail_len = nread - SNIPPET_HEAD_TAIL_HALF;
		if (tail_len > SNIPPET_HEAD_TAIL_HALF)
			tail_len = SNIPPET_HEAD_TAIL_HALF;
		tail_start = buf_ptr + (nread - tail_len);
	}
	__u64 ts = bpf_ktime_get_ns();
	struct ssl_event *ev = reserve_event(EVENT_SSL, sizeof(*ev));
	if (ev) {
		ev->pid = pid;
		ev->tid = tid;
		ev->ts_ns = ts;
		ev->direction = 2;
		ev->nbytes = (__u32)ret;
		ev->snippet_len = head_len + tail_len;
		bpf_probe_read_user(ev->snippet, head_len, (void *)buf_ptr);
		if (tail_len > 0)
			bpf_probe_read_user(ev->snippet + head_len, tail_len, (void *)tail_start);
		submit_event(ev);
	}
	bpf_map_delete_elem(&ssl_read_ctx, &tid);
	return 0;
}

SEC("uprobe/SSL_read_ex")
int uprobe_SSL_read_ex_entry(struct pt_regs *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;

	__u32 tid = get_tid();
	__u64 buf = PT_REGS_PARM2(ctx);
	__u64 readbytes_ptr = PT_REGS_PARM4(ctx); /* size_t *readbytes */
	struct ssl_read_ctx_val val = { .buf_ptr = buf, .readbytes_ptr = readbytes_ptr };
	bpf_map_update_elem(&ssl_read_ctx, &tid, &val, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read_ex")
int uretprobe_SSL_read_ex_exit(struct pt_regs *ctx)
{
	__u32 tid = get_tid();
	struct ssl_read_ctx_val *val = bpf_map_lookup_elem(&ssl_read_ctx, &tid);
	if (!val)
		return 0;
	__u64 readbytes_ptr = val->readbytes_ptr & 0x7fffffffffffULL;
	__u64 buf_ptr = val->buf_ptr & 0x7fffffffffffULL;
	if (readbytes_ptr == 0 || buf_ptr == 0) {
		bpf_map_delete_elem(&ssl_read_ctx, &tid);
		return 0;
	}

	__s64 ret = PT_REGS_RC(ctx);
	if (ret != 1) {
		bpf_map_delete_elem(&ssl_read_ctx, &tid);
		return 0;
	}

	__u64 nread = 0;
	bpf_probe_read_user(&nread, sizeof(nread), (void *)readbytes_ptr);
	if (nread == 0) {
		bpf_map_delete_elem(&ssl_read_ctx, &tid);
		return 0;
	}
	__u32 nr = (__u32)(nread > MAX_SNIPPET_BYTES ? MAX_SNIPPET_BYTES : nread);
	__u32 head_len = nr <= SNIPPET_HEAD_TAIL_HALF ? nr : SNIPPET_HEAD_TAIL_HALF;
	__u32 tail_len = 0;
	__u64 tail_start = 0;
	if (nr > SNIPPET_HEAD_TAIL_HALF) {
		tail_len = nr - SNIPPET_HEAD_TAIL_HALF;
		if (tail_len > SNIPPET_HEAD_TAIL_HALF)
			tail_len = SNIPPET_HEAD_TAIL_HALF;
		tail_start = buf_ptr + (nread - tail_len);
	}
	__u32 pid = get_pid();
	__u64 ts = bpf_ktime_get_ns();
	struct ssl_event *ev = reserve_event(EVENT_SSL, sizeof(*ev));
	if (ev) {
		ev->pid = pid;
		ev->tid = tid;
		ev->ts_ns = ts;
		ev->direction = 2;
		ev->nbytes = (__u32)nread;
		ev->snippet_len = head_len + tail_len;
		bpf_probe_read_user(ev->snippet, head_len, (void *)buf_ptr);
		if (tail_len > 0)
			bpf_probe_read_user(ev->snippet + head_len, tail_len, (void *)tail_start);
		submit_event(ev);
	}
	bpf_map_delete_elem(&ssl_read_ctx, &tid);
	return 0;
}

/* Syscall tracepoints: args at 16/24, exit ret at 16 */
#define SYS_ENTER_ARGS0  16
#define SYS_ENTER_ARGS1  24
#define SYS_EXIT_RET     16

static char openat_path_zeros[MAX_PATH];

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__u64 filename_ptr = 0;
	bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), (void *)ctx + SYS_ENTER_ARGS1);
	if (filename_ptr == 0)
		return 0;
	__u32 tid = get_tid();
	if (bpf_map_update_elem(&openat_path, &tid, openat_path_zeros, BPF_ANY))
		return 0;
	char *path = bpf_map_lookup_elem(&openat_path, &tid);
	if (!path)
		return 0;
	if (bpf_probe_read_user(path, MAX_PATH - 1, (void *)(long)filename_ptr)) {
		bpf_map_delete_elem(&openat_path, &tid);
		return 0;
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_sys_exit_openat(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__s64 ret = 0;
	bpf_probe_read_kernel(&ret, sizeof(ret), (void *)ctx + SYS_EXIT_RET);
	if (ret < 0)
		return 0;
	__u32 tid = get_tid();
	char *path = bpf_map_lookup_elem(&openat_path, &tid);
	if (!path)
		return 0;
	__u64 ts = bpf_ktime_get_ns();
	struct openat_event *ev = reserve_event(EVENT_OPENAT, sizeof(*ev));
	if (!ev) {
		bpf_map_delete_elem(&openat_path, &tid);
		return 0;
	}
	ev->pid = pid;
	ev->fd = (__u32)ret;
	ev->ts_ns = ts;
	__builtin_memcpy(ev->path, path, MAX_PATH);
	bpf_map_delete_elem(&openat_path, &tid);
	submit_event(ev);
	return 0;
}

/* Helper: capture path at enter (args[1]) for *at-style syscalls */
static __always_inline int path_enter(void *ctx, void *path_map)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__u64 pathname_ptr = 0;
	bpf_probe_read_kernel(&pathname_ptr, sizeof(pathname_ptr), (void *)ctx + SYS_ENTER_ARGS1);
	if (!pathname_ptr)
		return 0;
	__u32 tid = get_tid();
	char zeros[MAX_PATH];
	__builtin_memset(zeros, 0, sizeof(zeros));
	if (bpf_map_update_elem(path_map, &tid, zeros, BPF_ANY))
		return 0;
	char *path = bpf_map_lookup_elem(path_map, &tid);
	if (!path)
		return 0;
	if (bpf_probe_read_user(path, MAX_PATH - 1, (void *)(long)pathname_ptr)) {
		bpf_map_delete_elem(path_map, &tid);
		return 0;
	}
	return 0;
}

/* Helper: emit path_event on exit (ret >= 0) */
static __always_inline int path_exit(void *ctx, void *path_map, __u32 event_type)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__s64 ret = 0;
	bpf_probe_read_kernel(&ret, sizeof(ret), (void *)ctx + SYS_EXIT_RET);
	if (ret < 0)
		return 0;
	__u32 tid = get_tid();
	char *path = bpf_map_lookup_elem(path_map, &tid);
	if (!path)
		return 0;
	__u64 ts = bpf_ktime_get_ns();
	struct path_event *ev = reserve_event(event_type, sizeof(*ev));
	if (!ev) {
		bpf_map_delete_elem(path_map, &tid);
		return 0;
	}
	ev->pid = pid;
	ev->ts_ns = ts;
	__builtin_memcpy(ev->path, path, MAX_PATH);
	bpf_map_delete_elem(path_map, &tid);
	submit_event(ev);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_statx")
int tp_sys_enter_statx(void *ctx)
{
	return path_enter(ctx, &statx_path);
}

SEC("tracepoint/syscalls/sys_exit_statx")
int tp_sys_exit_statx(void *ctx)
{
	return path_exit(ctx, &statx_path, EVENT_STAT);
}

SEC("tracepoint/syscalls/sys_enter_faccessat")
int tp_sys_enter_faccessat(void *ctx)
{
	return path_enter(ctx, &faccessat_path);
}

SEC("tracepoint/syscalls/sys_exit_faccessat")
int tp_sys_exit_faccessat(void *ctx)
{
	return path_exit(ctx, &faccessat_path, EVENT_ACCESS);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_sys_enter_unlinkat(void *ctx)
{
	return path_enter(ctx, &unlinkat_path);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int tp_sys_exit_unlinkat(void *ctx)
{
	return path_exit(ctx, &unlinkat_path, EVENT_UNLINK);
}

SEC("tracepoint/syscalls/sys_enter_close")
int tp_sys_enter_close(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__u32 fd = 0;
	bpf_probe_read_kernel(&fd, sizeof(fd), (void *)ctx + SYS_ENTER_ARGS0);
	__u64 ts = bpf_ktime_get_ns();
	struct close_event *ev = reserve_event(EVENT_CLOSE, sizeof(*ev));
	if (!ev)
		return 0;
	ev->pid = pid;
	ev->fd = fd;
	ev->ts_ns = ts;
	submit_event(ev);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tp_sys_enter_read(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__u32 fd = 0;
	bpf_probe_read_kernel(&fd, sizeof(fd), (void *)ctx + SYS_ENTER_ARGS0);
	__u32 tid = get_tid();
	bpf_map_update_elem(&syscall_fd, &tid, &fd, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tp_sys_exit_read(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__s64 ret = 0;
	bpf_probe_read_kernel(&ret, sizeof(ret), (void *)ctx + SYS_EXIT_RET);
	__u32 tid = get_tid();
	__u32 *pfd = bpf_map_lookup_elem(&syscall_fd, &tid);
	if (!pfd)
		return 0;
	__u64 ts = bpf_ktime_get_ns();
	struct io_event *ev = reserve_event(EVENT_READ, sizeof(*ev));
	if (ev) {
		ev->pid = pid;
		ev->fd = *pfd;
		ev->count = (__u32)(ret > 0 ? ret : 0);
		ev->ts_ns = ts;
		submit_event(ev);
	}
	bpf_map_delete_elem(&syscall_fd, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tp_sys_enter_write(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__u32 fd = 0;
	bpf_probe_read_kernel(&fd, sizeof(fd), (void *)ctx + SYS_ENTER_ARGS0);
	__u32 tid = get_tid();
	bpf_map_update_elem(&syscall_fd, &tid, &fd, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tp_sys_exit_write(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__s64 ret = 0;
	bpf_probe_read_kernel(&ret, sizeof(ret), (void *)ctx + SYS_EXIT_RET);
	__u32 tid = get_tid();
	__u32 *pfd = bpf_map_lookup_elem(&syscall_fd, &tid);
	if (!pfd)
		return 0;
	__u64 ts = bpf_ktime_get_ns();
	struct io_event *ev = reserve_event(EVENT_WRITE, sizeof(*ev));
	if (ev) {
		ev->pid = pid;
		ev->fd = *pfd;
		ev->count = (__u32)(ret > 0 ? ret : 0);
		ev->ts_ns = ts;
		submit_event(ev);
	}
	bpf_map_delete_elem(&syscall_fd, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int tp_sys_enter_dup(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__u32 oldfd = 0;
	bpf_probe_read_kernel(&oldfd, sizeof(oldfd), (void *)ctx + SYS_ENTER_ARGS0);
	__u32 tid = get_tid();
	bpf_map_update_elem(&syscall_fd, &tid, &oldfd, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup")
int tp_sys_exit_dup(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__s64 ret = 0;
	bpf_probe_read_kernel(&ret, sizeof(ret), (void *)ctx + SYS_EXIT_RET);
	if (ret < 0)
		return 0;
	__u32 tid = get_tid();
	__u32 *pold = bpf_map_lookup_elem(&syscall_fd, &tid);
	if (!pold)
		return 0;
	__u64 ts = bpf_ktime_get_ns();
	struct fd_pair_event *ev = reserve_event(EVENT_DUP, sizeof(*ev));
	if (ev) {
		ev->pid = pid;
		ev->oldfd = *pold;
		ev->newfd = (__u32)ret;
		ev->ts_ns = ts;
		submit_event(ev);
	}
	bpf_map_delete_elem(&syscall_fd, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int tp_sys_enter_dup2(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__u32 oldfd = 0;
	bpf_probe_read_kernel(&oldfd, sizeof(oldfd), (void *)ctx + SYS_ENTER_ARGS0);
	__u32 tid = get_tid();
	bpf_map_update_elem(&syscall_fd, &tid, &oldfd, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup2")
int tp_sys_exit_dup2(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__s64 ret = 0;
	bpf_probe_read_kernel(&ret, sizeof(ret), (void *)ctx + SYS_EXIT_RET);
	if (ret < 0)
		return 0;
	__u32 tid = get_tid();
	__u32 *pold = bpf_map_lookup_elem(&syscall_fd, &tid);
	if (!pold)
		return 0;
	__u64 ts = bpf_ktime_get_ns();
	struct fd_pair_event *ev = reserve_event(EVENT_DUP2, sizeof(*ev));
	if (ev) {
		ev->pid = pid;
		ev->oldfd = *pold;
		ev->newfd = (__u32)ret;
		ev->ts_ns = ts;
		submit_event(ev);
	}
	bpf_map_delete_elem(&syscall_fd, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe")
int tp_sys_enter_pipe(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__u64 fds_ptr = 0;
	bpf_probe_read_kernel(&fds_ptr, sizeof(fds_ptr), (void *)ctx + SYS_ENTER_ARGS0);
	if (!fds_ptr)
		return 0;
	__u32 tid = get_tid();
	bpf_map_update_elem(&pipe_args, &tid, &fds_ptr, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_pipe")
int tp_sys_exit_pipe(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__s64 ret = 0;
	bpf_probe_read_kernel(&ret, sizeof(ret), (void *)ctx + SYS_EXIT_RET);
	if (ret < 0)
		return 0;
	__u32 tid = get_tid();
	__u64 *p = bpf_map_lookup_elem(&pipe_args, &tid);
	if (!p)
		return 0;
	__u64 fds_ptr = *p;
	__u32 fds[2] = {};
	if (bpf_probe_read_user(&fds, sizeof(fds), (void *)(long)fds_ptr)) {
		bpf_map_delete_elem(&pipe_args, &tid);
		return 0;
	}
	__u64 ts = bpf_ktime_get_ns();
	struct pipe_event *ev = reserve_event(EVENT_PIPE, sizeof(*ev));
	if (ev) {
		ev->pid = pid;
		ev->fd_read = fds[0];
		ev->fd_write = fds[1];
		ev->ts_ns = ts;
		submit_event(ev);
	}
	bpf_map_delete_elem(&pipe_args, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe2")
int tp_sys_enter_pipe2(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__u64 fds_ptr = 0;
	bpf_probe_read_kernel(&fds_ptr, sizeof(fds_ptr), (void *)ctx + SYS_ENTER_ARGS0);
	if (!fds_ptr)
		return 0;
	__u32 tid = get_tid();
	bpf_map_update_elem(&pipe_args, &tid, &fds_ptr, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_pipe2")
int tp_sys_exit_pipe2(void *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__s64 ret = 0;
	bpf_probe_read_kernel(&ret, sizeof(ret), (void *)ctx + SYS_EXIT_RET);
	if (ret < 0)
		return 0;
	__u32 tid = get_tid();
	__u64 *p = bpf_map_lookup_elem(&pipe_args, &tid);
	if (!p)
		return 0;
	__u64 fds_ptr = *p;
	__u32 fds[2] = {};
	if (bpf_probe_read_user(&fds, sizeof(fds), (void *)(long)fds_ptr)) {
		bpf_map_delete_elem(&pipe_args, &tid);
		return 0;
	}
	__u64 ts = bpf_ktime_get_ns();
	struct pipe_event *ev = reserve_event(EVENT_PIPE, sizeof(*ev));
	if (ev) {
		ev->pid = pid;
		ev->fd_read = fds[0];
		ev->fd_write = fds[1];
		ev->ts_ns = ts;
		submit_event(ev);
	}
	bpf_map_delete_elem(&pipe_args, &tid);
	return 0;
}

/* getaddrinfo: capture hostname on entry, (hostname, ip4) on exit for DNS matching. */
#define GETADDRINFO_MAX_ITER 8

SEC("uprobe/getaddrinfo")
int uprobe_getaddrinfo_entry(struct pt_regs *ctx)
{
	__u32 pid = get_pid();
	if (!is_interesting(pid))
		return 0;
	__u64 node_ptr = PT_REGS_PARM1(ctx);
	if (!node_ptr)
		return 0;
	__u32 tid = get_tid();
	char hostbuf[MAX_HOSTNAME];
	__builtin_memset(hostbuf, 0, sizeof(hostbuf));
	long err = bpf_probe_read_user(hostbuf, MAX_HOSTNAME - 1, (void *)(long)node_ptr);
	if (err)
		return 0;
	bpf_map_update_elem(&getaddrinfo_hostname, &tid, hostbuf, BPF_ANY);
	return 0;
}

SEC("uretprobe/getaddrinfo")
int uretprobe_getaddrinfo_exit(struct pt_regs *ctx)
{
	__u32 tid = get_tid();
	char *host = bpf_map_lookup_elem(&getaddrinfo_hostname, &tid);
	if (!host)
		return 0;
	__s64 ret = PT_REGS_RC(ctx);
	if (ret != 0) {
		bpf_map_delete_elem(&getaddrinfo_hostname, &tid);
		return 0;
	}
	__u32 pid = get_pid();
	__u64 res_ptr_loc = PT_REGS_PARM4(ctx); /* struct addrinfo **res */
	__u64 addrinfo_ptr = 0;
	if (bpf_probe_read_user(&addrinfo_ptr, sizeof(addrinfo_ptr), (void *)(long)res_ptr_loc)) {
		bpf_map_delete_elem(&getaddrinfo_hostname, &tid);
		return 0;
	}
	__u64 ts = bpf_ktime_get_ns();
	int iter = 0;
	while (addrinfo_ptr && iter < GETADDRINFO_MAX_ITER) {
		__u32 ai_family = 0;
		if (bpf_probe_read_user(&ai_family, sizeof(ai_family), (void *)(long)(addrinfo_ptr + 4)))
			break;
		if (ai_family != AF_INET) {
			__u64 next = 0;
			bpf_probe_read_user(&next, sizeof(next), (void *)(long)(addrinfo_ptr + 32));
			addrinfo_ptr = next;
			iter++;
			continue;
		}
		__u64 ai_addr = 0;
		if (bpf_probe_read_user(&ai_addr, sizeof(ai_addr), (void *)(long)(addrinfo_ptr + 24)))
			break;
		if (ai_addr) {
			__u8 ip4[4] = {};
			if (bpf_probe_read_user(ip4, 4, (void *)(long)(ai_addr + 4)) == 0) {
				struct getaddrinfo_event *ev = reserve_event(EVENT_GETADDRINFO, sizeof(*ev));
				if (ev) {
					ev->pid = pid;
					ev->ts_ns = ts;
					__builtin_memcpy(ev->hostname, host, MAX_HOSTNAME);
					__builtin_memcpy(ev->ip4, ip4, 4);
					submit_event(ev);
				}
			}
		}
		__u64 next = 0;
		bpf_probe_read_user(&next, sizeof(next), (void *)(long)(addrinfo_ptr + 32));
		addrinfo_ptr = next;
		iter++;
	}
	bpf_map_delete_elem(&getaddrinfo_hostname, &tid);
	return 0;
}

char _license[] SEC("license") = "GPL";
