#ifndef AGENT_OBSERVER_H
#define AGENT_OBSERVER_H

#define MAX_SNIPPET_BYTES 4096
#define MAX_CMDLINE_BYTES 512
#define MAX_EXE_LEN 256
#define MAX_PATH 256

enum event_type {
	EVENT_FORK = 1,
	EVENT_EXEC,
	EVENT_EXIT,
	EVENT_CONNECT,
	EVENT_SSL,
	EVENT_OPENAT,
	EVENT_CLOSE,
	EVENT_DUP,
	EVENT_DUP2,
	EVENT_READ,
	EVENT_WRITE,
	EVENT_PIPE,
	EVENT_GETADDRINFO,
	EVENT_STAT,
	EVENT_ACCESS,
	EVENT_UNLINK,
	EVENT_SIGNAL,
};

struct fork_event {
	__u32 parent_pid;
	__u32 child_pid;
	__u64 ts_ns;
	__u8  ctx_dump[64];  /* raw tracepoint ctx so daemon can find child_pid on any kernel */
};

struct exec_event {
	__u32 pid;
	__u64 ts_ns;
	char comm[16];
};

struct exit_event {
	__u32 pid;
	__u32 exit_code;
	__u64 ts_ns;
};

struct connect_event {
	__u32 pid;
	__u16 family;
	__u16 dst_port;
	__u8  dst_ip4[4];
	__u8  dst_ip6[16];
	__u64 ts_ns;
};

struct ssl_event {
	__u32 pid;
	__u32 tid;
	__u64 ts_ns;
	__u8  direction;
	__u32 nbytes;
	__u32 snippet_len;
	char  snippet[MAX_SNIPPET_BYTES];
};

struct openat_event {
	__u32 pid;
	__u32 fd;
	__u64 ts_ns;
	char  path[MAX_PATH];
};

/* Path-only events for correlation (stat/access/unlink) */
struct path_event {
	__u32 pid;
	__u32 padding;
	__u64 ts_ns;
	char  path[MAX_PATH];
};

struct close_event {
	__u32 pid;
	__u32 fd;
	__u64 ts_ns;
};

struct fd_pair_event {
	__u32 pid;
	__u32 oldfd;
	__u32 newfd;
	__u32 padding;
	__u64 ts_ns;
};

struct io_event {
	__u32 pid;
	__u32 fd;
	__u32 count;
	__u32 padding;
	__u64 ts_ns;
};

struct pipe_event {
	__u32 pid;
	__u32 fd_read;
	__u32 fd_write;
	__u32 padding;
	__u64 ts_ns;
};

#define MAX_HOSTNAME 256
struct getaddrinfo_event {
	__u32 pid;
	__u32 padding;
	char  hostname[MAX_HOSTNAME];
	__u8  ip4[4];
	__u64 ts_ns;
};

struct signal_event {
	__u32 sender_pid;
	__u32 target_pid;
	__s32 signal;
	__u64 ts_ns;
};

struct observer_event {
	__u32 type;
	__u32 padding;
	union {
		struct fork_event    fork;
		struct exec_event   exec;
		struct exit_event   exit;
		struct connect_event connect;
		struct ssl_event    ssl;
		struct openat_event openat;
		struct path_event   path_ev;
		struct close_event  close;
		struct fd_pair_event fd_pair;
		struct io_event     io;
		struct pipe_event   pipe;
		struct getaddrinfo_event getaddrinfo;
		struct signal_event signal;
	};
};

#endif
