"""Linux-only worker confinement, applied by the launcher just before exec of the worker.

Mechanisms (each independently switchable so the panel can test them one at a time):
  rlimits        RLIMIT_CPU (soft=budget, hard=budget+1) and RLIMIT_AS (=memory budget)
  netns          unshare(CLONE_NEWUSER|CLONE_NEWNET): empty network namespace, no usable loopback
  drop_caps      clear the bounding set and all capability sets (the user namespace grants a full set)
  seccomp_write  seccomp-bpf: deny write-opens and every path-mutating syscall (returns EPERM)
  seccomp_net    seccomp-bpf: deny socket()/socketpair() for any family except AF_UNIX
  landlock_fs    Landlock: handle every write-class filesystem access; allow it only under the scratch dirs
  landlock_net   Landlock ABI>=4: deny TCP bind/connect (does not cover UDP; pair with netns or seccomp_net)
Landlock exists only on newer kernels (the cluster is mixed: some nodes 4.18 without it, some 5.14 with ABI 6);
detect() reports what the current node offers and a requested mechanism that is missing raises (fail closed).
x86_64 only (syscall numbers). Fails closed: a required mechanism that cannot be installed raises.
"""
import ctypes
import errno
import os
import platform
import resource
import struct

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
PR_CAPBSET_DROP = 24
SECCOMP_MODE_FILTER = 2
AUDIT_ARCH_X86_64 = 0xC000003E
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000

BPF_LD_W_ABS = 0x20
BPF_JEQ_K = 0x15
BPF_JSET_K = 0x45
BPF_RET_K = 0x06

# x86_64 syscall numbers
SYS_OPEN, SYS_OPENAT, SYS_OPENAT2, SYS_SOCKET, SYS_SOCKETPAIR = 2, 257, 437, 41, 53
DENY_ALWAYS_WRITE = {
    "creat": 85, "truncate": 76, "ftruncate": 77, "rename": 82, "renameat": 264, "renameat2": 316,
    "unlink": 87, "unlinkat": 263, "mkdir": 83, "mkdirat": 258, "rmdir": 84, "symlink": 88,
    "symlinkat": 266, "link": 86, "linkat": 265, "mknod": 133, "mknodat": 259, "chmod": 90,
    "fchmod": 91, "fchmodat": 268, "chown": 92, "fchown": 93, "lchown": 94, "fchownat": 260,
    "openat2": SYS_OPENAT2, "open_by_handle_at": 304, "io_uring_setup": 425, "io_uring_enter": 426,
    "io_uring_register": 427, "ptrace": 101, "process_vm_writev": 311, "mount": 165, "umount2": 166,
    "pivot_root": 155, "chroot": 161, "unshare": 272, "setns": 308,
}
# open flags that make an open a write: O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND|__O_TMPFILE
OPEN_WRITE_MASK = 0x3 | 0o100 | 0o1000 | 0o2000 | 0o20000000


def detect():
    """Report which mechanisms this kernel offers. Cheap, side-effect free (forks for the userns test)."""
    out = {"machine": platform.machine(), "kernel": platform.release()}
    ver = libc.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1))  # landlock_create_ruleset(version query)
    out["landlock_abi"] = ver
    out["landlock"] = ver > 0
    try:
        with open("/sys/kernel/security/lsm") as f:
            out["lsm"] = f.read().strip()
    except OSError as e:
        out["lsm"] = "unreadable:%s" % e
    pid = os.fork()
    if pid == 0:
        rc = libc.unshare(CLONE_NEWUSER | CLONE_NEWNET)
        os._exit(0 if rc == 0 else 1)
    _, st = os.waitpid(pid, 0)
    out["userns_netns"] = os.WEXITSTATUS(st) == 0
    return out


def _errno_check(rc, what):
    if rc != 0:
        e = ctypes.get_errno()
        raise OSError(e, "%s failed: %s" % (what, os.strerror(e)))


def apply_rlimits(cpu_seconds, mem_bytes):
    resource.setrlimit(resource.RLIMIT_CPU, (int(cpu_seconds), int(cpu_seconds) + 1))
    resource.setrlimit(resource.RLIMIT_AS, (int(mem_bytes), int(mem_bytes)))


def enter_netns():
    uid, gid = os.getuid(), os.getgid()
    _errno_check(libc.unshare(CLONE_NEWUSER | CLONE_NEWNET), "unshare(NEWUSER|NEWNET)")
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny")
    with open("/proc/self/uid_map", "w") as f:
        f.write("%d %d 1" % (uid, uid))
    with open("/proc/self/gid_map", "w") as f:
        f.write("%d %d 1" % (gid, gid))


class _CapHdr(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]


def drop_all_caps():
    for cap in range(0, 64):
        libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)  # EINVAL past the last cap is expected
    hdr = _CapHdr(0x20080522, 0)
    data = (_CapData * 2)()
    _errno_check(libc.capset(ctypes.byref(hdr), ctypes.byref(data)), "capset")


def _ins(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


def build_filter(deny_write, deny_net):
    """Assemble the seccomp-bpf program. Default action: allow."""
    eperm = SECCOMP_RET_ERRNO | errno.EPERM
    prog = []
    ld = lambda off: _ins(BPF_LD_W_ABS, 0, 0, off)
    NR, ARCH = 0, 4
    ARG = lambda i: 16 + 8 * i  # low 32 bits of args[i] (little endian)
    prog += [ld(ARCH), _ins(BPF_JEQ_K, 1, 0, AUDIT_ARCH_X86_64), _ins(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS)]
    prog += [ld(NR)]
    prog += [_ins(BPF_JSET_K, 0, 1, 0x40000000), _ins(BPF_RET_K, 0, 0, eperm)]  # refuse x32 ABI numbers

    def block(nr, body):
        # if nr == this: run body (which must end by reloading NR); else skip it
        return [_ins(BPF_JEQ_K, 0, len(body), nr)] + body

    if deny_write:
        for nr in DENY_ALWAYS_WRITE.values():
            prog += block(nr, [_ins(BPF_RET_K, 0, 0, eperm)])
        for nr, argi in ((SYS_OPEN, 1), (SYS_OPENAT, 2)):
            prog += block(nr, [ld(ARG(argi)), _ins(BPF_JSET_K, 0, 1, OPEN_WRITE_MASK),
                               _ins(BPF_RET_K, 0, 0, eperm), ld(NR)])
    if deny_net:
        for nr in (SYS_SOCKET, SYS_SOCKETPAIR):
            # allow only domain == AF_UNIX (1)
            prog += block(nr, [ld(ARG(0)), _ins(BPF_JEQ_K, 1, 0, 1), _ins(BPF_RET_K, 0, 0, eperm), ld(NR)])
    prog += [_ins(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW)]
    return prog


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def install_seccomp(deny_write, deny_net):
    if platform.machine() != "x86_64":
        raise OSError(errno.ENOSYS, "seccomp filter built for x86_64 only")
    prog = build_filter(deny_write, deny_net)
    buf = ctypes.create_string_buffer(b"".join(prog), len(prog) * 8)
    fprog = _SockFprog(len(prog), ctypes.cast(buf, ctypes.c_void_p).value)
    _errno_check(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "prctl(NO_NEW_PRIVS)")
    _errno_check(libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0), "prctl(SECCOMP)")


LL_FS = {"WRITE_FILE": 1 << 1, "REMOVE_DIR": 1 << 4, "REMOVE_FILE": 1 << 5, "MAKE_CHAR": 1 << 6, "MAKE_DIR": 1 << 7,
         "MAKE_REG": 1 << 8, "MAKE_SOCK": 1 << 9, "MAKE_FIFO": 1 << 10, "MAKE_BLOCK": 1 << 11, "MAKE_SYM": 1 << 12}
LL_REFER, LL_TRUNCATE = 1 << 13, 1 << 14  # ABI 2 and 3
LL_NET_BIND, LL_NET_CONNECT = 1, 2  # ABI 4


def landlock_abi():
    return libc.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1))


def install_landlock(scratch_dirs, fs, net):
    abi = landlock_abi()
    if abi < 1:
        raise OSError(errno.ENOSYS, "Landlock not available on this kernel")
    if net and abi < 4:
        raise OSError(errno.ENOSYS, "Landlock net rules need ABI 4, have %d" % abi)
    handled_fs = sum(LL_FS.values()) | (LL_REFER if abi >= 2 else 0) | (LL_TRUNCATE if abi >= 3 else 0) if fs else 0
    handled_net = (LL_NET_BIND | LL_NET_CONNECT) if net else 0
    size = 8 if abi < 4 else 16
    attr = struct.pack("<QQ", handled_fs, handled_net)[:size]
    fd = libc.syscall(444, attr, ctypes.c_size_t(size), ctypes.c_uint32(0))
    if fd < 0:
        e = ctypes.get_errno()
        raise OSError(e, "landlock_create_ruleset: %s" % os.strerror(e))
    for d in scratch_dirs if fs else []:
        dfd = os.open(d, os.O_PATH | os.O_CLOEXEC)
        rule = struct.pack("<Qi", handled_fs, dfd)  # packed: u64 allowed_access, s32 parent_fd
        rc = libc.syscall(445, ctypes.c_int(fd), ctypes.c_int(1), rule, ctypes.c_uint32(0))
        os.close(dfd)
        if rc != 0:
            e = ctypes.get_errno()
            raise OSError(e, "landlock_add_rule: %s" % os.strerror(e))
    _errno_check(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "prctl(NO_NEW_PRIVS)")
    rc = libc.syscall(446, ctypes.c_int(fd), ctypes.c_uint32(0))
    os.close(fd)
    if rc != 0:
        e = ctypes.get_errno()
        raise OSError(e, "landlock_restrict_self: %s" % os.strerror(e))


DEFAULT_FULL = {"rlimits": True, "netns": True, "drop_caps": True, "seccomp_write": True, "seccomp_net": True}
NONE = {"rlimits": True, "netns": False, "drop_caps": False, "seccomp_write": False, "seccomp_net": False}


def apply(cfg, cpu_seconds, mem_bytes):
    """Apply the selected mechanisms in a safe order. Raises on failure (fail closed)."""
    if cfg.get("rlimits"):
        apply_rlimits(cpu_seconds, mem_bytes)
    if cfg.get("netns"):
        enter_netns()
    if cfg.get("drop_caps"):
        drop_all_caps()
    if cfg.get("landlock_fs") or cfg.get("landlock_net"):
        install_landlock(cfg.get("landlock_scratch") or [], bool(cfg.get("landlock_fs")), bool(cfg.get("landlock_net")))
    if cfg.get("seccomp_write") or cfg.get("seccomp_net"):
        install_seccomp(bool(cfg.get("seccomp_write")), bool(cfg.get("seccomp_net")))
