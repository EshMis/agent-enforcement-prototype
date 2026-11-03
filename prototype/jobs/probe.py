import ctypes, ctypes.util, os, sys, resource, platform, json
out = {"python": sys.version.split()[0], "platform": platform.platform()}
libc = ctypes.CDLL(None, use_errno=True)
SYS_landlock_create_ruleset = 444
class RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]
# ABI version query: attr=NULL size=0 flags=LANDLOCK_CREATE_RULESET_VERSION (1<<0)
libc.syscall.restype = ctypes.c_long
ver = libc.syscall(SYS_landlock_create_ruleset, None, ctypes.c_size_t(0), ctypes.c_uint32(1))
out["landlock_abi_version"] = ver
out["landlock_errno"] = ctypes.get_errno() if ver < 0 else 0
out["landlock_errno_name"] = os.strerror(out["landlock_errno"]) if ver < 0 else ""
for name, r in (("RLIMIT_CPU", resource.RLIMIT_CPU), ("RLIMIT_AS", resource.RLIMIT_AS), ("RLIMIT_NPROC", resource.RLIMIT_NPROC)):
    try:
        out[name] = resource.getrlimit(r)
        resource.setrlimit(r, resource.getrlimit(r))
        out[name + "_set_ok"] = True
    except Exception as e:
        out[name + "_set_ok"] = repr(e)
# prctl NO_NEW_PRIVS
out["prctl_no_new_privs"] = libc.prctl(38, 1, 0, 0, 0)
print(json.dumps(out))
