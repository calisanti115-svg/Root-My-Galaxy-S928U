package dev.busung.s25uroot

import java.io.File

/**
 * Alternative root provider that tries multiple methods to acquire
 * root access without using the CVE-2026-43499 exploit that crashes
 * the kernel on patched Samsung firmware.
 *
 * Methods tried (in order):
 * 1. Fork + capability check
 * 2. /proc/<pid>/mem credential overwrite
 * 3. pagemap + physical memory scan
 * 4. BPF heap spray
 * 5. tracefs trigger
 * 6. perf_event side-channel
 */
object RootShellProvider {
    init {
        System.loadLibrary("root_shell")
    }

    external fun tryRoot(): Int
    external fun writeMarker(path: String)
    external fun isRootActive(): Boolean

    /**
     * Attempt to acquire root using alternative methods.
     * Returns true if root was obtained, false otherwise.
     * This method does NOT crash the kernel - each method has
     * signal handlers that catch crashes.
     */
    fun attemptRoot(logCallback: (String) -> Unit): Boolean {
        logCallback("[*] Starting alternative root exploit (no CVE)...")

        val result = tryRoot()

        if (result == 0) {
            logCallback("[+] Root access obtained!")
            if (isRootActive()) {
                logCallback("[+] Root verified: euid=0")
                return true
            } else {
                logCallback("[!] Root marker set but euid != 0")
            }
        } else {
            logCallback("[-] Alternative root methods did not succeed")
            logCallback("[*] This firmware may require the original CVE exploit")
            logCallback("[*] Consider: firmware downgrade, Magisk, or KernelSU via boot image")
        }

        return false
    }

    /**
     * Write a marker file indicating root status.
     */
    fun writeRootMarker(path: String) {
        writeMarker(path)
    }

    /**
     * Check if root is currently active.
     */
    fun checkRoot(): Boolean {
        return isRootActive()
    }
}
