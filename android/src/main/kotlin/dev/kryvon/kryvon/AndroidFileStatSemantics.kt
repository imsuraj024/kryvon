package dev.kryvon.kryvon

/**
 * Android's OsConstants fields are zero-valued stubs in local JVM unit tests.
 * Use the stable POSIX/Linux ABI values here so these security semantics remain
 * deterministic both in production and in host-side tests.
 */
internal fun isExecutableRegularFile(mode: Int): Boolean {
    val isRegularFile = (mode and S_IFMT) == S_IFREG
    return isRegularFile && (mode and EXECUTE_MASK) != 0
}

/** Only definite path absence is negative; access and other OS errors fail closed. */
internal fun classifyPathStatError(errno: Int): ProbeResult = when (errno) {
    ERRNO_ENOENT, ERRNO_ENOTDIR -> ProbeResult.ABSENT
    else -> ProbeResult.ERROR
}

private const val ERRNO_ENOENT = 2
private const val ERRNO_ENOTDIR = 20
private const val S_IFMT = 0xF000
private const val S_IFREG = 0x8000
private const val EXECUTE_MASK = 0x49 // S_IXUSR | S_IXGRP | S_IXOTH
