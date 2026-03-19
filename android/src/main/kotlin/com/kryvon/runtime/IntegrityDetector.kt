package com.kryvon.runtime

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

class IntegrityDetector(private val context: Context) {

    fun checkIntegrity(expectedSha256: String?): Map<String, Any> {
        val indicators = mutableListOf<String>()
        var liveSha256: String? = null

        val sigResult = readSignatureSha256()
        liveSha256 = sigResult

        if (sigResult == null) {
            indicators.add("signatureUnavailable")
        } else if (expectedSha256 != null) {
            // Constant-time string comparison to resist timing attacks
            if (!secureEquals(sigResult, expectedSha256.lowercase())) {
                indicators.add("signatureMismatch")
            }
        }

        return mapOf(
            "indicators" to indicators,
            "signature" to (liveSha256 ?: "")
        )
    }

    /** Returns the lowercase SHA-256 hex digest of the first APK signing certificate. */
    private fun readSignatureSha256(): String? {
        return try {
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                info.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                val info = context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
                @Suppress("DEPRECATION")
                info.signatures
            }

            if (signatures.isNullOrEmpty()) return null

            val digest = MessageDigest.getInstance("SHA-256")
            val bytes = digest.digest(signatures[0].toByteArray())
            bytes.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            null
        }
    }

    /** Constant-time string equality to prevent timing side-channels. */
    private fun secureEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].code xor b[i].code)
        }
        return diff == 0
    }
}
