package dev.kryvon.kryvon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidSignalEvaluatorTest {
    @Test
    fun rootArtifactProducesMediumConfidenceDetection() {
        val evaluator = evaluator(
            mapOf("/known/su" to ProbeResult.EXECUTABLE_PRESENT),
            paths = listOf("/known/su", "/missing/su")
        )

        val result = evaluator.evaluate(AndroidSignalEvaluator.ROOT_SU_SIGNAL)!!

        assertEquals("detected", result.status)
        assertEquals("medium", result.confidence)
        assertEquals(0, result.metadata["partialCheckFailures"])
    }

    @Test
    fun fullyCheckedAbsentPathsProduceHighConfidenceNegative() {
        val evaluator = evaluator(
            mapOf("/a" to ProbeResult.ABSENT, "/b" to ProbeResult.ABSENT),
            paths = listOf("/a", "/b")
        )

        val result = evaluator.evaluate(AndroidSignalEvaluator.ROOT_SU_SIGNAL)!!

        assertEquals("not_detected", result.status)
        assertEquals("high", result.confidence)
        assertEquals(0, result.metadata["partialCheckFailures"])
    }

    @Test
    fun positiveArtifactSurvivesOtherPathFailureAndReportsPartialFailure() {
        val evaluator = evaluator(
            mapOf(
                "/found" to ProbeResult.EXECUTABLE_PRESENT,
                "/inaccessible" to ProbeResult.ERROR
            ),
            paths = listOf("/found", "/inaccessible")
        )

        val result = evaluator.evaluate(AndroidSignalEvaluator.ROOT_SU_SIGNAL)!!

        assertEquals("detected", result.status)
        assertEquals("medium", result.confidence)
        assertEquals(1, result.metadata["partialCheckFailures"])
    }

    @Test
    fun noArtifactAndAnyPathFailureProducesFailedNotNegative() {
        val evaluator = evaluator(
            mapOf("/absent" to ProbeResult.ABSENT, "/inaccessible" to ProbeResult.ERROR),
            paths = listOf("/absent", "/inaccessible")
        )

        val result = evaluator.evaluate(AndroidSignalEvaluator.ROOT_SU_SIGNAL)!!

        assertEquals("failed", result.status)
        assertNull(result.confidence)
        assertEquals("partial_path_check_failure", result.metadata["diagnosticCode"])
    }

    @Test
    fun statErrorsOnlyTreatMissingPathOrParentAsAbsent() {
        assertEquals(ProbeResult.ABSENT, classifyPathStatError(2 /* ENOENT */))
        assertEquals(ProbeResult.ABSENT, classifyPathStatError(20 /* ENOTDIR */))
        assertEquals(ProbeResult.ERROR, classifyPathStatError(13 /* EACCES */))
        assertEquals(ProbeResult.ERROR, classifyPathStatError(1 /* EPERM */))
        assertEquals(ProbeResult.ERROR, classifyPathStatError(5 /* EIO */))
    }

    @Test
    fun statModeMustBeRegularFileWithAnExecuteBit() {
        assertTrue(
            isExecutableRegularFile(0x8000 /* S_IFREG */ or 0x40 /* S_IXUSR */)
        )
        assertTrue(
            isExecutableRegularFile(OsConstants.S_IFREG or 0x08 /* S_IXGRP */)
        )
        assertFalse(
            isExecutableRegularFile(OsConstants.S_IFREG or 0x100 /* S_IRUSR */)
        )
        assertFalse(
            isExecutableRegularFile(0x4000 /* S_IFDIR */ or OsConstants.S_IXUSR)
        )
    }

    @Test
    fun debuggerPositiveAndNegativeAreHighConfidence() {
        val attached = AndroidSignalEvaluator(
            pathProbe = PathProbe { ProbeResult.ABSENT },
            debuggerProbe = DebuggerProbe { true }
        ).evaluate(AndroidSignalEvaluator.DEBUGGER_SIGNAL)!!
        val detached = AndroidSignalEvaluator(
            pathProbe = PathProbe { ProbeResult.ABSENT },
            debuggerProbe = DebuggerProbe { false }
        ).evaluate(AndroidSignalEvaluator.DEBUGGER_SIGNAL)!!

        assertEquals("detected", attached.status)
        assertEquals("high", attached.confidence)
        assertEquals("not_detected", detached.status)
        assertEquals("high", detached.confidence)
    }

    @Test
    fun debuggerApiExceptionProducesFailed() {
        val evaluator = AndroidSignalEvaluator(
            pathProbe = PathProbe { ProbeResult.ABSENT },
            debuggerProbe = DebuggerProbe { throw IllegalStateException("private exception") }
        )

        val result = evaluator.evaluate(AndroidSignalEvaluator.DEBUGGER_SIGNAL)!!

        assertEquals("failed", result.status)
        assertNull(result.confidence)
        assertEquals("debugger_api_failure", result.metadata["diagnosticCode"])
        assertTrue(result.metadata.values.none { it == "private exception" })
    }

    @Test
    fun unknownSignalIsUnsupportedByEvaluator() {
        val result = AndroidSignalEvaluator(
            pathProbe = PathProbe { ProbeResult.ABSENT },
            debuggerProbe = DebuggerProbe { false }
        ).evaluate("android.unknown.signal")

        assertNull(result)
    }

    private fun evaluator(
        outcomes: Map<String, ProbeResult>,
        paths: List<String>
    ) = AndroidSignalEvaluator(
        pathProbe = PathProbe { path -> outcomes[path] ?: ProbeResult.ABSENT },
        debuggerProbe = DebuggerProbe { false },
        suPaths = paths
    )
}
