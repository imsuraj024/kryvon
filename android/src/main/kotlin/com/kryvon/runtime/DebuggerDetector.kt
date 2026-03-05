package com.kryvon.runtime

import android.os.Debug

class DebuggerDetector {

    fun isDebuggerAttached(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

}