package com.proteles.auth

/** The time, in whole seconds since the epoch. Injected so tests control it. */
public fun interface Clock {
    public fun epochSeconds(): Long

    public companion object {
        public val SYSTEM: Clock = Clock { System.currentTimeMillis() / 1000 }
    }
}
