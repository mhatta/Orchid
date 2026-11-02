package com.subgraph.orchid.misc;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a class whose instances may be used from several threads at once
 * without any locking by the caller: whatever the order in which concurrent
 * calls are carried out, an instance stays consistent.
 * <p>
 * This is documentation only: nothing checks it.
 *
 * @see NotThreadSafe
 */
@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface ThreadSafe {
}
