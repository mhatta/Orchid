package com.subgraph.orchid.misc;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a class whose instances must not be used from several threads at
 * once unless the callers coordinate their access themselves.  It is meant
 * for classes that a reader might otherwise take to be safe to share.
 * <p>
 * This is documentation only: nothing checks it.
 *
 * @see ThreadSafe
 */
@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface NotThreadSafe {
}
