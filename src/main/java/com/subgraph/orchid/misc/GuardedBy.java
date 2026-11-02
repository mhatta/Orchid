package com.subgraph.orchid.misc;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a field, or a method, that may only be used while a given lock is
 * held.  The value names the lock, as an expression in the context of the
 * annotated member:
 * <ul>
 * <li><code>"this"</code>: the monitor of the object the member belongs to;</li>
 * <li><code>"Outer.this"</code>: the monitor of an enclosing instance;</li>
 * <li><code>"itself"</code>: for a field, the monitor of the object it refers to;</li>
 * <li><code>"lock"</code> or <code>"Other.lock"</code>: the object in that
 *     field (a monitor, or a {@link java.util.concurrent.locks.Lock});</li>
 * <li><code>"getLock()"</code>: the object that method returns;</li>
 * <li><code>"Some.class"</code>: the monitor of that class object.</li>
 * </ul>
 * This is documentation only: nothing checks it.
 */
@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface GuardedBy {
    String value();
}
