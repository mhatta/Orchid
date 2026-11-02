package com.subgraph.orchid.misc;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a class whose instances do not change once constructed, as far as
 * any caller can observe.  Its fields are not reassigned after the
 * constructor returns, the objects they refer to are not changed either,
 * and no method hands out a reference through which its state could be
 * changed.  A value may still be computed lazily and cached, if callers
 * cannot tell.
 * <p>
 * Instances of such a class can be shared between threads without locking.
 * This is documentation only: nothing checks it.
 */
@Documented
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface Immutable {
}
