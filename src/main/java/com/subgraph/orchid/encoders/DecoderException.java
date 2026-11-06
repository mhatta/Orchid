/*
 * Derived from the Bouncy Castle Crypto APIs for Java
 * (org.bouncycastle.util.encoders), imported into Orchid in 2013.
 *
 * Copyright (c) 2000-2013 The Legion Of The Bouncy Castle
 * (http://www.bouncycastle.org)
 *
 * Licensed under the MIT license. The full text is in the "Bouncy Castle"
 * section of the LICENSE file at the top of the source tree.
 */
package com.subgraph.orchid.encoders;

public class DecoderException
    extends IllegalStateException
{
	private static final long serialVersionUID = 4997418733670548381L;
	private Throwable cause;

    DecoderException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
