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

import java.io.IOException;
import java.io.OutputStream;

/**
 * Encode and decode byte arrays (typically from binary to 7-bit ASCII 
 * encodings).
 */
public interface Encoder
{
    int encode(byte[] data, int off, int length, OutputStream out) throws IOException;
    
    int decode(byte[] data, int off, int length, OutputStream out) throws IOException;

    int decode(String data, OutputStream out) throws IOException;
}
