/*
 * Derived from org.bouncycastle.math.ec.rfc7748.X25519 of the Bouncy Castle
 * Crypto APIs for Java, release 1.87 (tag r1rv87,
 * https://github.com/bcgit/bc-java).  Copyright (c) 2000-2026 The Legion
 * of the Bouncy Castle Inc. (https://www.bouncycastle.org); MIT license,
 * see LICENSE.
 *
 * Changes for Orchid: package; scalarMultBase() uses the Montgomery
 * ladder (upstream: Ed25519 comb), and the helpers of
 * org.bouncycastle.util.Arrays it used are inlined.
 */
package com.subgraph.orchid.crypto;

import java.security.SecureRandom;

/**
 * X25519 (RFC 7748): the Montgomery ladder with constant-time conditional
 * swaps, over the 10-limb field arithmetic of {@link X25519Field}.
 * Secret scalars take no secret-dependent branches or array indices.  As
 * upstream notes, pure Java cannot rule out timing variation from the JIT,
 * the garbage collector or caches, but there is nothing data-dependent in
 * the code for them to amplify.
 */
abstract class X25519
{
    public static final int POINT_SIZE = 32;
    public static final int SCALAR_SIZE = 32;

    private static class F extends X25519Field {};

    private static final int C_A = 486662;
    private static final int C_A24 = (C_A + 2)/4;

//    private static final int[] SQRT_NEG_486664 = { 0x03457E06, 0x03812ABF, 0x01A82CC6, 0x028A5BE8, 0x018B43A7,
//        0x03FC4F7E, 0x02C23700, 0x006BBD27, 0x03A30500, 0x001E4DDB };

    public static boolean calculateAgreement(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        scalarMult(k, kOff, u, uOff, r, rOff);
        return !areAllZeroes(r, rOff, POINT_SIZE);
    }

    public static void clampPrivateKey(byte[] k)
    {
        if (k == null)
        {
            throw new NullPointerException("'k' cannot be null");
        }
        if (k.length != SCALAR_SIZE)
        {
            throw new IllegalArgumentException("k");
        }

        k[0              ] &= 0xF8;
        k[SCALAR_SIZE - 1] &= 0x7F;
        k[SCALAR_SIZE - 1] |= 0x40;
    }

    private static void decodeScalar(byte[] k, int kOff, int[] n)
    {
        for (int i = 0; i < 8; ++i)
        {
            n[i] = F.decode32(k, kOff + i * 4);
        }

        n[0] &= 0xFFFFFFF8;
        n[7] &= 0x7FFFFFFF;
        n[7] |= 0x40000000;
    }

    public static void generatePrivateKey(SecureRandom random, byte[] k)
    {
        if (random == null)
        {
            throw new NullPointerException("'random' cannot be null");
        }
        if (k == null)
        {
            throw new NullPointerException("'k' cannot be null");
        }
        if (k.length != SCALAR_SIZE)
        {
            throw new IllegalArgumentException("k");
        }

        random.nextBytes(k);

        clampPrivateKey(k);
    }

    public static void generatePublicKey(byte[] k, int kOff, byte[] r, int rOff)
    {
        scalarMultBase(k, kOff, r, rOff);
    }

    private static void pointDouble(int[] x, int[] z)
    {
        int[] a = F.create();
        int[] b = F.create();

        F.apm(x, z, a, b);
        F.sqr(a, a);
        F.sqr(b, b);
        F.mul(a, b, x);
        F.sub(a, b, a);
        F.mul(a, C_A24, z);
        F.add(z, b, z);
        F.mul(z, a, z);
    }

    public static void scalarMult(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        validateSegment(k, kOff, SCALAR_SIZE);
        validateSegment(u, uOff, POINT_SIZE);
        validateSegment(r, rOff, POINT_SIZE);

        int[] n = new int[8];       decodeScalar(k, kOff, n);

        int[] x1 = F.create();      F.decode255(u, uOff, x1, 0);
        int[] x2 = F.create();      F.copy(x1, 0, x2, 0);
        int[] z2 = F.create();      z2[0] = 1;
        int[] x3 = F.create();      x3[0] = 1;
        int[] z3 = F.create();

        int[] t1 = F.create();
        int[] t2 = F.create();

//        assert n[7] >>> 30 == 1;

        int bit = 254, swap = 1;
        do
        {
            F.apm(x3, z3, t1, x3);
            F.apm(x2, z2, z3, x2);
            F.mul(t1, x2, t1);
            F.mul(x3, z3, x3);
            F.sqr(z3, z3);
            F.sqr(x2, x2);

            F.sub(z3, x2, t2);
            F.mul(t2, C_A24, z2);
            F.add(z2, x2, z2);
            F.mul(z2, t2, z2);
            F.mul(x2, z3, x2);

            F.apm(t1, x3, x3, z3);
            F.sqr(x3, x3);
            F.sqr(z3, z3);
            F.mul(z3, x1, z3);

            --bit;

            int word = bit >>> 5, shift = bit & 0x1F;
            int kt = (n[word] >>> shift) & 1;
            swap ^= kt;
            F.cswap(swap, x2, x3);
            F.cswap(swap, z2, z3);
            swap = kt;
        }
        while (bit >= 3);

//        assert swap == 0;

        for (int i = 0; i < 3; ++i)
        {
            pointDouble(x2, z2);
        }

        F.inv(z2, z2);
        F.mul(x2, z2, x2);

        F.normalize(x2);
        F.encode(x2, r, rOff);
    }

    /*
     * k * 9 by the Montgomery ladder of scalarMult().  Upstream computes
     * it on edwards25519 with a precomputed comb, which needs its own
     * Ed25519 code; the ladder is slower but constant time as well, and
     * upstream notes that it is equivalent.
     */
    public static void scalarMultBase(byte[] k, int kOff, byte[] r, int rOff)
    {
        byte[] u = new byte[POINT_SIZE];
        u[0] = 9;

        scalarMult(k, kOff, u, 0, r, rOff);
    }

    private static boolean areAllZeroes(byte[] buf, int off, int len)
    {
        int bits = 0;
        for (int i = 0; i < len; ++i)
        {
            bits |= buf[off + i];
        }
        return bits == 0;
    }

    private static void validateSegment(byte[] buf, int off, int len)
    {
        if (buf == null)
        {
            throw new NullPointerException("'buf' cannot be null");
        }
        if (off < 0 || len < 0 || off > buf.length - len)
        {
            throw new IndexOutOfBoundsException("segment out of range");
        }
    }
}
