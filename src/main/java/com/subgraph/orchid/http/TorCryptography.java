package com.subgraph.orchid.http;

import javax.crypto.Cipher;

/**
 * Checks for the "limited strength" cryptography policy of old Oracle
 * Java releases.
 *
 * @deprecated Every supported Java release (8u161 and later, all OpenJDK
 * builds) and Android allow unlimited key lengths, which Orchid needs
 * (AES-256 for version 3 onion services).  This class used to lift the
 * restriction by rewriting private fields of javax.crypto.JceSecurity by
 * reflection; that is gone, and the class will be removed in a later
 * release.
 */
@Deprecated
public class TorCryptography {

    /**
     * Whether the runtime limits AES keys to less than 256 bits.
     */
    public static boolean hasRestrictedCryptography(){
        try {
            return Cipher.getMaxAllowedKeyLength("AES") < 256;
        } catch (Exception e) {
            // Assume unrestricted if we can not determine and let Orchid throw an error.
            return false;
        }
    }

    /**
     * Does nothing.  It used to lift the limited strength policy of old
     * Oracle releases by reflection; update Java instead.
     */
    public static void removeCryptographyRestrictions() {
    }
}
