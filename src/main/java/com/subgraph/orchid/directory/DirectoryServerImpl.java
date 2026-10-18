package com.subgraph.orchid.directory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.subgraph.orchid.DirectoryServer;
import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.RouterStatus;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.logging.Logger;

public class DirectoryServerImpl extends RouterImpl implements DirectoryServer {
    private static final Logger logger = Logger.getInstance(DirectoryServerImpl.class);
	
    private final List<KeyCertificate> certificates = new ArrayList<KeyCertificate>();

    private boolean isHiddenServiceAuthority = false;
    private boolean isBridgeAuthority = false;
    private boolean isExtraInfoCache = false;
    private HexDigest v3Ident;

    DirectoryServerImpl(RouterStatus status) {
        super(null, status);
    }

    void setHiddenServiceAuthority() { isHiddenServiceAuthority = true; }
    void unsetHiddenServiceAuthority() { isHiddenServiceAuthority = false; }
    void setBridgeAuthority() { isBridgeAuthority = true; }
    void setExtraInfoCache() { isExtraInfoCache = true; }
    void setV3Ident(HexDigest fingerprint) { this.v3Ident = fingerprint; }

    public boolean isTrustedAuthority() {
            return true;
    }

    /**
     * Return true if this DirectoryServer entry has
     * complete and valid information.
     * @return
     */
    @Override
    public boolean isValid() {
        return true;
    }

    @Override
    public boolean isV2Authority() {
        return hasFlag("Authority") && hasFlag("V2Dir");
    }

    @Override
    public boolean isV3Authority() {
        return hasFlag("Authority") && v3Ident != null;
    }

    @Override
    public boolean isHiddenServiceAuthority() {
        return isHiddenServiceAuthority;
    }

    @Override
    public boolean isBridgeAuthority() {
        return isBridgeAuthority;
    }

    @Override
    public boolean isExtraInfoCache() {
        return isExtraInfoCache;
    }

    @Override
    public HexDigest getV3Identity() {
        return v3Ident;
    }

    /**
     * https://github.com/geo-gs/Orchid/commit/22beeae1b881707491addaba6a7654e9de9f9db1
     */
    @Override
    public KeyCertificate getCertificateByAuthority(HexDigest fingerprint){

        for(KeyCertificate kc: getCertificates()) {
            if(kc.getAuthorityFingerprint().equals(fingerprint)) {
                return kc;
            }
        }
        return null;            
    }

    @Override
    public KeyCertificate getCertificateByFingerprint(HexDigest fingerprint) {
        for(KeyCertificate kc: getCertificates()) {
            if(kc.getAuthoritySigningKey().getFingerprint().equals(fingerprint)) {
                return kc;
            }
        }
        return null;
    }

    @Override
    public List<KeyCertificate> getCertificates() {
        synchronized(certificates) {
            purgeExpiredCertificates();
            purgeOldCertificates();
            return new ArrayList<KeyCertificate>(certificates);
        }
    }

    private void purgeExpiredCertificates() {
        Iterator<KeyCertificate> it = certificates.iterator();
        while(it.hasNext()) {
            KeyCertificate elem = it.next();
            if(elem.isExpired()) {
                it.remove();
            }
        }
    }

    private void purgeOldCertificates() {
        if(certificates.size() < 2) {
            return;
        }
        final KeyCertificate newest = getNewestCertificate();
        final Iterator<KeyCertificate> it = certificates.iterator();
        while(it.hasNext()) {
            KeyCertificate elem = it.next();
            if(elem != newest && isMoreThan48HoursOlder(newest, elem)) {
                it.remove();
            }
        }
    }

    private KeyCertificate getNewestCertificate() {
        KeyCertificate newest = null;
        for(KeyCertificate kc : certificates) {
            if(newest == null || getPublishedMilliseconds(kc) > getPublishedMilliseconds(newest)) {
                newest = kc;
            }
        }
        return newest;
    }

    private boolean isMoreThan48HoursOlder(KeyCertificate newer, KeyCertificate older) {
        final long milliseconds = 48 * 60 * 60 * 1000;
        return (getPublishedMilliseconds(newer) - getPublishedMilliseconds(older)) > milliseconds;
    }

    private long getPublishedMilliseconds(KeyCertificate certificate) {
        return certificate.getKeyPublishedTime().getDate().getTime();
    }

    @Override
    public void addCertificate(KeyCertificate certificate) {
        if(!certificate.getAuthorityFingerprint().equals(v3Ident)) {
                throw new IllegalArgumentException("This certificate does not appear to belong to this directory authority");
        }
        final HexDigest signingKey = certificate.getAuthoritySigningKey().getFingerprint();
        synchronized(certificates) {
                // The same certificate is downloaded again after a restart
                // or when another consensus asks for it; keep one copy.
                final Iterator<KeyCertificate> it = certificates.iterator();
                while(it.hasNext()) {
                    if(it.next().getAuthoritySigningKey().getFingerprint().equals(signingKey)) {
                        it.remove();
                    }
                }
                logger.debug("Adding certificate for "+ getNickname() + " with signing key "+ signingKey);
                certificates.add(certificate);
        }
    }

    @Override
    public String toString() {
        // The ORPort is what Orchid connects to (BEGIN_DIR); the DirPort is unused.
        if(v3Ident != null) {
            return "(Directory: "+ getNickname() +" "+ getAddress() +":"+ getOnionPort() +" fingerprint="+ getIdentityHash() +" v3ident="+
                    v3Ident +")";
        } else{
            return "(Directory: "+ getNickname() +" "+ getAddress() +":"+ getOnionPort() +" fingerprint="+ getIdentityHash() +")";
        }
    }
}
