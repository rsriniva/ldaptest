package com.redhat.gss.tfonteyn.ldaptest;

import java.security.cert.Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

/**
 * Always accept the hostname
 *
 * @author Tom Fonteyne
 */
public class HostnameFakeVerifier implements HostnameVerifier
{

    @Override
    public boolean verify(String hostname, SSLSession session)
    {
        System.out.println("Checking: " + hostname + " in");
        try
        {
            Certificate[] certificates = session.getPeerCertificates();
            for (Certificate cert : certificates)
            {
                System.out.println(cert);
            }
        }
        catch (SSLPeerUnverifiedException e)
        {
            return false;
        }

        return true;
    }
}
