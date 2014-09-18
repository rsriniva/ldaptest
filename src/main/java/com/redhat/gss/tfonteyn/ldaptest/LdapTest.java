/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.redhat.gss.tfonteyn.ldaptest;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;

/**
 *
 * @author Tom Fonteyne
 */
public class LdapTest
{
    private String url = null;
    private String basedn = null;
    private String filter = null;
    private String userPassword = null;

    private String binddn = null;
    private String bindCredentials = null;

    private StartTlsResponse tls = null;
    private boolean useTLS = false;
    private boolean allowFakeHostname = false;
    private String referral = null;
    private final SearchControls searchControls = new SearchControls();
    private String[] attributes;

    public LdapTest()
    {
    }

    public void setUrl(String url)
    {
        this.url = url;
    }

    /**
     *
     * @param attributes comma separated
     */
    public void setAttributes(String attributes)
    {
        this.attributes = attributes.split(",");
    }

    public void setAttributes(String[] attributes)
    {
        this.attributes = attributes;
    }

    public void setBasedn(String basedn)
    {
        this.basedn = basedn;
    }

    public void setFilter(String filter)
    {
        this.filter = filter;
    }

    public void setUserPassword(String userPassword)
    {
        this.userPassword = userPassword;
    }

    public void setBinddn(String binddn)
    {
        this.binddn = binddn;
    }

    public void setBindCredentials(String bindCredentials)
    {
        this.bindCredentials = bindCredentials;
    }

    public void setTls(StartTlsResponse tls)
    {
        this.tls = tls;
    }

    public void setUseTLS(boolean useTLS)
    {
        this.useTLS = useTLS;
    }

    public void setAllowFakeHostname(boolean allowFakeHostname)
    {
        this.allowFakeHostname = allowFakeHostname;
    }

    public void setReferral(String referral)
    {
        this.referral = referral;
    }

    public boolean canExecute()
    {
        return (url != null && basedn != null && filter != null);
    }

    public void exec(PrintStream out) throws IOException, NamingException
    {
        LdapContext ctx = this.getLdapContext(out, url, binddn, bindCredentials);

        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        if (attributes != null)
        {
            searchControls.setReturningAttributes(attributes);
        }

        NamingEnumeration<SearchResult> results = null;
        try
        {
            results = ctx.search(basedn, filter, searchControls);
        }
        catch (NamingException e)
        {
            e.printStackTrace(out);
        }
        if (results == null)
        {
            out.println("search returned 'null'");
            close(ctx);
            return;
        }

        SearchResult result;
        Attributes ldapAttributes;
        boolean found = false;
        while (results.hasMore())
        {
            result = results.next();
            ldapAttributes = result.getAttributes();
            String dn = this.getUserdn(ldapAttributes, result);

            found = true;
            out.println("---------------------------------------------");
            out.println("dn was: " + (result.isRelative() ? "relative" : "absolute"));
            out.println("dn             : " + dn);
            out.println("name           : " + result.getName());
            out.println("NameInNamespace: " + result.getNameInNamespace());
            out.println("------------attributes-----------------------");
            this.dumpAttributes(out, ldapAttributes.getAll());
            out.println("---------------------------------------------");
            if (userPassword != null)
            {
                out.println("authentication " + (authUser(out, result,dn,userPassword) ? "successful" : "failed"));
            }
        }
        if (!found)
        {
            out.println("No results found");
        }
        close(ctx);
    }

    private boolean authUser(PrintStream out, SearchResult result, String user, String userpassword) throws IOException, NamingException
    {
        LdapContext ctx;

        if (result.getName().startsWith("ldap"))
        {
            //TODO:  is this the right way of doing this - it works, but ?
            String ref_url = result.getName().substring(0, result.getName().indexOf("/", 8));
            String ref_binddn = result.getNameInNamespace();

            out.println("Following referral to: " + ref_url);
            ctx = this.getLdapContext(out, ref_url, ref_binddn, userpassword);
        }
        else
        {
            ctx = this.getLdapContext(out, url, user, userpassword);
        }

        return (ctx != null);
    }

    public LdapContext getLdapContext(PrintStream out, String url, String binddn, String bindCredentials) throws IOException, NamingException
    {
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        if (referral != null)
        {
            env.put(Context.REFERRAL, referral);
        }
        if (binddn != null)
        {
            out.println("Binding with principal: " + binddn);
            env.put(Context.SECURITY_AUTHENTICATION, "simple"); // not actually needed
            env.put(Context.SECURITY_PRINCIPAL, binddn);
        }
        if (bindCredentials != null)
        {
            env.put(Context.SECURITY_CREDENTIALS, bindCredentials);
        }

        if (url.startsWith("ldaps"))
        {
            env.put(Context.SECURITY_PROTOCOL, "ssl");   // usually not needed
        }

        LdapContext ctx = new InitialLdapContext(env, null);
        out.println("Connected to: " + url);
        if (useTLS && (url.startsWith("ldap:")))
        {
            tls = (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
            if (allowFakeHostname)
            {
                tls.setHostnameVerifier(new HostnameFakeVerifier());
            }
            tls.negotiate();
            out.println("TLS enabled");
        }

        return ctx;
    }

    private String getUserdn(Attributes ldapAttributes, SearchResult result) throws NamingException
    {
        String distinguishedUserDN = null;
        if (ldapAttributes != null)
        {
            Attribute dn = ldapAttributes.get("dn");
            if (dn != null)
            {
                distinguishedUserDN = (String) dn.get();
            }
        }
        if (distinguishedUserDN == null)
        {
            if (result.isRelative() == true)
            {
                distinguishedUserDN = result.getName() + ("".equals(basedn) ? "" : "," + basedn);
            }
            else
            {
                distinguishedUserDN = result.getNameInNamespace();

            }
        }
        return distinguishedUserDN;
    }

    private void dumpAttributes(PrintStream out, NamingEnumeration attributes) throws NamingException
    {
        Attribute attr;
        while (attributes.hasMore())
        {
            attr = (Attribute) attributes.next();
            if (attr != null)
            {
                Object values = attr.get();
                if (values == null)
                {
                    out.println(attr.getID() + "=<<<no values found>>>");
                }
                else
                {
                    int size = attr.size();
                    if (size == 0)
                    {
                        out.println(attr.getID() + "=<<<size was 0>>>");
                    }
                    else
                    {
                        for (int s = 0; s < size; s++)
                        {
                            out.println(attr.getID() + "=" + attr.get(s).toString());
                        }
                    }
                }
            }
        }
    }

    private void close(LdapContext ctx)
    {
        if (ctx == null) return;
        try
        {
            ctx.close();
        }
        catch (NamingException ne)
        {
        }
    }
}
