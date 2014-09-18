package com.redhat.gss.tfonteyn.ldaptest;

import java.io.IOException;
import javax.naming.NamingException;

/**
 *
 * @author Tom Fonteyne
 */
public class Main
{
    private static final String VERSION = "2014-09-18";

    /**
     * @param args the command line arguments
     *
     * @throws javax.naming.NamingException
     * @throws java.io.IOException
     */
    public static void main(String[] args) throws NamingException, IOException
    {
        LdapTest instance = new LdapTest();
        if (readOptions(instance, args))
        {
            instance.exec(System.out);
        }
        else
        {
            usage();
        }
    }

    private static void usage()
    {
        System.out.println("A simple LDAP connection checker - by Tom Fonteyne - version:" + VERSION);
        System.out.println("Usage:");
        System.out.println(
            " java -jar ldaptest.jar -u <url> -b <baseDN> -f <filter> [-a attr1[,attr2]] [-D binddn -w password] [-rf|-ri|-rt] [-t [-n]]"
            + "\n Required:"
            + "\n  -u url          : in the format \"ldap://server:port\""
            + "\n  -b baseDN       : the base dn from which to search a user"
            + "\n  -f filter       : a standard LDAP filter"
            + "\n Optional:"
            + "\n  -p password     : when set, the user (from the filter) will be authenticated"
            + "\n  -D binddn       : bind (authenticate) to LDAP when creating the connection"
            + "\n  -w password     : password for the bind"
            + "\n  -rf | -ri | -rt : referrals: follow | ignore | throw"
            + "\n  -t              : use startTLS when connecting to the non-secure port"
            + "\n  -n              : in combination with -t: do not check the certificate hostname"
            + "\n  -a              : comma separated list of attributes to fetch, default is all"
            + "\n\n Secure connections need:"
            + "\n    java -Djavax.net.ssl.trustStore=/path/to/store.jks -Djavax.net.ssl.trustStorePassword=password -jar ldapTest.jar ..."
        );
        System.exit(1);
    }

    private static boolean readOptions(LdapTest instance, String[] args)
    {
        int i = 0;
        while (i < args.length)
        {
            if ("-u".equals(args[i]))
            {
                instance.setUrl(args[i + 1]);
                i += 2;
            }
            else if ("-b".equals(args[i]))
            {
                instance.setBasedn(args[i + 1]);
                i += 2;
            }
            else if ("-f".equals(args[i]))
            {
                instance.setFilter(args[i + 1]);
                i += 2;
            }
            else if ("-a".equals(args[i]))
            {
                instance.setAttributes(args[i + 1]);
                i += 2;
            }
            else if ("-p".equals(args[i]))
            {
                instance.setUserPassword(args[i + 1]);
                i += 2;
            }
            else if ("-D".equals(args[i]))
            {
                instance.setBinddn(args[i + 1]);
                i += 2;
            }
            else if ("-w".equals(args[i]))
            {
                instance.setBindCredentials(args[i + 1]);
                i += 2;
            }
            else if ("-t".equals(args[i]))
            {
                instance.setUseTLS(true);
                i += 1;
            }
            else if ("-h".equals(args[i]))
            {
                instance.setAllowFakeHostname(true);
                i += 1;
            }
            else if ("-rf".equals(args[i]))
            {
                instance.setReferral("follow");
                i += 1;
            }
            else if ("-ri".equals(args[i]))
            {
                instance.setReferral("ignore");
                i += 1;
            }
            else if ("-rt".equals(args[i]))
            {
                instance.setReferral("throw");
                i += 1;
            }
            else
            {
                usage();
            }
        }

        return instance.canExecute();
    }
}
