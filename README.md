~~~
A simple LDAP connection checker - by Tom Fonteyne
Usage:

java -jar ldaptest.jar -u <url> -b <baseDN> -f <filter> [-a attr1[,attr2]] [-D binddn -w password] [-rf|-ri|-rt] [-t [-n]]"

 Required:"
  -u url          : in the format "ldap://server:port"
  -b baseDN       : the base dn from which to search a user
  -f filter       : a standard LDAP filter

 Optional:
  -p password     : when set, the user (from the filter) will be authenticated
  -D binddn       : bind (authenticate) to LDAP when creating the connection
  -w password     : password for the bind
  -rf | -ri | -rt : referrals: follow | ignore | throw
  -t              : use startTLS when connecting to the non-secure port
  -n              : in combination with -t: do not check the certificate hostname
  -a              : comma separated list of attributes to fetch, default is all

 Secure connections need:
    java -Djavax.net.ssl.trustStore=/path/to/store.jks -Djavax.net.ssl.trustStorePassword=password -jar ldapTest.jar ...