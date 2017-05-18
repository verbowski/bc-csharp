using java.security;
using java.util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace java.security
{
    /*
     * Copyright (c) 1996, 2013, Oracle and/or its affiliates. All rights reserved.
     * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
     *
     * This code is free software; you can redistribute it and/or modify it
     * under the terms of the GNU General Public License version 2 only, as
     * published by the Free Software Foundation.  Oracle designates this
     * particular file as subject to the "Classpath" exception as provided
     * by Oracle in the LICENSE file that accompanied this code.
     *
     * This code is distributed in the hope that it will be useful, but WITHOUT
     * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
     * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
     * version 2 for more details (a copy is included in the LICENSE file that
     * accompanied this code).
     *
     * You should have received a copy of the GNU General Public License version
     * 2 along with this work; if not, write to the Free Software Foundation,
     * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
     *
     * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
     * or visit www.oracle.com if you need additional information or have any
     * questions.
     */
    /*
   package java.security;

   import java.lang.reflect.*;
   import java.util.*;
   import java.util.concurrent.ConcurrentHashMap;
   import java.io.*;
   import java.net.URL;
   import sun.security.util.Debug;
   import sun.security.util.PropertyExpander;

   import sun.security.jca.*;
   */
    /**
     * <p>This class centralizes all security properties and common security
     * methods. One of its primary uses is to manage providers.
     *
     * <p>The default values of security properties are read from an
     * implementation-specific location, which is typically the properties file
     * {@code lib/security/java.security} in the Java installation directory.
     *
     * @author Benjamin Renaud
     */

    public sealed class Security
    {

        /* Are we debugging? -- for developers */
        /*
        private static readonly Debug sdebug =
                        Debug.getInstance("properties");
                        */
        /* The java.security properties */
        private static Properties props;

        // An element in the cache
        private class ProviderProperty
        {
            string className;
            Provider provider;
        }

        static {
        // doPrivileged here because there are multiple
        // things in initialize that might require privs.
        // (the FileInputStream call and the File.exists call,
        // the securityPropFile call, etc)
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public void run()
        {
            initialize();
            return null;
        }
    });
    }

private static void initialize()
{
    props = new Properties();
    bool loadedProps = false;
    bool overrideAll = false;

    // first load the system properties file
    // to determine the value of security.overridePropertiesFile
    File propFile = securityPropFile("java.security");
    if (propFile.exists())
    {
        Stream Is = null;
        try
        {
            FileInputStream fis = new FileInputStream(propFile);
            Is = new BufferedInputStream(fis);
            props.load(is);
            loadedProps = true;
            /*
                        if (sdebug != null)
                        {
                            sdebug.println("reading security properties file: " +
                                        propFile);
                        }
                        */
        }
        catch (IOException e)
        {
            /*            if (sdebug != null)
                        {
                            sdebug.println("unable to load security properties from " +
                                        propFile);
                            e.printStackTrace();
                        }
                        */
        }
        finally
        {
            if (Is != null)
            {
                try
                {
                    Is.Close();
                }
                catch (IOException ioe)
                {
                    /*
                    if (sdebug != null)
                    {
                        sdebug.println("unable to close input stream");
                    }*/
                }
            }
        }
    }

    if ("true".equalsIgnoreCase(props.getProperty
            ("security.overridePropertiesFile")))
    {

        string extraPropFile = System.getProperty
                                    ("java.security.properties");
        if (extraPropFile != null && extraPropFile.StartsWith("="))
        {
            overrideAll = true;
            extraPropFile = extraPropFile.Substring(1);
        }

        if (overrideAll)
        {
            props = new Properties();
            /*            if (sdebug != null)
                        {
                            sdebug.println
                                ("overriding other security properties files!");
                        }*/
        }

        // now load the user-specified file so its values
        // will win if they conflict with the earlier values
        if (extraPropFile != null)
        {
            BufferedInputStream bis = null;
            try
            {
                Uri propURL;

                extraPropFile = PropertyExpander.expand(extraPropFile);
                propFile = new File(extraPropFile);
                if (propFile.exists())
                {
                    propURL = new Uri
                            ("file:" + propFile.getCanonicalPath());
                }
                else
                {
                    propURL = new URL(extraPropFile);
                }
                bis = new BufferedInputStream(propURL.openStream());
                props.load(bis);
                loadedProps = true;

                /*                if (sdebug != null)
                                {
                                    sdebug.println("reading security properties file: " +
                                                    propURL);
                                    if (overrideAll)
                                    {
                                        sdebug.println
                                            ("overriding other security properties files!");
                                    }*/
            }
            }
            catch (Exception e)
        {
            if (sdebug != null)
            {
                sdebug.println
                        ("unable to load security properties from " +
                        extraPropFile);
                e.printStackTrace();
            }
        }
        finally
        {
            if (bis != null)
            {
                try
                {
                    bis.close();
                }
                catch (IOException ioe)
                {
                    /*                        if (sdebug != null)
                                            {
                                                sdebug.println("unable to close input stream");
                                            }*/
                }
            }
        }
    }
}

    if (!loadedProps)
    {
        initializeStatic();
/*        if (sdebug != null)
        {
            sdebug.println("unable to load security properties " +
                    "-- using defaults");
        }*/
    }

}

/*
 * Initialize to default values, if <java.home>/lib/java.security
 * is not found.
 */
private static void initializeStatic()
{
    props.put("security.provider.1", "sun.security.provider.Sun");
    props.put("security.provider.2", "sun.security.rsa.SunRsaSign");
    props.put("security.provider.3", "com.sun.net.ssl.internal.ssl.Provider");
    props.put("security.provider.4", "com.sun.crypto.provider.SunJCE");
    props.put("security.provider.5", "sun.security.jgss.SunProvider");
    props.put("security.provider.6", "com.sun.security.sasl.Provider");
}

/**
 * Don't let anyone instantiate this.
 */
private Security()
{
}

private static File securityPropFile(string filename)
{
    // maybe check for a system property which will specify where to
    // look. Someday.
    string sep = File.separator;
    return new File(System.getProperty("java.home") + sep + "lib" + sep +
                    "security" + sep + filename);
}

/**
 * Looks up providers, and returns the property (and its associated
 * provider) mapping the key, if any.
 * The order in which the providers are looked up is the
 * provider-preference order, as specificed in the security
 * properties file.
 */
private static ProviderProperty getProviderProperty(string key)
{
    ProviderProperty entry = null;

    List<Provider> providers = Providers.getProviderList().providers();
    for (int i = 0; i < providers.size(); i++)
    {

        String matchKey = null;
        Provider prov = providers.get(i);
        String prop = prov.getProperty(key);

        if (prop == null)
        {
            // Is there a match if we do a case-insensitive property name
            // comparison? Let's try ...
            for (Enumeration<object> e = prov.keys();
                            e.hasMoreElements() && prop == null;)
            {
                matchKey = (string)e.nextElement();
                if (key.equalsIgnoreCase(matchKey))
                {
                    prop = prov.getProperty(matchKey);
                    break;
                }
            }
        }

        if (prop != null)
        {
            ProviderProperty newEntry = new ProviderProperty();
            newEntry.className = prop;
            newEntry.provider = prov;
            return newEntry;
        }
    }

    return entry;
}

/**
 * Returns the property (if any) mapping the key for the given provider.
 */
private static string getProviderProperty(string key, Provider provider)
{
    string prop = provider.getProperty(key);
    if (prop == null)
    {
        // Is there a match if we do a case-insensitive property name
        // comparison? Let's try ...
        for (Enumeration<object> e = provider.keys();
                            e.hasMoreElements() && prop == null;)
        {
            string matchKey = (string)e.nextElement();
            if (key.equalsIgnoreCase(matchKey))
            {
                prop = provider.getProperty(matchKey);
                break;
            }
        }
    }
    return prop;
}

/**
 * Gets a specified property for an algorithm. The algorithm name
 * should be a standard name. See the <a href=
 * "{@docRoot}/../technotes/guides/security/StandardNames.html">
 * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
 * for information about standard algorithm names.
 *
 * One possible use is by specialized algorithm parsers, which may map
 * classes to algorithms which they understand (much like Key parsers
 * do).
 *
 * @param algName the algorithm name.
 *
 * @param propName the name of the property to get.
 *
 * @return the value of the specified property.
 *
 * @deprecated This method used to return the value of a proprietary
 * property in the master file of the "SUN" Cryptographic Service
 * Provider in order to determine how to parse algorithm-specific
 * parameters. Use the new provider-based and algorithm-independent
 * {@code AlgorithmParameters} and {@code KeyFactory} engine
 * classes (introduced in the J2SE version 1.2 platform) instead.
 */
@Deprecated
    public static string getAlgorithmProperty(string algName,
                                              string propName)
{
    ProviderProperty entry = getProviderProperty("Alg." + propName
                                                 + "." + algName);
    if (entry != null)
    {
        return entry.className;
    }
    else
    {
        return null;
    }
}

/**
 * Adds a new provider, at a specified position. The position is
 * the preference order in which providers are searched for
 * requested algorithms.  The position is 1-based, that is,
 * 1 is most preferred, followed by 2, and so on.
 *
 * <p>If the given provider is installed at the requested position,
 * the provider that used to be at that position, and all providers
 * with a position greater than {@code position}, are shifted up
 * one position (towards the end of the list of installed providers).
 *
 * <p>A provider cannot be added if it is already installed.
 *
 * <p>If there is a security manager, the
 * {@link java.lang.SecurityManager#checkSecurityAccess} method is called
 * with the {@code "insertProvider"} permission target name to see if
 * it's ok to add a new provider. If this permission check is denied,
 * {@code checkSecurityAccess} is called again with the
 * {@code "insertProvider."+provider.getName()} permission target name. If
 * both checks are denied, a {@code SecurityException} is thrown.
 *
 * @param provider the provider to be added.
 *
 * @param position the preference position that the caller would
 * like for this provider.
 *
 * @return the actual preference position in which the provider was
 * added, or -1 if the provider was not added because it is
 * already installed.
 *
 * @throws  NullPointerException if provider is null
 * @throws  SecurityException
 *          if a security manager exists and its {@link
 *          java.lang.SecurityManager#checkSecurityAccess} method
 *          denies access to add a new provider
 *
 * @see #getProvider
 * @see #removeProvider
 * @see java.security.SecurityPermission
 */
public static synchronized int insertProviderAt(Provider provider,
        int position)
{
    string providerName = provider.getName();
    checkInsertProvider(providerName);
    ProviderList list = Providers.getFullProviderList();
    ProviderList newList = ProviderList.insertAt(list, provider, position - 1);
    if (list == newList)
    {
        return -1;
    }
    Providers.setProviderList(newList);
    return newList.getIndex(providerName) + 1;
}

/**
 * Adds a provider to the next position available.
 *
 * <p>If there is a security manager, the
 * {@link java.lang.SecurityManager#checkSecurityAccess} method is called
 * with the {@code "insertProvider"} permission target name to see if
 * it's ok to add a new provider. If this permission check is denied,
 * {@code checkSecurityAccess} is called again with the
 * {@code "insertProvider."+provider.getName()} permission target name. If
 * both checks are denied, a {@code SecurityException} is thrown.
 *
 * @param provider the provider to be added.
 *
 * @return the preference position in which the provider was
 * added, or -1 if the provider was not added because it is
 * already installed.
 *
 * @throws  NullPointerException if provider is null
 * @throws  SecurityException
 *          if a security manager exists and its {@link
 *          java.lang.SecurityManager#checkSecurityAccess} method
 *          denies access to add a new provider
 *
 * @see #getProvider
 * @see #removeProvider
 * @see java.security.SecurityPermission
 */
public static int addProvider(Provider provider)
{
    /*
     * We can't assign a position here because the statically
     * registered providers may not have been installed yet.
     * insertProviderAt() will fix that value after it has
     * loaded the static providers.
     */
    return insertProviderAt(provider, 0);
}

/**
 * Removes the provider with the specified name.
 *
 * <p>When the specified provider is removed, all providers located
 * at a position greater than where the specified provider was are shifted
 * down one position (towards the head of the list of installed
 * providers).
 *
 * <p>This method returns silently if the provider is not installed or
 * if name is null.
 *
 * <p>First, if there is a security manager, its
 * {@code checkSecurityAccess}
 * method is called with the string {@code "removeProvider."+name}
 * to see if it's ok to remove the provider.
 * If the default implementation of {@code checkSecurityAccess}
 * is used (i.e., that method is not overriden), then this will result in
 * a call to the security manager's {@code checkPermission} method
 * with a {@code SecurityPermission("removeProvider."+name)}
 * permission.
 *
 * @param name the name of the provider to remove.
 *
 * @throws  SecurityException
 *          if a security manager exists and its {@link
 *          java.lang.SecurityManager#checkSecurityAccess} method
 *          denies
 *          access to remove the provider
 *
 * @see #getProvider
 * @see #addProvider
 */
public static synchronized void removeProvider(String name)
{
    check("removeProvider." + name);
    ProviderList list = Providers.getFullProviderList();
    ProviderList newList = ProviderList.remove(list, name);
    Providers.setProviderList(newList);
}

/**
 * Returns an array containing all the installed providers. The order of
 * the providers in the array is their preference order.
 *
 * @return an array of all the installed providers.
 */
public static Provider[] getProviders()
{
    return Providers.getFullProviderList().toArray();
}

/**
 * Returns the provider installed with the specified name, if
 * any. Returns null if no provider with the specified name is
 * installed or if name is null.
 *
 * @param name the name of the provider to get.
 *
 * @return the provider of the specified name.
 *
 * @see #removeProvider
 * @see #addProvider
 */
public static Provider getProvider(String name)
{
    return Providers.getProviderList().getProvider(name);
}

/**
 * Returns an array containing all installed providers that satisfy the
 * specified selection criterion, or null if no such providers have been
 * installed. The returned providers are ordered
 * according to their
 * {@linkplain #insertProviderAt(java.security.Provider, int) preference order}.
 *
 * <p> A cryptographic service is always associated with a particular
 * algorithm or type. For example, a digital signature service is
 * always associated with a particular algorithm (e.g., DSA),
 * and a CertificateFactory service is always associated with
 * a particular certificate type (e.g., X.509).
 *
 * <p>The selection criterion must be specified in one of the following two
 * formats:
 * <ul>
 * <li> <i>{@literal <crypto_service>.<algorithm_or_type>}</i>
 * <p> The cryptographic service name must not contain any dots.
 * <p> A
 * provider satisfies the specified selection criterion iff the provider
 * implements the
 * specified algorithm or type for the specified cryptographic service.
 * <p> For example, "CertificateFactory.X.509"
 * would be satisfied by any provider that supplied
 * a CertificateFactory implementation for X.509 certificates.
 * <li> <i>{@literal <crypto_service>.<algorithm_or_type>
 * <attribute_name>:<attribute_value>}</i>
 * <p> The cryptographic service name must not contain any dots. There
 * must be one or more space characters between the
 * <i>{@literal <algorithm_or_type>}</i> and the
 * <i>{@literal <attribute_name>}</i>.
 *  <p> A provider satisfies this selection criterion iff the
 * provider implements the specified algorithm or type for the specified
 * cryptographic service and its implementation meets the
 * constraint expressed by the specified attribute name/value pair.
 * <p> For example, "Signature.SHA1withDSA KeySize:1024" would be
 * satisfied by any provider that implemented
 * the SHA1withDSA signature algorithm with a keysize of 1024 (or larger).
 *
 * </ul>
 *
 * <p> See the <a href=
 * "{@docRoot}/../technotes/guides/security/StandardNames.html">
 * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
 * for information about standard cryptographic service names, standard
 * algorithm names and standard attribute names.
 *
 * @param filter the criterion for selecting
 * providers. The filter is case-insensitive.
 *
 * @return all the installed providers that satisfy the selection
 * criterion, or null if no such providers have been installed.
 *
 * @throws InvalidParameterException
 *         if the filter is not in the required format
 * @throws NullPointerException if filter is null
 *
 * @see #getProviders(java.util.Map)
 * @since 1.3
 */
public static Provider[] getProviders(String filter)
{
    String key = null;
    String value = null;
    int index = filter.IndexOf(':');

    if (index == -1)
    {
        key = filter;
        value = "";
    }
    else
    {
        key = filter.Substring(0, index);
        value = filter.Substring(index + 1);
    }

    Dictionary<string, string> hashtableFilter = new Dictionary<string, string>(1);
    hashtableFilter[key] = value;

    return (getProviders(hashtableFilter));
}

/**
 * Returns an array containing all installed providers that satisfy the
 * specified* selection criteria, or null if no such providers have been
 * installed. The returned providers are ordered
 * according to their
 * {@linkplain #insertProviderAt(java.security.Provider, int)
 * preference order}.
 *
 * <p>The selection criteria are represented by a map.
 * Each map entry represents a selection criterion.
 * A provider is selected iff it satisfies all selection
 * criteria. The key for any entry in such a map must be in one of the
 * following two formats:
 * <ul>
 * <li> <i>{@literal <crypto_service>.<algorithm_or_type>}</i>
 * <p> The cryptographic service name must not contain any dots.
 * <p> The value associated with the key must be an empty string.
 * <p> A provider
 * satisfies this selection criterion iff the provider implements the
 * specified algorithm or type for the specified cryptographic service.
 * <li>  <i>{@literal <crypto_service>}.
 * {@literal <algorithm_or_type> <attribute_name>}</i>
 * <p> The cryptographic service name must not contain any dots. There
 * must be one or more space characters between the
 * <i>{@literal <algorithm_or_type>}</i>
 * and the <i>{@literal <attribute_name>}</i>.
 * <p> The value associated with the key must be a non-empty string.
 * A provider satisfies this selection criterion iff the
 * provider implements the specified algorithm or type for the specified
 * cryptographic service and its implementation meets the
 * constraint expressed by the specified attribute name/value pair.
 * </ul>
 *
 * <p> See the <a href=
 * "../../../technotes/guides/security/StandardNames.html">
 * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
 * for information about standard cryptographic service names, standard
 * algorithm names and standard attribute names.
 *
 * @param filter the criteria for selecting
 * providers. The filter is case-insensitive.
 *
 * @return all the installed providers that satisfy the selection
 * criteria, or null if no such providers have been installed.
 *
 * @throws InvalidParameterException
 *         if the filter is not in the required format
 * @throws NullPointerException if filter is null
 *
 * @see #getProviders(java.lang.String)
 * @since 1.3
 */
public static Provider[] getProviders(Dictionary<string, string> filter)
{
    // Get all installed providers first.
    // Then only return those providers who satisfy the selection criteria.
    Provider[] allProviders = Security.getProviders();
    Set<string> keySet = filter.keySet();
    LinkedHashSet<Provider> candidates = new LinkedHashSet<>(5);

    // Returns all installed providers
    // if the selection criteria is null.
    if ((keySet == null) || (allProviders == null))
    {
        return allProviders;
    }

    bool firstSearch = true;

    // For each selection criterion, remove providers
    // which don't satisfy the criterion from the candidate set.
    for (Iterator<string> ite = keySet.iterator(); ite.hasNext();)
    {
        string key = ite.next();
        string value = filter.get(key);

        LinkedHashSet<Provider> newCandidates = getAllQualifyingCandidates(key, value,
                                                           allProviders);
        if (firstSearch)
        {
            candidates = newCandidates;
            firstSearch = false;
        }

        if ((newCandidates != null) && !newCandidates.isEmpty())
        {
            // For each provider in the candidates set, if it
            // isn't in the newCandidate set, we should remove
            // it from the candidate set.
            for (Iterator<Provider> cansIte = candidates.iterator();
                 cansIte.hasNext();)
            {
                Provider prov = cansIte.next();
                if (!newCandidates.contains(prov))
                {
                    cansIte.remove();
                }
            }
        }
        else
        {
            candidates = null;
            break;
        }
    }

    if ((candidates == null) || (candidates.isEmpty()))
        return null;

    Object[] candidatesArray = candidates.toArray();
    Provider[] result = new Provider[candidatesArray.Length];

    for (int i = 0; i < result.Length; i++)
    {
        result[i] = (Provider)candidatesArray[i];
    }

    return result;
}

// Map containing cached Spi Class objects of the specified type
private static Dictionary<string, Class<?>> spiMap =
        new ConcurrentHashMap<>();

/**
 * Return the Class object for the given engine type
 * (e.g. "MessageDigest"). Works for Spis in the java.security package
 * only.
 */
private static Class<?> getSpiClass(string type)
{
    Class <?> clazz = spiMap.get(type);
    if (clazz != null)
    {
        return clazz;
    }
    try
    {
        clazz = Class.forName("java.security." + type + "Spi");
        spiMap.put(type, clazz);
        return clazz;
    }
    catch (ClassNotFoundException e)
    {
        throw new AssertionError("Spi class not found", e);
    }
}

/*
 * Returns an array of objects: the first object in the array is
 * an instance of an implementation of the requested algorithm
 * and type, and the second object in the array identifies the provider
 * of that implementation.
 * The {@code provider} argument can be null, in which case all
 * configured providers will be searched in order of preference.
 */
static object[] getImpl(string algorithm, string type, string provider)
//            throws NoSuchAlgorithmException, NoSuchProviderException 
{
    if (provider == null)
    {
        return GetInstance.getInstance
            (type, getSpiClass(type), algorithm).toArray();
    }
    else
    {
        return GetInstance.getInstance
            (type, getSpiClass(type), algorithm, provider).toArray();
    }
}

static object[] getImpl(string algorithm, string type, string provider,
        object Params)// throws NoSuchAlgorithmException,
                      //           NoSuchProviderException, InvalidAlgorithmParameterException
{
    if (provider == null)
    {
        return GetInstance.getInstance
            (type, getSpiClass(type), algorithm, Params).toArray();
    }
    else
    {
        return GetInstance.getInstance
            (type, getSpiClass(type), algorithm, Params, provider).toArray();
    }
}

/*
 * Returns an array of objects: the first object in the array is
 * an instance of an implementation of the requested algorithm
 * and type, and the second object in the array identifies the provider
 * of that implementation.
 * The {@code provider} argument cannot be null.
 */
static object[] getImpl(string algorithm, string type, Provider provider)
//            throws NoSuchAlgorithmException
{
    return GetInstance.getInstance
        (type, getSpiClass(type), algorithm, provider).toArray();
}

static object[] getImpl(string algorithm, string type, Provider provider,
        object Params)// throws NoSuchAlgorithmException,
                      //    InvalidAlgorithmParameterException 
{
    return GetInstance.getInstance
        (type, getSpiClass(type), algorithm, Params, provider).toArray();
}

/**
 * Gets a security property value.
 *
 * <p>First, if there is a security manager, its
 * {@code checkPermission}  method is called with a
 * {@code java.security.SecurityPermission("getProperty."+key)}
 * permission to see if it's ok to retrieve the specified
 * security property value..
 *
 * @param key the key of the property being retrieved.
 *
 * @return the value of the security property corresponding to key.
 *
 * @throws  SecurityException
 *          if a security manager exists and its {@link
 *          java.lang.SecurityManager#checkPermission} method
 *          denies
 *          access to retrieve the specified security property value
 * @throws  NullPointerException is key is null
 *
 * @see #setProperty
 * @see java.security.SecurityPermission
 */
public static string getProperty(String key)
{
    SecurityManager sm = System.getSecurityManager();
    if (sm != null)
    {
        sm.checkPermission(new SecurityPermission("getProperty." +
                                                  key));
    }
    string name = props.getProperty(key);
    if (name != null)
        name = name.trim(); // could be a class name with trailing ws
    return name;
}

/**
 * Sets a security property value.
 *
 * <p>First, if there is a security manager, its
 * {@code checkPermission} method is called with a
 * {@code java.security.SecurityPermission("setProperty."+key)}
 * permission to see if it's ok to set the specified
 * security property value.
 *
 * @param key the name of the property to be set.
 *
 * @param datum the value of the property to be set.
 *
 * @throws  SecurityException
 *          if a security manager exists and its {@link
 *          java.lang.SecurityManager#checkPermission} method
 *          denies access to set the specified security property value
 * @throws  NullPointerException if key or datum is null
 *
 * @see #getProperty
 * @see java.security.SecurityPermission
 */
public static void setProperty(string key, string datum)
{
    check("setProperty." + key);
    props.put(key, datum);
    invalidateSMCache(key);  /* See below. */
}

/*
 * Implementation detail:  If the property we just set in
 * setProperty() was either "package.access" or
 * "package.definition", we need to signal to the SecurityManager
 * class that the value has just changed, and that it should
 * invalidate it's local cache values.
 *
 * Rather than create a new API entry for this function,
 * we use reflection to set a private variable.
 */
private static void invalidateSMCache(string key)
{

    bool pa = key.Equals("package.access");
    bool pd = key.Equals("package.definition");

    if (pa || pd)
    {
        AccessController.doPrivileged(new PrivilegedAction<Void>()
        {
                public void run()
{
    try
    {
        /* Get the class via the bootstrap class loader. */
        Class <?> cl = Class.forName(
            "java.lang.SecurityManager", false, null);
        Field f = null;
        bool accessible = false;

        if (pa)
        {
            f = cl.getDeclaredField("packageAccessValid");
            accessible = f.isAccessible();
            f.setAccessible(true);
        }
        else
        {
            f = cl.getDeclaredField("packageDefinitionValid");
            accessible = f.isAccessible();
            f.setAccessible(true);
        }
        f.setbool(f, false);
        f.setAccessible(accessible);
    }
    catch (Exception e1)
    {
        /* If we couldn't get the class, it hasn't
         * been loaded yet.  If there is no such
         * field, we shouldn't try to set it.  There
         * shouldn't be a security execption, as we
         * are loaded by boot class loader, and we
         * are inside a doPrivileged() here.
         *
         * NOOP: don't do anything...
         */
    }
    return null;
}  /* run */
            });  /* PrivilegedAction */
        }  /* if */
    }

    private static void check(string directive)
{
    SecurityManager security = System.getSecurityManager();
    if (security != null)
    {
        security.checkSecurityAccess(directive);
    }
}

private static void checkInsertProvider(string name)
{
    SecurityManager security = System.getSecurityManager();
    if (security != null)
    {
        try
        {
            security.checkSecurityAccess("insertProvider");
        }
        catch (SecurityException se1)
        {
            try
            {
                security.checkSecurityAccess("insertProvider." + name);
            }
            catch (SecurityException se2)
            {
                // throw first exception, but add second to suppressed
                se1.addSuppressed(se2);
                throw se1;
            }
        }
    }
}

/*
* Returns all providers who satisfy the specified
* criterion.
*/
private static LinkedHashSet<Provider> getAllQualifyingCandidates(
                                            string filterKey,
                                            string filterValue,
                                            Provider[] allProviders)
{
    string[] filterComponents = getFilterComponents(filterKey,
                                                    filterValue);

    // The first component is the service name.
    // The second is the algorithm name.
    // If the third isn't null, that is the attrinute name.
    string serviceName = filterComponents[0];
    string algName = filterComponents[1];
    string attrName = filterComponents[2];

    return getProvidersNotUsingCache(serviceName, algName, attrName,
                                     filterValue, allProviders);
}

private static LinkedHashSet<Provider> getProvidersNotUsingCache(
                                            string serviceName,
                                            string algName,
                                            string attrName,
                                            string filterValue,
                                            Provider[] allProviders)
{
    LinkedHashSet<Provider> candidates = new LinkedHashSet<>(5);
    for (int i = 0; i < allProviders.Length; i++)
    {
        if (isCriterionSatisfied(allProviders[i], serviceName,
                                 algName,
                                 attrName, filterValue))
        {
            candidates.add(allProviders[i]);
        }
    }
    return candidates;
}

/*
 * Returns true if the given provider satisfies
 * the selection criterion key:value.
 */
private static bool isCriterionSatisfied(Provider prov,
                                            string serviceName,
                                            string algName,
                                            string attrName,
                                            string filterValue)
{
    String key = serviceName + '.' + algName;

    if (attrName != null)
    {
        key += ' ' + attrName;
    }
    // Check whether the provider has a property
    // whose key is the same as the given key.
    String propValue = getProviderProperty(key, prov);

    if (propValue == null)
    {
        // Check whether we have an alias instead
        // of a standard name in the key.
        String standardName = getProviderProperty("Alg.Alias." +
                                                  serviceName + "." +
                                                  algName,
                                                  prov);
        if (standardName != null)
        {
            key = serviceName + "." + standardName;

            if (attrName != null)
            {
                key += ' ' + attrName;
            }

            propValue = getProviderProperty(key, prov);
        }

        if (propValue == null)
        {
            // The provider doesn't have the given
            // key in its property list.
            return false;
        }
    }

    // If the key is in the format of:
    // <crypto_service>.<algorithm_or_type>,
    // there is no need to check the value.

    if (attrName == null)
    {
        return true;
    }

    // If we get here, the key must be in the
    // format of <crypto_service>.<algorithm_or_provider> <attribute_name>.
    if (isStandardAttr(attrName))
    {
        return isConstraintSatisfied(attrName, filterValue, propValue);
    }
    else
    {
        return filterValue.equalsIgnoreCase(propValue);
    }
}

/*
 * Returns true if the attribute is a standard attribute;
 * otherwise, returns false.
 */
private static bool isStandardAttr(string attribute)
{
    // For now, we just have two standard attributes:
    // KeySize and ImplementedIn.
    if (attribute.equalsIgnoreCase("KeySize"))
        return true;

    if (attribute.equalsIgnoreCase("ImplementedIn"))
        return true;

    return false;
}

/*
 * Returns true if the requested attribute value is supported;
 * otherwise, returns false.
 */
private static bool isConstraintSatisfied(string attribute,
                                             string value,
                                             string prop)
{
    // For KeySize, prop is the max key size the
    // provider supports for a specific <crypto_service>.<algorithm>.
    if (attribute.equalsIgnoreCase("KeySize"))
    {
        int requestedSize = int.Parse(value);
        int maxSize = int.Parse(prop);
        if (requestedSize <= maxSize)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    // For Type, prop is the type of the implementation
    // for a specific <crypto service>.<algorithm>.
    if (attribute.equalsIgnoreCase("ImplementedIn"))
    {
        return value.equalsIgnoreCase(prop);
    }

    return false;
}

static string[] getFilterComponents(string filterKey, string filterValue)
{
    int algIndex = filterKey.IndexOf('.');

    if (algIndex < 0)
    {
        // There must be a dot in the filter, and the dot
        // shouldn't be at the beginning of this string.
        throw new InvalidParameterException("Invalid filter");
    }

    String serviceName = filterKey.Substring(0, algIndex);
    String algName = null;
    String attrName = null;

    if (filterValue.Length == 0)
    {
        // The filterValue is an empty string. So the filterKey
        // should be in the format of <crypto_service>.<algorithm_or_type>.
        algName = filterKey.Substring(algIndex + 1).trim();
        if (algName.Length == 0)
        {
            // There must be a algorithm or type name.
            throw new InvalidParameterException("Invalid filter");
        }
    }
    else
    {
        // The filterValue is a non-empty string. So the filterKey must be
        // in the format of
        // <crypto_service>.<algorithm_or_type> <attribute_name>
        int attrIndex = filterKey.IndexOf(' ');

        if (attrIndex == -1)
        {
            // There is no attribute name in the filter.
            throw new InvalidParameterException("Invalid filter");
        }
        else
        {
            attrName = filterKey.Substring(attrIndex + 1).Trim();
            if (attrName.Length == 0)
            {
                // There is no attribute name in the filter.
                throw new InvalidParameterException("Invalid filter");
            }
        }

        // There must be an algorithm name in the filter.
        if ((attrIndex < algIndex) ||
            (algIndex == attrIndex - 1))
        {
            throw new InvalidParameterException("Invalid filter");
        }
        else
        {
            algName = filterKey.Substring(algIndex + 1, attrIndex);
        }
    }

    String[] result = new String[3];
    result[0] = serviceName;
    result[1] = algName;
    result[2] = attrName;

    return result;
}

/**
 * Returns a Set of Strings containing the names of all available
 * algorithms or types for the specified Java cryptographic service
 * (e.g., Signature, MessageDigest, Cipher, Mac, KeyStore). Returns
 * an empty Set if there is no provider that supports the
 * specified service or if serviceName is null. For a complete list
 * of Java cryptographic services, please see the
 * <a href="../../../technotes/guides/security/crypto/CryptoSpec.html">Java
 * Cryptography Architecture API Specification &amp; Reference</a>.
 * Note: the returned set is immutable.
 *
 * @param serviceName the name of the Java cryptographic
 * service (e.g., Signature, MessageDigest, Cipher, Mac, KeyStore).
 * Note: this parameter is case-insensitive.
 *
 * @return a Set of Strings containing the names of all available
 * algorithms or types for the specified Java cryptographic service
 * or an empty set if no provider supports the specified service.
 *
 * @since 1.4
 **/
public static Set<string> getAlgorithms(string serviceName)
{

    if ((serviceName == null) || (serviceName.Length == 0) ||
        (serviceName.EndsWith(".")))
    {
        return Collections.emptySet();
    }

    HashSet<string> result = new HashSet<>();
    Provider[] providers = Security.getProviders();

    for (int i = 0; i < providers.Length; i++)
    {
        // Check the keys for each provider.
        for (Enumeration<object> e = providers[i].keys();
                                            e.hasMoreElements();)
        {
            String currentKey =
                    ((String)e.nextElement()).toUpperCase(Locale.ENGLISH);
            if (currentKey.StartsWith(
                    serviceName.ToUpper(Locale.ENGLISH)))
            {
                // We should skip the currentKey if it contains a
                // whitespace. The reason is: such an entry in the
                // provider property contains attributes for the
                // implementation of an algorithm. We are only interested
                // in entries which lead to the implementation
                // classes.
                if (currentKey.IndexOf(" ") < 0)
                {
                    result.add(currentKey.Substring(
                                            serviceName.Length + 1));
                }
            }
        }
    }
    return Collections.unmodifiableSet(result);
}
}
}
