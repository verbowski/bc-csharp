using java.security;
using java.util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.Text;
using static java.security.Provider;

// http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/8u40-b25/java/security/Provider.java#Provider
namespace java.security
{
    /*
     * Copyright (c) 1996, 2014, Oracle and/or its affiliates. All rights reserved.
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

   import java.io.*;
   import java.util.*;
   import static java.util.Locale.ENGLISH;
import java.lang.ref.*;
   import java.lang.reflect.*;
   import java.util.function.BiConsumer;
   import java.util.function.BiFunction;
   import java.util.function.Function;
   */
    /**
     * This class represents a "provider" for the
     * Java Security API, where a provider implements some or all parts of
     * Java Security. Services that a provider may implement include:
     *
     * <ul>
     *
     * <li>Algorithms (such as DSA, RSA, MD5 or SHA-1).
     *
     * <li>Key generation, conversion, and management facilities (such as for
     * algorithm-specific keys).
     *
     *</ul>
     *
     * <p>Each provider has a name and a version number, and is configured
     * in each runtime it is installed in.
     *
     * <p>See <a href =
     * "../../../technotes/guides/security/crypto/CryptoSpec.html#Provider">The Provider Class</a>
     * in the "Java Cryptography Architecture API Specification &amp; Reference"
     * for information about how a particular type of provider, the
     * cryptographic service provider, works and is installed. However,
     * please note that a provider can be used to implement any security
     * service in Java that uses a pluggable architecture with a choice
     * of implementations that fit underneath.
     *
     * <p>Some provider implementations may encounter unrecoverable internal
     * errors during their operation, for example a failure to communicate with a
     * security token. A {@link ProviderException} should be used to indicate
     * such errors.
     *
     * <p>The service type {@code Provider} is reserved for use by the
     * security framework. Services of this type cannot be added, removed,
     * or modified by applications.
     * The following attributes are automatically placed in each Provider object:
     * <table cellspacing=4>
     * <caption><b>Attributes Automatically Placed in a Provider object</b></caption>
     * <tr><th>Name</th><th>Value</th>
     * <tr><td>{@code Provider.id name}</td>
      *    <td>{@code string.valueOf(provider.getName())}</td>
     * <tr><td>{@code Provider.id version}</td>
     *     <td>{@code string.valueOf(provider.getVersion())}</td>
     * <tr><td>{@code Provider.id info}</td>
           <td>{@code string.valueOf(provider.getInfo())}</td>
     * <tr><td>{@code Provider.id className}</td>
     *     <td>{@code provider.getClass().getName()}</td>
     * </table>
     *
     * @author Benjamin Renaud
     * @author Andreas Sterbenz
     */
    public abstract class Provider : Properties
    {

        // Declare serialVersionUID to be compatible with JDK1.1
        static readonly long serialVersionUID = -4298000515446427739L;

//        private static readonly sun.security.util.Debug debug = sun.security.util.Debug.getInstance("provider", "Provider");

        /**
         * The provider name.
         *
         * @serial
         */
        private string name;

        /**
         * A description of the provider and its services.
         *
         * @serial
         */
        private string info;

        /**
         * The provider version number.
         *
         * @serial
         */
        private double version;

        [NonSerialized]  // equivalent of transient keyword in Java
        private Set<Map.Entry<object, object>> entrySet = null;
        [NonSerialized]  // equivalent of transient keyword in Java
        private int entrySetCallCount = 0;
        [NonSerialized]  // equivalent of transient keyword in Java
        private /*transient*/ bool initialized;

        /**
         * Constructs a provider with the specified name, version number,
         * and information.
         *
         * @param name the provider name.
         *
         * @param version the provider version number.
         *
         * @param info a description of the provider and its services.
         */
        protected Provider(string name, double version, string info)
        {
            this.name = name;
            this.version = version;
            this.info = info;
            putId();
            initialized = true;
        }

        /**
         * Returns the name of this provider.
         *
         * @return the name of this provider.
         */
        public string getName()
        {
            return name;
        }

        /**
         * Returns the version number for this provider.
         *
         * @return the version number for this provider.
         */
        public double getVersion()
        {
            return version;
        }

        /**
         * Returns a human-readable description of the provider and its
         * services.  This may return an HTML page, with relevant links.
         *
         * @return a description of the provider and its services.
         */
        public string getInfo()
        {
            return info;
        }

        /**
         * Returns a string with the name and the version number
         * of this provider.
         *
         * @return the string with the name and the version number
         * for this provider.
         */
        public string toString()
        {
            return name + " version " + version;
        }

        /*
         * override the following methods to ensure that provider
         * information can only be changed if the caller has the appropriate
         * permissions.
         */

        /**
         * Clears this provider so that it no longer contains the properties
         * used to look up facilities implemented by the provider.
         *
         * <p>If a security manager is enabled, its {@code checkSecurityAccess}
         * method is called with the string {@code "clearProviderProperties."+name}
         * (where {@code name} is the provider name) to see if it's ok to clear
         * this provider.
         *
         * @throws  SecurityException
         *          if a security manager exists and its {@link
         *          java.lang.SecurityManager#checkSecurityAccess} method
         *          denies access to clear this provider
         *
         * @since 1.2
         */
        //    @Override
        [MethodImpl(MethodImplOptions.Synchronized)]
        public void clear()
        {
            check("clearProviderProperties." + name);
            /*
            if (debug != null)
            {
                debug.println("Remove " + name + " provider properties");
            }
            */
            implClear();
        }

        /**
         * Reads a property list (key and element pairs) from the input stream.
         *
         * @param inStream   the input stream.
         * @exception  IOException  if an error occurred when reading from the
         *               input stream.
         * @see java.util.Properties#load
         */
        //    @Override
        [MethodImpl(MethodImplOptions.Synchronized)]
        public void load(Stream inStream) //throws IOException
        {
            check("putProviderProperty."+name);
            /*
        if (debug != null) {
                debug.println("Load " + name + " provider properties");
            }
            */
            Properties tempProperties = new Properties();
        tempProperties.load(inStream);
        implPutAll(tempProperties);
    }
    /**
     * Copies all of the mappings from the specified Map to this provider.
     * These mappings will replace any properties that this provider had
     * for any of the keys currently in the specified Map.
     *
     * @since 1.2
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public void putAll(Map<?,?> t)
    {
        check("putProviderProperty." + name);
            /*
        if (debug != null)
        {
            debug.println("Put all " + name + " provider properties");
        }
        */
        implPutAll(t);
    }

    /**
     * Returns an unmodifiable Set view of the property entries contained
     * in this Provider.
     *
     * @see   java.util.Map.Entry
     * @since 1.2
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]

    public override Set<Map.Entry<object, object>> entrySet()
    {
        checkInitialized();
        if (entrySet == null)
        {
            if (entrySetCallCount++ == 0)  // Initial call
                entrySet = Collections.unmodifiableMap(this).entrySet();
            else
                return base.entrySet();   // Recursive call
        }

        // This exception will be thrown if the implementation of
        // Collections.unmodifiableMap.entrySet() is changed such that it
        // no longer calls entrySet() on the backing Map.  (Provider's
        // entrySet implementation depends on this "implementation detail",
        // which is unlikely to change.
        if (entrySetCallCount != 2)
            throw new RuntimeException("Internal error.");

        return entrySet;
    }

    /**
     * Returns an unmodifiable Set view of the property keys contained in
     * this provider.
     *
     * @since 1.2
     */
    //@Override
    public override Set<object> keySet()
    {
        checkInitialized();
        return Collections.unmodifiableSet(base.keySet());
    }

    /**
     * Returns an unmodifiable Collection view of the property values
     * contained in this provider.
     *
     * @since 1.2
     */
    //@Override
    public override Collection<object> values()
    {
        checkInitialized();
        return Collections.unmodifiableCollection(base.values());
    }

    /**
     * Sets the {@code key} property to have the specified
     * {@code value}.
     *
     * <p>If a security manager is enabled, its {@code checkSecurityAccess}
     * method is called with the string {@code "putProviderProperty."+name},
     * where {@code name} is the provider name, to see if it's ok to set this
     * provider's property values.
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method
     *          denies access to set property values.
     *
     * @since 1.2
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public object put(object key, object value)
    {
        check("putProviderProperty." + name);
            /*
        if (debug != null)
        {
            debug.println("Set " + name + " provider property [" +
                          key + "/" + value + "]");
        }
        */
        return implPut(key, value);
    }
    /**
     * If the specified key is not already associated with a value (or is mapped
     * to {@code null}) associates it with the given value and returns
     * {@code null}, else returns the current value.
     *
     * <p>If a security manager is enabled, its {@code checkSecurityAccess}
     * method is called with the string {@code "putProviderProperty."+name},
     * where {@code name} is the provider name, to see if it's ok to set this
     * provider's property values.
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method
     *          denies access to set property values.
     *
     * @since 1.8
     */
    // @Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public object putIfAbsent(object key, object value)
    {
        check("putProviderProperty." + name);
            /*
        if (debug != null)
        {
            debug.println("Set " + name + " provider property [" +
                          key + "/" + value + "]");
        }*/
        return implPutIfAbsent(key, value);
    }

    /**
     * Removes the {@code key} property (and its corresponding
     * {@code value}).
     *
     * <p>If a security manager is enabled, its {@code checkSecurityAccess}
     * method is called with the string {@code "removeProviderProperty."+name},
     * where {@code name} is the provider name, to see if it's ok to remove this
     * provider's properties.
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method
     *          denies access to remove this provider's properties.
     *
     * @since 1.2
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]

    public object remove(object key)
    {
        check("removeProviderProperty." + name);
            /*
        if (debug != null)
        {
            debug.println("Remove " + name + " provider property " + key);
        }*/
        return implRemove(key);
    }

    /**
     * Removes the entry for the specified key only if it is currently
     * mapped to the specified value.
     *
     * <p>If a security manager is enabled, its {@code checkSecurityAccess}
     * method is called with the string {@code "removeProviderProperty."+name},
     * where {@code name} is the provider name, to see if it's ok to remove this
     * provider's properties.
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method
     *          denies access to remove this provider's properties.
     *
     * @since 1.8
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public bool remove(object key, object value)
    {
        check("removeProviderProperty." + name);
            /*
        if (debug != null)
        {
            debug.println("Remove " + name + " provider property " + key);
        }*/
        return implRemove(key, value);
    }
    /**
     * Replaces the entry for the specified key only if currently
     * mapped to the specified value.
     *
     * <p>If a security manager is enabled, its {@code checkSecurityAccess}
     * method is called with the string {@code "putProviderProperty."+name},
     * where {@code name} is the provider name, to see if it's ok to set this
     * provider's property values.
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method
     *          denies access to set property values.
     *
     * @since 1.8
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public bool replace(object key, object oldValue,
            object newValue)
    {
        check("putProviderProperty." + name);
            /*
        if (debug != null)
        {
            debug.println("Replace " + name + " provider property " + key);
        }*/
        return implReplace(key, oldValue, newValue);
    }

    /**
     * Replaces the entry for the specified key only if it is
     * currently mapped to some value.
     *
     * <p>If a security manager is enabled, its {@code checkSecurityAccess}
     * method is called with the string {@code "putProviderProperty."+name},
     * where {@code name} is the provider name, to see if it's ok to set this
     * provider's property values.
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method
     *          denies access to set property values.
     *
     * @since 1.8
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public object replace(object key, object value)
    {
        check("putProviderProperty." + name);
            /*
        if (debug != null)
        {
            debug.println("Replace " + name + " provider property " + key);
        }*/
        return implReplace(key, value);
    }
    /**
     * Replaces each entry's value with the result of invoking the given
     * function on that entry, in the order entries are returned by an entry
     * set iterator, until all entries have been processed or the function
     * throws an exception.
     *
     * <p>If a security manager is enabled, its {@code checkSecurityAccess}
     * method is called with the string {@code "putProviderProperty."+name},
     * where {@code name} is the provider name, to see if it's ok to set this
     * provider's property values.
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method
     *          denies access to set property values.
     *
     * @since 1.8
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public void replaceAll(BiFunction<? super object, ? super object, ? extends object> function)
    {
        check("putProviderProperty." + name);
            /*
        if (debug != null)
        {
            debug.println("ReplaceAll " + name + " provider property ");
        }*/
        implReplaceAll(function);
    }

    /**
     * Attempts to compute a mapping for the specified key and its
     * current mapped value (or {@code null} if there is no current
     * mapping).
     *
     * <p>If a security manager is enabled, its {@code checkSecurityAccess}
     * method is called with the strings {@code "putProviderProperty."+name}
     * and {@code "removeProviderProperty."+name}, where {@code name} is the
     * provider name, to see if it's ok to set this provider's property values
     * and remove this provider's properties.
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method
     *          denies access to set property values or remove properties.
     *
     * @since 1.8
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public object compute(object key,
        BiFunction<? super object, ? super object, ? extends object> remappingFunction)
    {
        check("putProviderProperty." + name);
        check("removeProviderProperty" + name);
            /*
        if (debug != null)
        {
            debug.println("Compute " + name + " provider property " + key);
        }
        */
        return implCompute(key, remappingFunction);
    }

    /**
     * If the specified key is not already associated with a value (or
     * is mapped to {@code null}), attempts to compute its value using
     * the given mapping function and enters it into this map unless
     * {@code null}.
     *
     * <p>If a security manager is enabled, its {@code checkSecurityAccess}
     * method is called with the strings {@code "putProviderProperty."+name}
     * and {@code "removeProviderProperty."+name}, where {@code name} is the
     * provider name, to see if it's ok to set this provider's property values
     * and remove this provider's properties.
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method
     *          denies access to set property values and remove properties.
     *
     * @since 1.8
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public object computeIfAbsent(object key, Function<? super object, ? extends object> mappingFunction)
    {
        check("putProviderProperty." + name);
        check("removeProviderProperty" + name);
            /*
        if (debug != null)
        {
            debug.println("ComputeIfAbsent " + name + " provider property " +
                    key);
        }
        */
        return implComputeIfAbsent(key, mappingFunction);
    }
    /**
     * If the value for the specified key is present and non-null, attempts to
     * compute a new mapping given the key and its current mapped value.
     *
     * <p>If a security manager is enabled, its {@code checkSecurityAccess}
     * method is called with the strings {@code "putProviderProperty."+name}
     * and {@code "removeProviderProperty."+name}, where {@code name} is the
     * provider name, to see if it's ok to set this provider's property values
     * and remove this provider's properties.
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method
     *          denies access to set property values or remove properties.
     *
     * @since 1.8
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public object computeIfPresent(object key, BiFunction<? super object, ? super object, ? extends object> remappingFunction)
    {
        check("putProviderProperty." + name);
        check("removeProviderProperty" + name);
            /*
        if (debug != null)
        {
            debug.println("ComputeIfPresent " + name + " provider property " +
                    key);
        }*/
        return implComputeIfPresent(key, remappingFunction);
    }
    /**
     * If the specified key is not already associated with a value or is
     * associated with null, associates it with the given value. Otherwise,
     * replaces the value with the results of the given remapping function,
     * or removes if the result is null. This method may be of use when
     * combining multiple mapped values for a key.
     *
     * <p>If a security manager is enabled, its {@code checkSecurityAccess}
     * method is called with the strings {@code "putProviderProperty."+name}
     * and {@code "removeProviderProperty."+name}, where {@code name} is the
     * provider name, to see if it's ok to set this provider's property values
     * and remove this provider's properties.
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method
     *          denies access to set property values or remove properties.
     *
     * @since 1.8
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public object merge(object key, object value, BiFunction<? super object, ? super object, ? extends object> remappingFunction)
    {
        check("putProviderProperty." + name);
        check("removeProviderProperty" + name);
            /*
        if (debug != null)
        {
            debug.println("Merge " + name + " provider property " + key);
        }*/
        return implMerge(key, value, remappingFunction);
    }

    // let javadoc show doc from superclass
    //@Override
    public object get(object key)
    {
        checkInitialized();
        return base.get(key);
    }
    /**
     * @since 1.8
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public object getOrDefault(object key, object defaultValue)
    {
        checkInitialized();
        return base.getOrDefault(key, defaultValue);
    }

    /**
     * @since 1.8
     */
    //@Override
    [MethodImpl(MethodImplOptions.Synchronized)]
    public void forEach(BiConsumer<? super object, ? super object> action)
    {
        checkInitialized();
        base.forEach(action);
    }

    // let javadoc show doc from superclass
    //@Override
    public Enumeration<object> keys()
    {
        checkInitialized();
        return base.keys();
    }

    // let javadoc show doc from superclass
    //@Override
    public Enumeration<object> elements()
    {
        checkInitialized();
        return base.elements();
    }

    // let javadoc show doc from superclass
    public string getProperty(string key)
    {
        checkInitialized();
        return base.getProperty(key);
    }

    private void checkInitialized()
    {
        if (!initialized)
        {
            throw new IllegalStateException();
        }
    }

    private void check(string directive)
    {
        checkInitialized();
        SecurityManager security = System.getSecurityManager();
        if (security != null)
        {
            security.checkSecurityAccess(directive);
        }
    }

    // legacy properties changed since last call to any services method?
    [NonSerialized]  // equivalent of transient keyword in Java
    private bool legacyChanged;
    // serviceMap changed since last call to getServices()
    [NonSerialized]  // equivalent of transient keyword in Java
    private bool servicesChanged;

    // Map<String,String>
    [NonSerialized]  // equivalent of transient keyword in Java
    private Map<string, string> legacyStrings;

    // Map<ServiceKey,Service>
    // used for services added via putService(), initialized on demand
    [NonSerialized]  // equivalent of transient keyword in Java
    private Map<ServiceKey, Service> serviceMap;

    // Map<ServiceKey,Service>
    // used for services added via legacy methods, init on demand
    [NonSerialized]  // equivalent of transient keyword in Java
    private Map<ServiceKey, Service> legacyMap;

    // Set<Service>
    // Unmodifiable set of all services. Initialized on demand.
    [NonSerialized]  // equivalent of transient keyword in Java
    private Set<Service> serviceSet;

    // register the id attributes for this provider
    // this is to ensure that equals() and hashCode() do not incorrectly
    // report to different provider objects as the same
    private void putId()
    {
        // note: name and info may be null
        base.put("Provider.id name", string.valueOf(name));
        base.put("Provider.id version", string.valueOf(version));
        base.put("Provider.id info", string.valueOf(info));
        base.put("Provider.id className", this.getClass().getName());
    }

    private void readobject(ObjectInputStream In)
    //                throws IOException, ClassNotFoundException
    {
        Map<object, object> copy = new HashMap<>();
        for (Map.Entry<object, object> entry : base.entrySet())
        {
            copy.put(entry.getKey(), entry.getValue());
        }
        defaults = null;
        In.defaultReadobject();
        implClear();
        initialized = true;
        putAll(copy);
    }
    private bool checkLegacy(object key)
    {
        string keyString = (string)key;
        if (keyString.StartsWith("Provider."))
        {
            return false;
        }

        legacyChanged = true;
        if (legacyStrings == null)
        {
            legacyStrings = new LinkedHashMap<string, string>();
        }
        return true;
    }

    /**
     * Copies all of the mappings from the specified Map to this provider.
     * Internal method to be called AFTER the security check has been
     * performed.
     */
    private void implPutAll(Map<?,?> t)
    {
        for (Map.Entry <?,?> e : t.entrySet())
        {
            implPut(e.getKey(), e.getValue());
        }
    }

    private object implRemove(object key)
    {
        if (key is string)
        {
            if (!checkLegacy(key))
            {
                return null;
            }
            legacyStrings.remove((string)key);
        }
        return base.remove(key);
    }

    private bool implRemove(object key, object value)
    {
        if (key is string && value is string)
        {
            if (!checkLegacy(key))
            {
                return false;
            }
            legacyStrings.remove((string)key, value);
        }
        return base.remove(key, value);
    }

    private bool implReplace(object key, object oldValue, object newValue)
    {
        if ((key is string) && (oldValue is string) &&
                (newValue is string))
        {
            if (!checkLegacy(key))
            {
                return false;
            }
            legacyStrings.replace((string)key, (string)oldValue,
                    (string)newValue);
        }
        return base.replace(key, oldValue, newValue);
    }

    private object implReplace(object key, object value)
    {
        if ((key is string) && (value is string))
        {
            if (!checkLegacy(key))
            {
                return null;
            }
            legacyStrings.replace((string)key, (string)value);
        }
        return base.replace(key, value);
    }

    private void implReplaceAll(BiFunction<? super object, ? super object, ? extends object> function)
    {
        legacyChanged = true;
        if (legacyStrings == null)
        {
            legacyStrings = new LinkedHashMap<string, string>();
        }
        else
        {
            legacyStrings.replaceAll((BiFunction <? super string, ? super string, ? extends string >) function);
        }
        base.replaceAll(function);
    }
    private object implMerge(object key, object value, BiFunction<? super object, ? super object, ? extends object> remappingFunction)
    {
        if ((key is string) && (value is string))
        {
            if (!checkLegacy(key))
            {
                return null;
            }
            legacyStrings.merge((string)key, (string)value,
                    (BiFunction <? super string, ? super string, ? extends string >) remappingFunction);
        }
        return base.merge(key, value, remappingFunction);
    }

    private object implCompute(object key, BiFunction<? super object, ? super object, ? extends object> remappingFunction)
    {
        if (key is string)
        {
            if (!checkLegacy(key))
            {
                return null;
            }
            legacyStrings.computeIfAbsent((string)key,
                    (Function <? super string, ? extends string >) remappingFunction);
        }
        return base.compute(key, remappingFunction);
    }

    private object implComputeIfAbsent(object key, Function<? super object, ? extends object> mappingFunction)
    {
        if (key is string)
        {
            if (!checkLegacy(key))
            {
                return null;
            }
            legacyStrings.computeIfAbsent((string)key,
                    (Function <? super string, ? extends string >) mappingFunction);
        }
        return base.computeIfAbsent(key, mappingFunction);
    }

    private object implComputeIfPresent(object key, BiFunction<? super object, ? super object, ? extends object> remappingFunction)
    {
        if (key is string)
        {
            if (!checkLegacy(key))
            {
                return null;
            }
            legacyStrings.computeIfPresent((string)key,
                    (BiFunction <? super string, ? super string, ? extends string >) remappingFunction);
        }
        return base.computeIfPresent(key, remappingFunction);
    }

    private object implPut(object key, object value)
    {
        if ((key is string) && (value is string))
        {
            if (!checkLegacy(key))
            {
                return null;
            }
            legacyStrings.put((string)key, (string)value);
        }
        return base.put(key, value);
    }

    private object implPutIfAbsent(object key, object value)
    {
        if ((key is string) && (value is string))
        {
            if (!checkLegacy(key))
            {
                return null;
            }
            legacyStrings.putIfAbsent((string)key, (string)value);
        }
        return base.putIfAbsent(key, value);
    }

    private void implClear()
    {
        if (legacyStrings != null)
        {
            legacyStrings.clear();
        }
        if (legacyMap != null)
        {
            legacyMap.clear();
        }
        if (serviceMap != null)
        {
            serviceMap.clear();
        }
        legacyChanged = false;
        servicesChanged = false;
        serviceSet = null;
        base.clear();
        putId();
    }

    // used as key in the serviceMap and legacyMap HashMaps
    private static class ServiceKey
    {
        private readonly string type;
        private readonly string algorithm;
        private readonly string originalAlgorithm;
        private ServiceKey(string type, string algorithm, bool intern)
        {
            this.type = type;
            this.originalAlgorithm = algorithm;
            algorithm = algorithm.ToUpper(ENGLISH);
            this.algorithm = intern ? algorithm.intern() : algorithm;
        }
        public int hashCode()
        {
            return type.hashCode() + algorithm.hashCode();
        }
        public bool equals(object obj)
        {
            if (this == obj)
            {
                return true;
            }
            if (obj is ServiceKey == false)
            {
                return false;
            }
            ServiceKey other = (ServiceKey)obj;
            return this.type.Equals(other.type)
                && this.algorithm.Equals(other.algorithm);
        }
        bool matches(string type, string algorithm)
        {
            return (this.type == type) && (this.originalAlgorithm == algorithm);
        }
    }

    /**
     * Ensure all the legacy string properties are fully parsed into
     * service objects.
     */
    private void ensureLegacyParsed()
    {
        if ((legacyChanged == false) || (legacyStrings == null))
        {
            return;
        }
        serviceSet = null;
        if (legacyMap == null)
        {
            legacyMap = new LinkedHashMap<ServiceKey, Service>();
        }
        else
        {
            legacyMap.clear();
        }
        for (Map.Entry<string, string> entry : legacyStrings.entrySet())
        {
            parseLegacyPut(entry.getKey(), entry.getValue());
        }
        removeInvalidServices(legacyMap);
        legacyChanged = false;
    }

    /**
     * Remove all invalid services from the Map. Invalid services can only
     * occur if the legacy properties are inconsistent or incomplete.
     */
    private void removeInvalidServices(Map<ServiceKey, Service> map)
    {
        for (Iterator<Map.Entry<ServiceKey, Service>> t =
                map.entrySet().iterator(); t.hasNext();)
        {
            Service s = t.next().getValue();
            if (s.isValid() == false)
            {
                t.remove();
            }
        }
    }

    private string[] getTypeAndAlgorithm(string key)
    {
        int i = key.IndexOf(".");
        if (i < 1)
        {
                /*
            if (debug != null)
            {
                debug.println("Ignoring invalid entry in provider "
                        + name + ":" + key);
            }*/
            return null;
        }
        string type = key.Substring(0, i);
        string alg = key.Substring(i + 1);
        return new string[] { type, alg };
    }

    private readonly static string ALIAS_PREFIX = "Alg.Alias.";
    private readonly static string ALIAS_PREFIX_LOWER = "alg.alias.";
    private readonly static int ALIAS_LENGTH = ALIAS_PREFIX.Length;

    private void parseLegacyPut(string name, string value)
    {
        if (name.ToLower(ENGLISH).startsWith(ALIAS_PREFIX_LOWER))
        {
            // e.g. put("Alg.Alias.MessageDigest.SHA", "SHA-1");
            // aliasKey ~ MessageDigest.SHA
            string stdAlg = value;
            string aliasKey = name.Substring(ALIAS_LENGTH);
            string[] typeAndAlg = getTypeAndAlgorithm(aliasKey);
            if (typeAndAlg == null)
            {
                return;
            }
            string type = getEngineName(typeAndAlg[0]);
            string aliasAlg = typeAndAlg[1].intern();
            ServiceKey key = new ServiceKey(type, stdAlg, true);
            Service s = legacyMap.get(key);
            if (s == null)
            {
                s = new Service(this);
                s.type = type;
                s.algorithm = stdAlg;
                legacyMap.put(key, s);
            }
            legacyMap.put(new ServiceKey(type, aliasAlg, true), s);
            s.addAlias(aliasAlg);
        }
        else
        {
            string[] typeAndAlg = getTypeAndAlgorithm(name);
            if (typeAndAlg == null)
            {
                return;
            }
            int i = typeAndAlg[1].IndexOf(' ');
            if (i == -1)
            {
                // e.g. put("MessageDigest.SHA-1", "sun.security.provider.SHA");
                string type = getEngineName(typeAndAlg[0]);
                string stdAlg = typeAndAlg[1].intern();
                string className = value;
                ServiceKey key = new ServiceKey(type, stdAlg, true);
                Service s = legacyMap.get(key);
                if (s == null)
                {
                    s = new Service(this);
                    s.type = type;
                    s.algorithm = stdAlg;
                    legacyMap.put(key, s);
                }
                s.className = className;
            }
            else
            { // attribute
              // e.g. put("MessageDigest.SHA-1 ImplementedIn", "Software");
                string attributeValue = value;
                string type = getEngineName(typeAndAlg[0]);
                string attributeString = typeAndAlg[1];
                string stdAlg = attributeString.Substring(0, i).intern();
                string attributeName = attributeString.Substring(i + 1);
                // kill additional spaces
                while (attributeName.StartsWith(" "))
                {
                    attributeName = attributeName.Substring(1);
                }
                attributeName = attributeName.intern();
                ServiceKey key = new ServiceKey(type, stdAlg, true);
                Service s = legacyMap.get(key);
                if (s == null)
                {
                    s = new Service(this);
                    s.type = type;
                    s.algorithm = stdAlg;
                    legacyMap.put(key, s);
                }
                s.addAttribute(attributeName, attributeValue);
            }
        }
    }

    /**
     * Get the service describing this Provider's implementation of the
     * specified type of this algorithm or alias. If no such
     * implementation exists, this method returns null. If there are two
     * matching services, one added to this provider using
     * {@link #putService putService()} and one added via {@link #put put()},
     * the service added via {@link #putService putService()} is returned.
     *
     * @param type the type of {@link Service service} requested
     * (for example, {@code MessageDigest})
     * @param algorithm the case insensitive algorithm name (or alternate
     * alias) of the service requested (for example, {@code SHA-1})
     *
     * @return the service describing this Provider's matching service
     * or null if no such service exists
     *
     * @throws NullPointerException if type or algorithm is null
     *
     * @since 1.5
     */
    [MethodImpl(MethodImplOptions.Synchronized)]
    public Service getService(string type, string algorithm)
    {
        checkInitialized();
        // avoid allocating a new key object if possible
        ServiceKey key = previousKey;
        if (key.matches(type, algorithm) == false)
        {
            key = new ServiceKey(type, algorithm, false);
            previousKey = key;
        }
        if (serviceMap != null)
        {
            Service service = serviceMap.get(key);
            if (service != null)
            {
                return service;
            }
        }
        ensureLegacyParsed();
        return (legacyMap != null) ? legacyMap.get(key) : null;
    }

    // ServiceKey from previous getService() call
    // by re-using it if possible we avoid allocating a new object
    // and the toUpperCase() call.
    // re-use will occur e.g. as the framework traverses the provider
    // list and queries each provider with the same values until it finds
    // a matching service
    private static volatile ServiceKey previousKey =
                                            new ServiceKey("", "", false);

    /**
     * Get an unmodifiable Set of all services supported by
     * this Provider.
     *
     * @return an unmodifiable Set of all services supported by
     * this Provider
     *
     * @since 1.5
     */
    [MethodImpl(MethodImplOptions.Synchronized)]
    public Set<Service> getServices()
    {
        checkInitialized();
        if (legacyChanged || servicesChanged)
        {
            serviceSet = null;
        }
        if (serviceSet == null)
        {
            ensureLegacyParsed();
            Set<Service> set = new LinkedHashSet<>();
            if (serviceMap != null)
            {
                set.addAll(serviceMap.values());
            }
            if (legacyMap != null)
            {
                set.addAll(legacyMap.values());
            }
            serviceSet = Collections.unmodifiableSet(set);
            servicesChanged = false;
        }
        return serviceSet;
    }

    /**
     * Add a service. If a service of the same type with the same algorithm
     * name exists and it was added using {@link #putService putService()},
     * it is replaced by the new service.
     * This method also places information about this service
     * in the provider's Hashtable values in the format described in the
     * <a href="../../../technotes/guides/security/crypto/CryptoSpec.html">
     * Java Cryptography Architecture API Specification &amp; Reference </a>.
     *
     * <p>Also, if there is a security manager, its
     * {@code checkSecurityAccess} method is called with the string
     * {@code "putProviderProperty."+name}, where {@code name} is
     * the provider name, to see if it's ok to set this provider's property
     * values. If the default implementation of {@code checkSecurityAccess}
     * is used (that is, that method is not overriden), then this results in
     * a call to the security manager's {@code checkPermission} method with
     * a {@code SecurityPermission("putProviderProperty."+name)}
     * permission.
     *
     * @param s the Service to add
     *
     * @throws SecurityException
     *      if a security manager exists and its {@link
     *      java.lang.SecurityManager#checkSecurityAccess} method denies
     *      access to set property values.
     * @throws NullPointerException if s is null
     *
     * @since 1.5
     */
    [MethodImpl(MethodImplOptions.Synchronized)]
    protected void putService(Service s)
    {
        check("putProviderProperty." + name);
            /*
        if (debug != null)
        {
            debug.println(name + ".putService(): " + s);
        }*/
        if (s == null)
        {
            throw new NullPointerException();
        }
        if (s.getProvider() != this)
        {
            throw new IllegalArgumentException
                    ("service.getProvider() must match this Provider object");
        }
        if (serviceMap == null)
        {
            serviceMap = new LinkedHashMap<ServiceKey, Service>();
        }
        servicesChanged = true;
        string type = s.getType();
        string algorithm = s.getAlgorithm();
        ServiceKey key = new ServiceKey(type, algorithm, true);
        // remove existing service
        implRemoveService(serviceMap.get(key));
        serviceMap.put(key, s);
        for (string alias : s.getAliases())
        {
            serviceMap.put(new ServiceKey(type, alias, true), s);
        }
        putPropertyStrings(s);
    }

    /**
     * Put the string properties for this Service in this Provider's
     * Hashtable.
     */
    private void putPropertyStrings(Service s)
    {
        string type = s.getType();
        string algorithm = s.getAlgorithm();
        // use super() to avoid permission check and other processing
        base.put(type + "." + algorithm, s.getClassName());
        for (string alias : s.getAliases())
        {
            base.put(ALIAS_PREFIX + type + "." + alias, algorithm);
        }
        for (Map.Entry<UString, string> entry : s.attributes.entrySet())
        {
            string key = type + "." + algorithm + " " + entry.getKey();
            base.put(key, entry.getValue());
        }
    }

    /**
     * Remove the string properties for this Service from this Provider's
     * Hashtable.
     */
    private void removePropertyStrings(Service s)
    {
        string type = s.getType();
        string algorithm = s.getAlgorithm();
        // use super() to avoid permission check and other processing
        base.remove(type + "." + algorithm);
        for (string alias : s.getAliases())
        {
            base.remove(ALIAS_PREFIX + type + "." + alias);
        }
        for (Map.Entry<UString, string> entry : s.attributes.entrySet())
        {
            string key = type + "." + algorithm + " " + entry.getKey();
            base.remove(key);
        }
    }

    /**
     * Remove a service previously added using
     * {@link #putService putService()}. The specified service is removed from
     * this provider. It will no longer be returned by
     * {@link #getService getService()} and its information will be removed
     * from this provider's Hashtable.
     *
     * <p>Also, if there is a security manager, its
     * {@code checkSecurityAccess} method is called with the string
     * {@code "removeProviderProperty."+name}, where {@code name} is
     * the provider name, to see if it's ok to remove this provider's
     * properties. If the default implementation of
     * {@code checkSecurityAccess} is used (that is, that method is not
     * overriden), then this results in a call to the security manager's
     * {@code checkPermission} method with a
     * {@code SecurityPermission("removeProviderProperty."+name)}
     * permission.
     *
     * @param s the Service to be removed
     *
     * @throws  SecurityException
     *          if a security manager exists and its {@link
     *          java.lang.SecurityManager#checkSecurityAccess} method denies
     *          access to remove this provider's properties.
     * @throws NullPointerException if s is null
     *
     * @since 1.5
     */
    [MethodImpl(MethodImplOptions.Synchronized)]
    protected void removeService(Service s)
    {
        check("removeProviderProperty." + name);
            /*
        if (debug != null)
        {
            debug.println(name + ".removeService(): " + s);
        }
        */
        if (s == null)
        {
            throw new NullPointerException();
        }
        implRemoveService(s);
    }

    private void implRemoveService(Service s)
    {
        if ((s == null) || (serviceMap == null))
        {
            return;
        }
        string type = s.getType();
        string algorithm = s.getAlgorithm();
        ServiceKey key = new ServiceKey(type, algorithm, false);
        Service oldService = serviceMap.get(key);
        if (s != oldService)
        {
            return;
        }
        servicesChanged = true;
        serviceMap.remove(key);
        for (string alias : s.getAliases())
        {
            serviceMap.remove(new ServiceKey(type, alias, false));
        }
        removePropertyStrings(s);
    }

    // Wrapped string that behaves in a case insensitive way for equals/hashCode
    public /*static*/ class UString
    {
        readonly string _string;
        readonly string lowerString;

        UString(string s)
        {
            this._string = s;
            this.lowerString = s.ToLower(ENGLISH);
        }

        public int hashCode()
        {
            return lowerString.GetHashCode();
        }

        public bool equals(object obj)
        {
            if (this == obj)
            {
                return true;
            }
            if (obj is UString == false)
            {
                return false;
            }
            UString other = (UString)obj;
            return lowerString.Equals(other.lowerString);
        }

        public string toString()
        {
            return _string;
        }
    }

    // describe relevant properties of a type of engine
    public /*static*/ class EngineDescription
    {
        readonly string name;
        readonly bool supportsParameter;
        readonly string constructorParameterClassName;
        private volatile Class<?> constructorParameterClass;

        EngineDescription(string name, bool sp, string paramName)
        {
            this.name = name;
            this.supportsParameter = sp;
            this.constructorParameterClassName = paramName;
        }
        Class<?> getConstructorParameterClass() //throws ClassNotFoundException
        {
            Class <?> clazz = constructorParameterClass;
            if (clazz == null)
            {
                clazz = Class.forName(constructorParameterClassName);
                constructorParameterClass = clazz;
            }
            return clazz;
        }
    }

    // built in knowledge of the engine types shipped as part of the JDK
    private static readonly Map<string, EngineDescription> knownEngines;

    private static void addEngine(string name, bool sp, string paramName)
    {
        EngineDescription ed = new EngineDescription(name, sp, paramName);
        // also index by canonical name to avoid toLowerCase() for some lookups
        knownEngines.put(name.ToLower(ENGLISH), ed);
        knownEngines.put(name, ed);
    }

    static {
        knownEngines = new Dictionary<string, EngineDescription>();
        // JCA
        addEngine("AlgorithmParameterGenerator",        false, null);
        addEngine("AlgorithmParameters",                false, null);
        addEngine("KeyFactory",                         false, null);
        addEngine("KeyPairGenerator",                   false, null);
        addEngine("KeyStore",                           false, null);
        addEngine("MessageDigest",                      false, null);
        addEngine("SecureRandom",                       false, null);
        addEngine("Signature",                          true,  null);
        addEngine("CertificateFactory",                 false, null);
        addEngine("CertPathBuilder",                    false, null);
        addEngine("CertPathValidator",                  false, null);
        addEngine("CertStore",                          false,
                            "java.security.cert.CertStoreParameters");
        // JCE
        addEngine("Cipher",                             true,  null);
        addEngine("ExemptionMechanism",                 false, null);
        addEngine("Mac",                                true,  null);
        addEngine("KeyAgreement",                       true,  null);
        addEngine("KeyGenerator",                       false, null);
        addEngine("SecretKeyFactory",                   false, null);
        // JSSE
        addEngine("KeyManagerFactory",                  false, null);
        addEngine("SSLContext",                         false, null);
        addEngine("TrustManagerFactory",                false, null);
        // JGSS
        addEngine("GssApiMechanism",                    false, null);
        // SASL
        addEngine("SaslClientFactory",                  false, null);
        addEngine("SaslServerFactory",                  false, null);
        // POLICY
        addEngine("Policy",                             false,
                            "java.security.Policy$Parameters");
        // CONFIGURATION
        addEngine("Configuration",                      false,
                            "javax.security.auth.login.Configuration$Parameters");
        // XML DSig
        addEngine("XMLSignatureFactory",                false, null);
        addEngine("KeyInfoFactory",                     false, null);
        addEngine("TransformService",                   false, null);
        // Smart Card I/O
        addEngine("TerminalFactory",                    false,
                            "java.lang.object");
}

// get the "standard" (mixed-case) engine name for arbitary case engine name
// if there is no known engine by that name, return s
private static string getEngineName(string s)
{
    // try original case first, usually correct
    EngineDescription e = knownEngines.get(s);
    if (e == null)
    {
        e = knownEngines.get(s.ToLower(ENGLISH));
    }
    return (e == null) ? s : e.name;
}

/**
 * The description of a security service. It encapsulates the properties
 * of a service and contains a factory method to obtain new implementation
 * instances of this service.
 *
 * <p>Each service has a provider that offers the service, a type,
 * an algorithm name, and the name of the class that implements the
 * service. Optionally, it also includes a list of alternate algorithm
 * names for this service (aliases) and attributes, which are a map of
 * (name, value) string pairs.
 *
 * <p>This class defines the methods {@link #supportsParameter
 * supportsParameter()} and {@link #newInstance newInstance()}
 * which are used by the Java security framework when it searches for
 * suitable services and instantiates them. The valid arguments to those
 * methods depend on the type of service. For the service types defined
 * within Java SE, see the
 * <a href="../../../technotes/guides/security/crypto/CryptoSpec.html">
 * Java Cryptography Architecture API Specification &amp; Reference </a>
 * for the valid values.
 * Note that components outside of Java SE can define additional types of
 * services and their behavior.
 *
 * <p>Instances of this class are immutable.
 *
 * @since 1.5
 */
public class Service
{
    private string type, algorithm, className;
    private readonly Provider provider;
    private List<string> aliases;
    private Dictionary<UString, string> attributes;
    // Reference to the cached implementation Class object
    private volatile Reference<Class<?>> classRef;
    // flag indicating whether this service has its attributes for
    // supportedKeyFormats or supportedKeyClasses set
    // if null, the values have not been initialized
    // if TRUE, at least one of supportedFormats/Classes is non null
    private volatile bool hasKeyAttributes;
    // supported encoding formats
    private string[] supportedFormats;
    // names of the supported key (super) classes
    private Class[] supportedClasses;
    // whether this service has been registered with the Provider
    private bool registered;
    private static readonly Class<?>[] CLASS0 = new Class<?>[0];
    // this constructor and these methods are used for parsing
    // the legacy string properties.
    private Service(Provider provider)
    {
        this.provider = provider;
        aliases = Collections.< string > emptyList();
        attributes = Collections.< UString, string > emptyMap();
    }
    private bool isValid()
    {
        return (type != null) && (algorithm != null) && (className != null);
    }
    private void addAlias(string alias)
    {
        if (aliases.isEmpty())
        {
            aliases = new ArrayList<string>(2);
        }
        aliases.Add(alias);
    }

    void addAttribute(string type, string value)
    {
        if (attributes.isEmpty())
        {
            attributes = new Dictionary<UString, string>(8);
        }
        attributes.put(new UString(type), value);
    }
    /**
     * Construct a new service.
     *
     * @param provider the provider that offers this service
     * @param type the type of this service
     * @param algorithm the algorithm name
     * @param className the name of the class implementing this service
     * @param aliases List of aliases or null if algorithm has no aliases
     * @param attributes Map of attributes or null if this implementation
     *                   has no attributes
     *
     * @throws NullPointerException if provider, type, algorithm, or
     * className is null
     */
    public Service(Provider provider, string type, string algorithm,
            string className, List<string> aliases,
            Dictionary<string, string> attributes)
    {
        if ((provider == null) || (type == null) ||
                (algorithm == null) || (className == null))
        {
            throw new NullPointerException();
        }
        this.provider = provider;
        this.type = getEngineName(type);
        this.algorithm = algorithm;
        this.className = className;
        if (aliases == null)
        {
            this.aliases = Collections.< string > emptyList();
        }
        else
        {
            this.aliases = new ArrayList<string>(aliases);
        }
        if (attributes == null)
        {
            this.attributes = Collections.< UString, string > emptyMap();
        }
        else
        {
            this.attributes = new Dictionary<UString, string>();
            for (Map.Entry<string, string> entry : attributes.entrySet())
            {
                this.attributes.put(new UString(entry.getKey()), entry.getValue());
            }
        }
    }
    /**
     * Get the type of this service. For example, {@code MessageDigest}.
     *
     * @return the type of this service
     */
    public string getType()
    {
        return type;
    }
    /**
     * Return the name of the algorithm of this service. For example,
     * {@code SHA-1}.
     *
     * @return the algorithm of this service
     */
    public string getAlgorithm()
    {
        return algorithm;
    }
    /**
     * Return the Provider of this service.
     *
     * @return the Provider of this service
     */
    public Provider getProvider()
    {
        return provider;
    }
    /**
     * Return the name of the class implementing this service.
     *
     * @return the name of the class implementing this service
     */
    public string getClassName()
    {
        return className;
    }
    // internal only
    private List<string> getAliases()
    {
        return aliases;
    }

    /**
     * Return the value of the specified attribute or null if this
     * attribute is not set for this Service.
     *
     * @param name the name of the requested attribute
     *
     * @return the value of the specified attribute or null if the
     *         attribute is not present
     *
     * @throws NullPointerException if name is null
     */
    public string getAttribute(string name)
    {
        if (name == null)
        {
            throw new NullPointerException();
        }
        return attributes.get(new UString(name));
    }
    /**
     * Return a new instance of the implementation described by this
     * service. The security provider framework uses this method to
     * construct implementations. Applications will typically not need
     * to call it.
     *
     * <p>The default implementation uses reflection to invoke the
     * standard constructor for this type of service.
     * Security providers can override this method to implement
     * instantiation in a different way.
     * For details and the values of constructorParameter that are
     * valid for the various types of services see the
     * <a href="../../../technotes/guides/security/crypto/CryptoSpec.html">
     * Java Cryptography Architecture API Specification &amp;
     * Reference</a>.
     *
     * @param constructorParameter the value to pass to the constructor,
     * or null if this type of service does not use a constructorParameter.
     *
     * @return a new implementation of this service
     *
     * @throws InvalidParameterException if the value of
     * constructorParameter is invalid for this type of service.
     * @throws NoSuchAlgorithmException if instantiation failed for
     * any other reason.
     */
    public object newInstance(object constructorParameter)
    //                throws NoSuchAlgorithmException
    {
        if (registered == false)
        {
            if (provider.getService(type, algorithm) != this)
            {
                throw new NoSuchAlgorithmException
                    ("Service not registered with Provider "
                    + provider.getName() + ": " + this);
            }
            registered = true;
        }
        try
        {
            EngineDescription cap = knownEngines.get(type);
            if (cap == null)
            {
                // unknown engine type, use generic code
                // this is the code path future for non-core
                // optional packages
                return newInstanceGeneric(constructorParameter);
            }
            if (cap.constructorParameterClassName == null)
            {
                if (constructorParameter != null)
                {
                    throw new InvalidParameterException
                        ("constructorParameter not used with " + type
                        + " engines");
                }
                Class <?> clazz = getImplClass();
                Class <?>[] empty = { };
                Constructor <?> con = clazz.getConstructor(empty);
                return con.newInstance();
            }
            else
            {
                Class <?> paramClass = cap.getConstructorParameterClass();
                if (constructorParameter != null)
                {
                    Class <?> argClass = constructorParameter.getClass();
                    if (paramClass.isAssignableFrom(argClass) == false)
                    {
                        throw new InvalidParameterException
                        ("constructorParameter must be is "
                        + cap.constructorParameterClassName.replace('$', '.')
                        + " for engine type " + type);
                    }
                }
                Class <?> clazz = getImplClass();
                Constructor <?> cons = clazz.getConstructor(paramClass);
                return cons.newInstance(constructorParameter);
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            throw e;
        }
        catch (InvocationTargetException e)
        {
            throw new NoSuchAlgorithmException
                ("Error constructing implementation (algorithm: "
                + algorithm + ", provider: " + provider.getName()
                + ", class: " + className + ")", e.getCause());
        }
        catch (Exception e)
        {
            throw new NoSuchAlgorithmException
                ("Error constructing implementation (algorithm: "
                + algorithm + ", provider: " + provider.getName()
                + ", class: " + className + ")", e);
        }
    }
    // return the implementation Class object for this service
    private Class<?> getImplClass()// throws NoSuchAlgorithmException
    {
        try
        {
            Reference < Class <?>> ref = classRef;
            Class <?> clazz = (ref == null) ? null : ref.get();
            if (clazz == null)
            {
                ClassLoader cl = provider.getClass().getClassLoader();
                if (cl == null)
                {
                    clazz = Class.forName(className);
                }
                else
                {
                    clazz = cl.loadClass(className);
                }
                if (!Modifier.isPublic(clazz.getModifiers()))
                {
                    throw new NoSuchAlgorithmException
                        ("class configured for " + type + " (provider: " +
                        provider.getName() + ") is not public.");
                }
                classRef = new WeakReference<Class<?>>(clazz);
            }
            return clazz;
        }
        catch (ClassNotFoundException e)
        {
            throw new NoSuchAlgorithmException
                ("class configured for " + type + " (provider: " +
                provider.getName() + ") cannot be found.", e);
        }
    }
    /**
     * Generic code path for unknown engine types. Call the
     * no-args constructor if constructorParameter is null, otherwise
     * use the first matching constructor.
     */
    private object newInstanceGeneric(object constructorParameter)
    //               throws Exception
    {
        Class <?> clazz = getImplClass();
        if (constructorParameter == null)
        {
            // create instance with public no-arg constructor if it exists
            try
            {
                Class <?>[] empty = { };
                Constructor <?> con = clazz.getConstructor(empty);
                return con.newInstance();
            }
            catch (NoSuchMethodException e)
            {
                throw new NoSuchAlgorithmException("No public no-arg "
                    + "constructor found in class " + className);
            }
        }
        Class <?> argClass = constructorParameter.getClass();
        Constructor[]
        cons = clazz.getConstructors();
        // find first public constructor that can take the
        // argument as parameter
        for (Constructor <?> con : cons)
        {
            Class <?>[] paramTypes = con.getParameterTypes();
            if (paramTypes.length != 1)
            {
                continue;
            }
            if (paramTypes[0].isAssignableFrom(argClass) == false)
            {
                continue;
            }
            return con.newInstance(constructorParameter);
        }
        throw new NoSuchAlgorithmException("No public constructor matching "
            + argClass.getName() + " found in class " + className);
    }
    /**
     * Test whether this Service can use the specified parameter.
     * Returns false if this service cannot use the parameter. Returns
     * true if this service can use the parameter, if a fast test is
     * infeasible, or if the status is unknown.
     *
     * <p>The security provider framework uses this method with
     * some types of services to quickly exclude non-matching
     * implementations for consideration.
     * Applications will typically not need to call it.
     *
     * <p>For details and the values of parameter that are valid for the
     * various types of services see the top of this class and the
     * <a href="../../../technotes/guides/security/crypto/CryptoSpec.html">
     * Java Cryptography Architecture API Specification &amp;
     * Reference</a>.
     * Security providers can override it to implement their own test.
     *
     * @param parameter the parameter to test
     *
     * @return false if this this service cannot use the specified
     * parameter; true if it can possibly use the parameter
     *
     * @throws InvalidParameterException if the value of parameter is
     * invalid for this type of service or if this method cannot be
     * used with this type of service
     */
    public bool supportsParameter(object parameter)
    {
        EngineDescription cap = knownEngines.get(type);
        if (cap == null)
        {
            // unknown engine type, return true by default
            return true;
        }
        if (cap.supportsParameter == false)
        {
            throw new InvalidParameterException("supportsParameter() not "
                + "used with " + type + " engines");
        }
        // allow null for keys without attributes for compatibility
        if ((parameter != null) && (parameter is Key == false))
        {
            throw new InvalidParameterException
                ("Parameter must be is Key for engine " + type);
        }
        if (hasKeyAttributes() == false)
        {
            return true;
        }
        if (parameter == null)
        {
            return false;
        }
        Key key = (Key)parameter;
        if (supportsKeyFormat(key))
        {
            return true;
        }
        if (supportsKeyClass(key))
        {
            return true;
        }
        return false;
    }
    /**
     * Return whether this service has its Supported* properties for
     * keys defined. Parses the attributes if not yet initialized.
     */
    private bool hasKeyAttributes()
    {
        bool b = hasKeyAttributes;
        if (b == null)
        {
            lock(this) {
                string s;
                s = getAttribute("SupportedKeyFormats");
                if (s != null)
                {
                    supportedFormats = s.split("\\|");
                }
                s = getAttribute("SupportedKeyClasses");
                if (s != null)
                {
                    string[] classNames = s.split("\\|");
                    List < Class <?>> classList =
                        new ArrayList<>(classNames.length);
                    for (string className : classNames)
                    {
                        Class <?> clazz = getKeyClass(className);
                        if (clazz != null)
                        {
                            classList.add(clazz);
                        }
                    }
                    supportedClasses = classList.toArray(CLASS0);
                }
                bool _bool = (supportedFormats != null)
                    || (supportedClasses != null);
                b = bool.valueOf(_bool);
                hasKeyAttributes = b;
            }
        }
        return b.boolValue();
    }
    // get the key class object of the specified name
    private Class<?> getKeyClass(string name)
    {
        try
        {
            return Class.forName(name);
        }
        catch (ClassNotFoundException e)
        {
            // ignore
        }
        try
        {
            ClassLoader cl = provider.getClass().getClassLoader();
            if (cl != null)
            {
                return cl.loadClass(name);
            }
        }
        catch (ClassNotFoundException e)
        {
            // ignore
        }
        return null;
    }
    private bool supportsKeyFormat(Key key)
    {
        if (supportedFormats == null)
        {
            return false;
        }
        string format = key.getFormat();
        if (format == null)
        {
            return false;
        }
        for (string supportedFormat : supportedFormats)
        {
            if (supportedFormat.equals(format))
            {
                return true;
            }
        }
        return false;
    }
    private bool supportsKeyClass(Key key)
    {
        if (supportedClasses == null)
        {
            return false;
        }
        Class <?> keyClass = key.getClass();
        for (Class <?> clazz : supportedClasses)
        {
            if (clazz.isAssignableFrom(keyClass))
            {
                return true;
            }
        }
        return false;
    }
    /**
     * Return a string representation of this service.
     *
     * @return a string representation of this service.
     */
    public string toString()
    {
        string aString = aliases.isEmpty()
            ? "" : "\r\n  aliases: " + aliases.ToString();
        string attrs = attributes.isEmpty()
            ? "" : "\r\n  attributes: " + attributes.ToString();
        return provider.getName() + ": " + type + "." + algorithm
            + " -> " + className + aString + attrs + "\r\n";
    }
}
}
}