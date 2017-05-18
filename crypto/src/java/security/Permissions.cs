﻿using java.security;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;

namespace java.security
{
    /*
     * Copyright (c) 1997, 2013, Oracle and/or its affiliates. All rights reserved.
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

    import java.util.Enumeration;
    import java.util.Hashtable;
    import java.util.NoSuchElementException;
    import java.util.Map;
    import java.util.HashMap;
    import java.util.List;
    import java.util.Iterator;
    import java.util.Collections;
    import java.io.Serializable;
    import java.io.ObjectStreamField;
    import java.io.ObjectOutputStream;
    import java.io.ObjectInputStream;
    import java.io.IOException;
    */

    /**
     * This class represents a heterogeneous collection of Permissions. That is,
     * it contains different types of Permission objects, organized into
     * PermissionCollections. For example, if any
     * {@code java.io.FilePermission} objects are added to an instance of
     * this class, they are all stored in a single
     * PermissionCollection. It is the PermissionCollection returned by a call to
     * the {@code newPermissionCollection} method in the FilePermission class.
     * Similarly, any {@code java.lang.RuntimePermission} objects are
     * stored in the PermissionCollection returned by a call to the
     * {@code newPermissionCollection} method in the
     * RuntimePermission class. Thus, this class represents a collection of
     * PermissionCollections.
     *
     * <p>When the {@code add} method is called to add a Permission, the
     * Permission is stored in the appropriate PermissionCollection. If no such
     * collection exists yet, the Permission object's class is determined and the
     * {@code newPermissionCollection} method is called on that class to create
     * the PermissionCollection and add it to the Permissions object. If
     * {@code newPermissionCollection} returns null, then a default
     * PermissionCollection that uses a hashtable will be created and used. Each
     * hashtable entry stores a Permission object as both the key and the value.
     *
     * <p> Enumerations returned via the {@code elements} method are
     * not <em>fail-fast</em>.  Modifications to a collection should not be
     * performed while enumerating over that collection.
     *
     * @see Permission
     * @see PermissionCollection
     * @see AllPermission
     *
     *
     * @author Marianne Mueller
     * @author Roland Schemers
     *
     * @serial exclude
     */

    public sealed class Permissions : PermissionCollection, ISerializable
    {
    /**
     * Key is permissions Class, value is PermissionCollection for that class.
     * Not serialized; see serialization section at end of class.
     */
     [NonSerialized]
    private Dictionary<Class<?>, PermissionCollection> permsMap;

        // optimization. keep track of whether unresolved permissions need to be
        // checked
        [NonSerialized]
        private bool hasUnresolved = false;

    // optimization. keep track of the AllPermission collection
    // - package private for ProtectionDomain optimization
    PermissionCollection allPermission;

    /**
     * Creates a new Permissions object containing no PermissionCollections.
     */
    public Permissions()
    {
        permsMap = new Dictionary<Class<?>, PermissionCollection>(11);
        allPermission = null;
    }

    /**
     * Adds a permission object to the PermissionCollection for the class the
     * permission belongs to. For example, if <i>permission</i> is a
     * FilePermission, it is added to the FilePermissionCollection stored
     * in this Permissions object.
     *
     * This method creates
     * a new PermissionCollection object (and adds the permission to it)
     * if an appropriate collection does not yet exist. <p>
     *
     * @param permission the Permission object to add.
     *
     * @exception SecurityException if this Permissions object is
     * marked as readonly.
     *
     * @see PermissionCollection#isReadOnly()
     */

    public void add(Permission permission)
    {
        if (isReadOnly())
            throw new SecurityException(
              "attempt to add a Permission to a readonly Permissions object");

        PermissionCollection pc;

        lock(this) {
            pc = getPermissionCollection(permission, true);
            pc.add(permission);
        }

        // No sync; staleness -> optimizations delayed, which is OK
        if (permission is AllPermission) {
            allPermission = pc;
        }
        if (permission is UnresolvedPermission) {
            hasUnresolved = true;
        }
    }

    /**
     * Checks to see if this object's PermissionCollection for permissions of
     * the specified permission's class implies the permissions
     * expressed in the <i>permission</i> object. Returns true if the
     * combination of permissions in the appropriate PermissionCollection
     * (e.g., a FilePermissionCollection for a FilePermission) together
     * imply the specified permission.
     *
     * <p>For example, suppose there is a FilePermissionCollection in this
     * Permissions object, and it contains one FilePermission that specifies
     * "read" access for  all files in all subdirectories of the "/tmp"
     * directory, and another FilePermission that specifies "write" access
     * for all files in the "/tmp/scratch/foo" directory.
     * Then if the {@code implies} method
     * is called with a permission specifying both "read" and "write" access
     * to files in the "/tmp/scratch/foo" directory, {@code true} is
     * returned.
     *
     * <p>Additionally, if this PermissionCollection contains the
     * AllPermission, this method will always return true.
     * <p>
     * @param permission the Permission object to check.
     *
     * @return true if "permission" is implied by the permissions in the
     * PermissionCollection it
     * belongs to, false if not.
     */

    public bool implies(Permission permission)
    {
        // No sync; staleness -> skip optimization, which is OK
        if (allPermission != null)
        {
            return true; // AllPermission has already been added
        }
        else
        {
            lock(this) {
                PermissionCollection pc = getPermissionCollection(permission,
                    false);
                if (pc != null)
                {
                    return pc.implies(permission);
                }
                else
                {
                    // none found
                    return false;
                }
            }
        }
    }

    /**
     * Returns an enumeration of all the Permission objects in all the
     * PermissionCollections in this Permissions object.
     *
     * @return an enumeration of all the Permissions.
     */

    public Enumeration<Permission> elements()
    {
        // go through each Permissions in the hash table
        // and call their elements() function.

        lock(this) {
            return new PermissionsEnumerator(permsMap.values().iterator());
        }
    }

    /**
     * Gets the PermissionCollection in this Permissions object for
     * permissions whose type is the same as that of <i>p</i>.
     * For example, if <i>p</i> is a FilePermission,
     * the FilePermissionCollection
     * stored in this Permissions object will be returned.
     *
     * If createEmpty is true,
     * this method creates a new PermissionCollection object for the specified
     * type of permission objects if one does not yet exist.
     * To do so, it first calls the {@code newPermissionCollection} method
     * on <i>p</i>.  Subclasses of class Permission
     * override that method if they need to store their permissions in a
     * particular PermissionCollection object in order to provide the
     * correct semantics when the {@code PermissionCollection.implies}
     * method is called.
     * If the call returns a PermissionCollection, that collection is stored
     * in this Permissions object. If the call returns null and createEmpty
     * is true, then
     * this method instantiates and stores a default PermissionCollection
     * that uses a hashtable to store its permission objects.
     *
     * createEmpty is ignored when creating empty PermissionCollection
     * for unresolved permissions because of the overhead of determining the
     * PermissionCollection to use.
     *
     * createEmpty should be set to false when this method is invoked from
     * implies() because it incurs the additional overhead of creating and
     * adding an empty PermissionCollection that will just return false.
     * It should be set to true when invoked from add().
     */
    private PermissionCollection getPermissionCollection(Permission p,
        bool createEmpty)
    {
        Class <?> c = p.getClass();

        PermissionCollection pc = permsMap.get(c);

        if (!hasUnresolved && !createEmpty)
        {
            return pc;
        }
        else if (pc == null)
        {

            // Check for unresolved permissions
            pc = (hasUnresolved ? getUnresolvedPermissions(p) : null);

            // if still null, create a new collection
            if (pc == null && createEmpty)
            {

                pc = p.newPermissionCollection();

                // still no PermissionCollection?
                // We'll give them a PermissionsHash.
                if (pc == null)
                    pc = new PermissionsHash();
            }

            if (pc != null)
            {
                permsMap.put(c, pc);
            }
        }
        return pc;
    }

    /**
     * Resolves any unresolved permissions of type p.
     *
     * @param p the type of unresolved permission to resolve
     *
     * @return PermissionCollection containing the unresolved permissions,
     *  or null if there were no unresolved permissions of type p.
     *
     */
    private PermissionCollection getUnresolvedPermissions(Permission p)
    {
        // Called from within synchronized method so permsMap doesn't need lock

        UnresolvedPermissionCollection uc =
        (UnresolvedPermissionCollection)permsMap.get(UnresolvedPermission.class);

        // we have no unresolved permissions if uc is null
        if (uc == null)
            return null;

        List<UnresolvedPermission> unresolvedPerms =
                                        uc.getUnresolvedPermissions(p);

        // we have no unresolved permissions of this type if unresolvedPerms is null
        if (unresolvedPerms == null)
            return null;

        java.security.cert.Certificate certs[] = null;

    object signers[] = p.getClass().getSigners();

    int n = 0;
        if (signers != null) {
            for (int j = 0; j<signers.length; j++) {
                if (signers[j] instanceof java.security.cert.Certificate) {
                    n++;
                }
            }
            certs = new java.security.cert.Certificate[n];
            n = 0;
            for (int j = 0; j<signers.length; j++) {
                if (signers[j] instanceof java.security.cert.Certificate) {
                    certs[n++] = (java.security.cert.Certificate)signers[j];
                }
            }
        }

        PermissionCollection pc = null;
        synchronized(unresolvedPerms)
{
    int len = unresolvedPerms.size();
    for (int i = 0; i < len; i++)
    {
        UnresolvedPermission up = unresolvedPerms.get(i);
        Permission perm = up.resolve(p, certs);
        if (perm != null)
        {
            if (pc == null)
            {
                pc = p.newPermissionCollection();
                if (pc == null)
                    pc = new PermissionsHash();
            }
            pc.add(perm);
        }
    }
}
        return pc;
    }

    private static readonly long serialVersionUID = 4858622370623524688L;

// Need to maintain serialization interoperability with earlier releases,
// which had the serializable field:
// private Hashtable perms;

/**
 * @serialField perms java.util.Hashtable
 *     A table of the Permission classes and PermissionCollections.
 * @serialField allPermission java.security.PermissionCollection
 */
private static sealed ObjectStreamField[] serialPersistentFields = {
        new ObjectStreamField("perms", Hashtable.class),
        new ObjectStreamField("allPermission", PermissionCollection.class),
    };

    /**
     * @serialData Default fields.
     */
    /*
     * Writes the contents of the permsMap field out as a Hashtable for
     * serialization compatibility with earlier releases. allPermission
     * unchanged.
     */
    private void writeObject(ObjectOutputStream Out) throws IOException
{
    // Don't call out.defaultWriteObject()

    // Copy perms into a Hashtable
    Dictionary<Class<?>, PermissionCollection> perms =
            new Dictionary<>(permsMap.size()*2); // no sync; estimate
        lock(this)
{
    perms.putAll(permsMap);
}

// Write out serializable fields
ObjectOutputStream.PutField pfields = Out.putFields();

pfields.put("allPermission", allPermission); // no sync; staleness OK
        pfields.put("perms", perms);
        Out.writeFields();
    }

    /*
     * Reads in a Hashtable of Class/PermissionCollections and saves them in the
     * permsMap field. Reads in allPermission.
     */
    private void readObject(ObjectInputStream In) throws IOException,
    ClassNotFoundException {
        // Don't call defaultReadObject()

        // Read in serialized fields
        ObjectInputStream.GetField gfields = In.readFields();

// Get allPermission
allPermission = (PermissionCollection) gfields.get("allPermission", null);

        // Get permissions
        // writeObject writes a Hashtable<Class<?>, PermissionCollection> for
        // the perms key, so this cast is safe, unless the data is corrupt.
        @SuppressWarnings("unchecked")
        Dictionary<Class<?>, PermissionCollection> perms =
            (Dictionary < Class <?>, PermissionCollection>)gfields.get("perms", null);
        permsMap = new HashMap<Class<?>, PermissionCollection>(perms.size()*2);
        permsMap.putAll(perms);

        // Set hasUnresolved
        UnresolvedPermissionCollection uc =
        (UnresolvedPermissionCollection)permsMap.get(UnresolvedPermission.class);
        hasUnresolved = (uc != null && uc.elements().hasMoreElements());
    }
}

sealed class PermissionsEnumerator : Enumeration<Permission> {

    // all the perms
    private Iterator<PermissionCollection> perms;
// the current set
private Enumeration<Permission> permset;

    PermissionsEnumerator(Iterator<PermissionCollection> e)
{
    perms = e;
    permset = getNextEnumWithMore();
}

// No need to synchronize; caller should sync on object as required
public bool hasMoreElements()
{
    // if we enter with permissionimpl null, we know
    // there are no more left.

    if (permset == null)
        return false;

    // try to see if there are any left in the current one

    if (permset.hasMoreElements())
        return true;

    // get the next one that has something in it...
    permset = getNextEnumWithMore();

    // if it is null, we are done!
    return (permset != null);
}

// No need to synchronize; caller should sync on object as required
public Permission nextElement()
{

    // hasMoreElements will update permset to the next permset
    // with something in it...

    if (hasMoreElements())
    {
        return permset.nextElement();
    }
    else
    {
        throw new NoSuchElementException("PermissionsEnumerator");
    }

}

private Enumeration<Permission> getNextEnumWithMore()
{
    while (perms.hasNext())
    {
        PermissionCollection pc = perms.next();
        Enumeration<Permission> next = pc.elements();
        if (next.hasMoreElements())
            return next;
    }
    return null;

}
}

/**
 * A PermissionsHash stores a homogeneous set of permissions in a hashtable.
 *
 * @see Permission
 * @see Permissions
 *
 *
 * @author Roland Schemers
 *
 * @serial include
 */

sealed class PermissionsHash : PermissionCollection, ISerializable
{
    /**
     * Key and value are (same) permissions objects.
     * Not serialized; see serialization section at end of class.
     */
     [NonSerialized]
    private Dictionary<Permission, Permission> permsMap;

    /**
     * Create an empty PermissionsHash object.
     */

    PermissionsHash()
{
    permsMap = new Dictionary<Permission, Permission>(11);
}

/**
 * Adds a permission to the PermissionsHash.
 *
 * @param permission the Permission object to add.
 */

public void add(Permission permission)
{
    lock(this) {
        permsMap.put(permission, permission);
    }
}

/**
 * Check and see if this set of permissions implies the permissions
 * expressed in "permission".
 *
 * @param permission the Permission object to compare
 *
 * @return true if "permission" is a proper subset of a permission in
 * the set, false if not.
 */

public bool implies(Permission permission)
{
    // attempt a fast lookup and implies. If that fails
    // then enumerate through all the permissions.
    lock(this) {
        Permission p = permsMap.get(permission);

        // If permission is found, then p.equals(permission)
        if (p == null)
        {
            for (Permission p_ : permsMap.values())
            {
                if (p_.implies(permission))
                    return true;
            }
            return false;
        }
        else
        {
            return true;
        }
    }
}

/**
 * Returns an enumeration of all the Permission objects in the container.
 *
 * @return an enumeration of all the Permissions.
 */

public Enumeration<Permission> elements()
{
    // Convert Iterator of Map values into an Enumeration
    lock(this) {
        return Collections.enumeration(permsMap.values());
    }
}

private static readonly long serialVersionUID = -8491988220802933440L;
// Need to maintain serialization interoperability with earlier releases,
// which had the serializable field:
// private Hashtable perms;
/**
 * @serialField perms java.util.Hashtable
 *     A table of the Permissions (both key and value are same).
 */
private static readonly ObjectStreamField[] serialPersistentFields = {
        new ObjectStreamField("perms", Hashtable.class),
    };

    /**
     * @serialData Default fields.
     */
    /*
     * Writes the contents of the permsMap field out as a Hashtable for
     * serialization compatibility with earlier releases.
     */
    private void writeObject(ObjectOutputStream Out)// throws IOException
{
    // Don't call out.defaultWriteObject()

    // Copy perms into a Hashtable
    Dictionary<Permission, Permission> perms =
                new Dictionary<>(permsMap.size()*2);
        lock(this)
{
    perms.putAll(permsMap);
}

// Write out serializable fields
ObjectOutputStream.PutField pfields = Out.putFields();
pfields.put("perms", perms);
        Out.writeFields();
    }

    /*
     * Reads in a Hashtable of Permission/Permission and saves them in the
     * permsMap field.
     */
    private void readObject(ObjectInputStream In) //throws IOException,
    //ClassNotFoundException 
    {
        // Don't call defaultReadObject()

        // Read in serialized fields
        ObjectInputStream.GetField gfields = In.readFields();

        // Get permissions
        // writeObject writes a Hashtable<Class<?>, PermissionCollection> for
        // the perms key, so this cast is safe, unless the data is corrupt.
        @SuppressWarnings("unchecked")
        Dictionary<Permission, Permission> perms =
                (Dictionary<Permission, Permission>)gfields.get("perms", null);
permsMap = new Dictionary<Permission, Permission>(perms.size()*2);
        permsMap.putAll(perms);
    }
}
}