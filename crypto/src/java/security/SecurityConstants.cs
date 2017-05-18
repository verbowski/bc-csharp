using java.security;
using System;
using System.Collections.Generic;
using System.Text;

namespace java.security
{
    /*
     * Copyright (c) 2003, 2013, Oracle and/or its affiliates. All rights reserved.
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
    package sun.security.util;

    import java.net.SocketPermission;
    import java.net.NetPermission;
    import java.security.AccessController;
    import java.security.PrivilegedAction;
    import java.security.Permission;
    import java.security.BasicPermission;
    import java.security.SecurityPermission;
    import java.security.AllPermission;
    */
    /**
     * Permission constants and string constants used to create permissions
     * used throughout the JDK.
     */
    public sealed class SecurityConstants
    {
        // Cannot create one of these
        private SecurityConstants()
        {
        }

        // Commonly used string constants for permission actions used by
        // SecurityManager. Declare here for shortcut when checking permissions
        // in FilePermission, SocketPermission, and PropertyPermission.

        public static readonly string FILE_DELETE_ACTION = "delete";
        public static readonly string FILE_EXECUTE_ACTION = "execute";
        public static readonly string FILE_READ_ACTION = "read";
        public static readonly string FILE_WRITE_ACTION = "write";
        public static readonly string FILE_READLINK_ACTION = "readlink";

        public static readonly string SOCKET_RESOLVE_ACTION = "resolve";
        public static readonly string SOCKET_CONNECT_ACTION = "connect";
        public static readonly string SOCKET_LISTEN_ACTION = "listen";
        public static readonly string SOCKET_ACCEPT_ACTION = "accept";
        public static readonly string SOCKET_CONNECT_ACCEPT_ACTION = "connect,accept";

        public static readonly string PROPERTY_RW_ACTION = "read,write";
        public static readonly string PROPERTY_READ_ACTION = "read";
        public static readonly string PROPERTY_WRITE_ACTION = "write";

    // Permission constants used in the various checkPermission() calls in JDK.

    // java.lang.Class, java.lang.SecurityManager, java.lang.System,
    // java.net.URLConnection, java.security.AllPermission, java.security.Policy,
    // sun.security.provider.PolicyFile
    public static readonly AllPermission ALL_PERMISSION = new AllPermission();

        /**
         * AWT Permissions used in the JDK.
         */
        public class AWT
        {
            private AWT() { }

            /**
             * The class name of the factory to create java.awt.AWTPermission objects.
             */
            private static readonly string AWTFactory = "sun.awt.AWTPermissionFactory";

        /**
         * The PermissionFactory to create AWT permissions (or null if AWT is
         * not present)
         */
        private static readonly PermissionFactory<?> factory = permissionFactory();

            private static PermissionFactory<?> permissionFactory()
            {
                Class <?> c;
                try
                {
                    c = Class.forName(AWTFactory, false, AWT.class.getClassLoader());
            } catch (ClassNotFoundException e) {
                // not available
                return null;
    }
            // AWT present
            try {
                return (PermissionFactory<?>)c.newInstance();
            } catch (ReflectiveOperationException x) {
                throw new InternalError(x);
            }
        }

        private static Permission newAWTPermission(string name)
{
    return (factory == null) ? null : factory.newPermission(name);
}

// java.lang.SecurityManager
public static readonly Permission TOPLEVEL_WINDOW_PERMISSION =
            new AWTPermission("showWindowWithoutWarningBanner");

// java.lang.SecurityManager
public static readonly Permission ACCESS_CLIPBOARD_PERMISSION =
            new AWTPermission("accessClipboard");

// java.lang.SecurityManager
public static readonly Permission CHECK_AWT_EVENTQUEUE_PERMISSION =
            new AWTPermission("accessEventQueue");

// java.awt.Dialog
public static readonly Permission TOOLKIT_MODALITY_PERMISSION =
            new AWTPermission("toolkitModality");

// java.awt.Robot
public static readonly Permission READ_DISPLAY_PIXELS_PERMISSION =
            new AWTPermission("readDisplayPixels");

// java.awt.Robot
public static readonly Permission CREATE_ROBOT_PERMISSION =
            new AWTPermission("createRobot");

// java.awt.MouseInfo
public static readonly Permission WATCH_MOUSE_PERMISSION =
            new AWTPermission("watchMousePointer");

// java.awt.Window
public static readonly Permission SET_WINDOW_ALWAYS_ON_TOP_PERMISSION =
            new AWTPermission("setWindowAlwaysOnTop");

// java.awt.Toolkit
public static readonly Permission ALL_AWT_EVENTS_PERMISSION =
            new AWTPermission("listenToAllAWTEvents");

// java.awt.SystemTray
public static readonly Permission ACCESS_SYSTEM_TRAY_PERMISSION =
            new AWTPermission("accessSystemTray");
    }

    // java.net.URL
    public static readonly NetPermission SPECIFY_HANDLER_PERMISSION =
       new NetPermission("specifyStreamHandler");

// java.net.ProxySelector
public static readonly NetPermission SET_PROXYSELECTOR_PERMISSION =
       new NetPermission("setProxySelector");

// java.net.ProxySelector
public static readonly NetPermission GET_PROXYSELECTOR_PERMISSION =
       new NetPermission("getProxySelector");

// java.net.CookieHandler
public static readonly NetPermission SET_COOKIEHANDLER_PERMISSION =
       new NetPermission("setCookieHandler");

// java.net.CookieHandler
public static readonly NetPermission GET_COOKIEHANDLER_PERMISSION =
       new NetPermission("getCookieHandler");

// java.net.ResponseCache
public static readonly NetPermission SET_RESPONSECACHE_PERMISSION =
       new NetPermission("setResponseCache");

// java.net.ResponseCache
public static readonly NetPermission GET_RESPONSECACHE_PERMISSION =
       new NetPermission("getResponseCache");

// java.lang.SecurityManager, sun.applet.AppletPanel, sun.misc.Launcher
public static readonly RuntimePermission CREATE_CLASSLOADER_PERMISSION =
        new RuntimePermission("createClassLoader");

// java.lang.SecurityManager
public static readonly RuntimePermission CHECK_MEMBER_ACCESS_PERMISSION =
        new RuntimePermission("accessDeclaredMembers");

// java.lang.SecurityManager, sun.applet.AppletSecurity
public static readonly RuntimePermission MODIFY_THREAD_PERMISSION =
        new RuntimePermission("modifyThread");

// java.lang.SecurityManager, sun.applet.AppletSecurity
public static readonly RuntimePermission MODIFY_THREADGROUP_PERMISSION =
        new RuntimePermission("modifyThreadGroup");

// java.lang.Class
public static readonly RuntimePermission GET_PD_PERMISSION =
        new RuntimePermission("getProtectionDomain");

// java.lang.Class, java.lang.ClassLoader, java.lang.Thread
public static readonly RuntimePermission GET_CLASSLOADER_PERMISSION =
        new RuntimePermission("getClassLoader");

// java.lang.Thread
public static readonly RuntimePermission STOP_THREAD_PERMISSION =
       new RuntimePermission("stopThread");

// java.lang.Thread
public static readonly RuntimePermission GET_STACK_TRACE_PERMISSION =
       new RuntimePermission("getStackTrace");

// java.security.AccessControlContext
public static readonly SecurityPermission CREATE_ACC_PERMISSION =
       new SecurityPermission("createAccessControlContext");

// java.security.AccessControlContext
public static readonly SecurityPermission GET_COMBINER_PERMISSION =
       new SecurityPermission("getDomainCombiner");

// java.security.Policy, java.security.ProtectionDomain
public static readonly SecurityPermission GET_POLICY_PERMISSION =
        new SecurityPermission("getPolicy");

// java.lang.SecurityManager
public static readonly SocketPermission LOCAL_LISTEN_PERMISSION =
        new SocketPermission("localhost:0", SOCKET_LISTEN_ACTION);
}
}
