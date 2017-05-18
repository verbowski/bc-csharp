using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace java.util
{
    //    package java.util;

    public interface Set : Collection
    {
        int size();
        bool isEmpty();
        bool contains(Object o);
        IEnumerator iterator();
        Object[] toArray();
        Object[] toArray(Object[] a);
        bool add(Object o);
        bool remove(Object o);
        bool containsAll(Collection c);
        bool addAll(Collection c);
        bool retainAll(Collection c);
        bool removeAll(Collection c);
        void clear();
        bool equals(Object o);
        int hashCode();
    }
}
