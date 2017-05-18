using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace java.util
{
//    package java.util;

    public interface Collection
    {
         bool add(Object o);// throws UnsupportedOperationException, ClassCastException, IllegalArgumentException;
         bool addAll(Collection c);//throws UnsupportedOperationException, ClassCastException, IllegalArgumentException;
         void clear();//  throws UnsupportedOperationException;
         bool contains(Object o);
         bool containsAll(Collection c);
         bool equals(Object o);
         int hashCode();
         bool isEmpty();
         IEnumerable iterator();
         /*SK13*/bool remove(Object o);// throws UnsupportedOperationException;
         bool removeAll(Collection c);//  throws UnsupportedOperationException;
         bool retainAll(Collection c);//  throws UnsupportedOperationException;
         int size();
         Object[] toArray();
         Object[] toArray(Object[] a);// throws ArrayStoreException;
    }
}
