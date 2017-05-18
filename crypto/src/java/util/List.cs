using System;
using System.Collections.Generic;
using System.Text;

namespace java.util
{
//    package java.util;

    public interface List : Collection
    {
        void add(int index, Object element);// throws UnsupportedOperationException,ClassCastException,IllegalArgumentException,IndexOutOfBoundsException;
        bool addAll(int index, Collection c);// throws UnsupportedOperationException,ClassCastException,IllegalArgumentException,IndexOutOfBoundsException;
        Object get(int index);// throws IndexOutOfBoundsException;
        int indexOf(Object o);
        int lastIndexOf(Object o);
        ListIterator listIterator();
        ListIterator listIterator(int index);//throws IndexOutOfBoundsException;
        Object remove(int index);//throws UnsupportedOperationException, IndexOutOfBoundsException;
        Object set(int index, Object element);// throws UnsupportedOperationException, ClassCastException, IllegalArgumentException, IndexOutOfBoundsException;
        List subList(int fromIndex, int toIndex);//throws IndexOutOfBoundsException;
    }

    }
