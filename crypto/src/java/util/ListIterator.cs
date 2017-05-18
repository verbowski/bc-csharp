using System;
using System.Collections.Generic;
using System.Text;

namespace java.util
{
//    package java.util;

    /**
     * Title:
     * Description:
     * Copyright:    Copyright (c) 2001
     * Company:
     * @version 1.0
     */

    public interface ListIterator : Iterator
    {
        bool hasPrevious();
        Object previous();// throws NoSuchElementException;
    int nextIndex();
    int previousIndex();
    void set(Object o);//throws UnsupportedOperationException, ClassCastException, IllegalArgumentException, IllegalStateException;
        void add(Object o);// throws UnsupportedOperationException, ClassCastException, IllegalArgumentException;
    }
}