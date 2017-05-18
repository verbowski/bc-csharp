using System;
using System.Collections.Generic;
using System.Text;

namespace java.util
{
//    package java.util;

    public interface Iterator
    {
        bool hasNext();
        object next();// throws NoSuchElementException;
        void remove();// throws UnsupportedOperationException, IllegalStateException;
    }
}
