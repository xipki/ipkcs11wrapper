/*
 * Copyright (C) 2013, 2014 Brett Wooldridge
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.xipki.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.StaticLogger;

import java.lang.ref.WeakReference;
import java.lang.reflect.Array;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

import static java.util.concurrent.TimeUnit.*;
import static java.util.concurrent.locks.LockSupport.parkNanos;

/**
 * This is a specialized concurrent bag that achieves superior performance
 * to LinkedBlockingQueue and LinkedTransferQueue for the purposes of a
 * connection pool.  It uses ThreadLocal storage when possible to avoid
 * locks, but resorts to scanning a common collection if there are no
 * available items in the ThreadLocal list.  Not-in-use items in the
 * ThreadLocal lists can be "stolen" when the borrowing thread has none
 * of its own.  It is a "lock-less" implementation using a specialized
 * AbstractQueuedLongSynchronizer to manage cross-thread signaling.
 * <p>
 * Note that items that are "borrowed" from the bag are not actually
 * removed from any collection, so garbage collection will not occur
 * even if the reference is abandoned.  Thus care must be taken to
 * "requite" borrowed objects otherwise a memory leak will result.  Only
 * the "remove" method can completely remove an object from the bag.
 *
 * @author Brett Wooldridge
 * @author Lijun Liao (xipki)
 *
 * @param <T> the templated type to store in the bag
 */
public class ConcurrentBag<T> implements AutoCloseable {

  private static ClockSource CLOCK =  "Mac OS X".equalsIgnoreCase(System.getProperty("os.name"))
      ? new MillisecondClockSource() : new NanosecondClockSource();

  private final CopyOnWriteArrayList<BagEntry<T>> sharedList;
  private final boolean weakThreadLocals;

  private final ThreadLocal<List<Object>> threadList;
  private final AtomicInteger waiters;
  private volatile boolean closed;

  private final SynchronousQueue<BagEntry<T>> handoffQueue;

  static final int STATE_NOT_IN_USE = 0;
  static final int STATE_IN_USE = 1;
  static final int STATE_REMOVED = -1;
  static final int STATE_RESERVED = -2;

  /**
   * Construct a ConcurrentBag with the specified listener.
   */
  public ConcurrentBag() {
    this.weakThreadLocals = useWeakThreadLocals();

    this.handoffQueue = new SynchronousQueue<>(true);
    this.waiters = new AtomicInteger();
    this.sharedList = new CopyOnWriteArrayList<>();
    if (weakThreadLocals) {
      this.threadList = ThreadLocal.withInitial(() -> new ArrayList<>(16));
    } else {
      this.threadList = ThreadLocal.withInitial(() -> new FastList<>(BagEntry.class, 16));
    }
  }

  /**
   * The method will borrow a BagEntry from the bag, blocking for the
   * specified timeout if none are available.
   *
   * @param timeout how long to wait before giving up, in units of unit
   * @param timeUnit a <code>TimeUnit</code> determining how to interpret the timeout parameter
   * @return a borrowed instance from the bag or null if a timeout occurs
   * @throws InterruptedException if interrupted while waiting
   */
  public BagEntry<T> borrow(long timeout, final TimeUnit timeUnit) throws InterruptedException {
    // Try the thread-local list first
    final List<Object> list = threadList.get();
    for (int i = list.size() - 1; i >= 0; i--) {
      final Object entry = list.remove(i);
      @SuppressWarnings("unchecked")
      final BagEntry<T> bagEntry = weakThreadLocals ? ((WeakReference<BagEntry<T>>) entry).get() : (BagEntry<T>) entry;
      if (bagEntry != null && bagEntry.compareAndSet(STATE_NOT_IN_USE, STATE_IN_USE)) {
        return bagEntry;
      }
    }

    try {
      for (BagEntry<T> bagEntry : sharedList) {
        if (bagEntry.compareAndSet(STATE_NOT_IN_USE, STATE_IN_USE)) {
          return bagEntry;
        }
      }

      timeout = timeUnit.toNanos(timeout);
      do {
        final long start = CLOCK.currentTime();
        final BagEntry<T> bagEntry = handoffQueue.poll(timeout, NANOSECONDS);
        if (bagEntry == null || bagEntry.compareAndSet(STATE_NOT_IN_USE, STATE_IN_USE)) {
          return bagEntry;
        }

        timeout -= CLOCK.elapsedNanos(start);
      } while (timeout > 10_000);

      return null;
    } finally {
      waiters.decrementAndGet();
    }
  }

  /**
   * This method will return a borrowed object to the bag.  Objects
   * that are borrowed from the bag but never "requited" will result
   * in a memory leak.
   *
   * @param bagEntry the value to return to the bag
   * @throws NullPointerException if value is null
   * @throws IllegalStateException if the bagEntry was not borrowed from the bag
   */
  public void requite(final BagEntry<T> bagEntry) {
    bagEntry.setState(STATE_NOT_IN_USE);

    for (int i = 0; waiters.get() > 0; i++) {
      if (bagEntry.getState() != STATE_NOT_IN_USE || handoffQueue.offer(bagEntry)) {
        return;
      } else if ((i & 0xff) == 0xff) {
        parkNanos(MICROSECONDS.toNanos(10));
      } else {
        Thread.yield();
      }
    }

    final List<Object> threadLocalList = threadList.get();
    if (threadLocalList.size() < 50) {
      threadLocalList.add(weakThreadLocals ? new WeakReference<>(bagEntry) : bagEntry);
    }
  }

  /**
   * Add a new object to the bag for others to borrow.
   *
   * @param bagEntry an object to add to the bag
   */
  public void add(final BagEntry<T> bagEntry) {
    if (closed) {
      StaticLogger.info("ConcurrentBag has been closed, ignoring add()");
      throw new IllegalStateException("ConcurrentBag has been closed, ignoring add()");
    }

    sharedList.add(bagEntry);

    // spin until a thread takes it or none are waiting
    while (waiters.get() > 0 && bagEntry.getState() == STATE_NOT_IN_USE && !handoffQueue.offer(bagEntry)) {
      Thread.yield();
    }
  }

  /**
   * Remove a value from the bag.  This method should only be called
   * with objects obtained by <code>borrow(long, TimeUnit)</code> or <code>reserve(T)</code>
   *
   * @param bagEntry the value to remove
   * @return true if the entry was removed, false otherwise
   * @throws IllegalStateException if an attempt is made to remove an object
   *         from the bag that was not borrowed or reserved first
   */
  public boolean remove(final BagEntry<T> bagEntry) {
    if (!bagEntry.compareAndSet(STATE_IN_USE, STATE_REMOVED)
        && !bagEntry.compareAndSet(STATE_RESERVED, STATE_REMOVED) && !closed) {
      StaticLogger.warn("Attempt to remove an object from the bag that was not borrowed or reserved: {}", bagEntry);
      return false;
    }

    final boolean removed = sharedList.remove(bagEntry);
    if (!removed && !closed) {
      StaticLogger.warn("Attempt to remove an object from the bag that does not exist: {}", bagEntry);
    }

    threadList.get().remove(bagEntry);

    return removed;
  }

  /**
   * Close the bag to further adds.
   */
  @Override
  public void close() {
    closed = true;
  }

  /**
   * This method provides a "snapshot" in time of the bag items.  It
   * does not "lock" or reserve items in any way.  Call <code>reserve(T)</code>
   * on items in the list, or understand the concurrency implications of
   * modifying items, before performing any action on them.
   *
   * @return a possibly empty list of (all) bag items
   */
  @SuppressWarnings("unchecked")
  public List<BagEntry<T>> values() {
    return (List<BagEntry<T>>) sharedList.clone();
  }

  /**
   * Get the total number of items in the bag.
   *
   * @return the number of items in the bag
   */
  public int size() {
    return sharedList.size();
  }

  /**
   * Determine whether to use WeakReferences based on whether there is a
   * custom ClassLoader implementation sitting between this class and the
   * System ClassLoader.
   *
   * @return true if we should use WeakReferences in our ThreadLocals, false otherwise
   */
  private boolean useWeakThreadLocals() {
    try {
      return getClass().getClassLoader() != ClassLoader.getSystemClassLoader();
    } catch (SecurityException se) {
      return true;
    }
  }


  public static class BagEntry<T> {

    @SuppressWarnings({ "unused" })
    private volatile int state = 0; // Don't delete me and add final declaration, will be used by the stateUpdater

    private static final AtomicIntegerFieldUpdater<BagEntry> stateUpdater;

    private final T value;

    static {
      stateUpdater = AtomicIntegerFieldUpdater.newUpdater(BagEntry.class, "state");
    }

    public BagEntry(T value) {
      this.value = value;
    }

    public T value() {
      return value;
    }

    public int getState() {
      return stateUpdater.get(this);
    }

    public boolean compareAndSet(int expect, int update) {
      return stateUpdater.compareAndSet(this, expect, update);
    }

    public void setState(int update) {
      stateUpdater.set(this, update);
    }

  }

  /**
   * A resolution-independent provider of current time-stamps and elapsed time
   * calculations.
   *
   * @author Brett Wooldridge
   */
  private interface ClockSource {

    /**
     * Get the current time-stamp (resolution is opaque).
     *
     * @return the current time-stamp
     */
    long currentTime();

    /**
     * Convert an opaque time-stamp returned by currentTime() into an
     * elapsed time in milliseconds, based on the current instant in time.
     *
     * @param startTime an opaque time-stamp returned by an instance of this class
     * @return the elapsed time between startTime and now in milliseconds
     */
    long elapsedNanos(long startTime);

  }

  private static final class MillisecondClockSource implements ClockSource {
    @Override
    public long currentTime() {
      return System.currentTimeMillis();
    }

    @Override
    public long elapsedNanos(final long startTime) {
      return MILLISECONDS.toNanos(System.currentTimeMillis() - startTime);
    }

  }

  private static class NanosecondClockSource implements ClockSource {
    @Override
    public long currentTime() {
      return System.nanoTime();
    }

    @Override
    public long elapsedNanos(final long startTime) {
      return System.nanoTime() - startTime;
    }

  }

  /**
   * Fast list without range checking.
   *
   * @author Brett Wooldridge
   */
  private static final class FastList<T> implements List<T>, RandomAccess {

    private final Class<?> clazz;
    private T[] elementData;
    private int size;

    /**
     * Construct a FastList with a specified size.
     * @param clazz the Class stored in the collection
     * @param capacity the initial size of the FastList
     */
    @SuppressWarnings("unchecked")
    public FastList(Class<?> clazz, int capacity) {
      this.elementData = (T[]) Array.newInstance(clazz, capacity);
      this.clazz = clazz;
    }

    /**
     * Add an element to the tail of the FastList.
     *
     * @param element the element to add
     */
    @Override
    public boolean add(T element) {
      if (size < elementData.length) {
        elementData[size++] = element;
      } else {
        // overflow-conscious code
        final int oldCapacity = elementData.length;
        final int newCapacity = oldCapacity << 1;
        @SuppressWarnings("unchecked")
        final T[] newElementData = (T[]) Array.newInstance(clazz, newCapacity);
        System.arraycopy(elementData, 0, newElementData, 0, oldCapacity);
        newElementData[size++] = element;
        elementData = newElementData;
      }

      return true;
    }

    /**
     * Get the element at the specified index.
     *
     * @param index the index of the element to get
     * @return the element, or ArrayIndexOutOfBounds is thrown if the index is invalid
     */
    @Override
    public T get(int index) {
      return elementData[index];
    }

    /**
     * This remove method is most efficient when the element being removed
     * is the last element.  Equality is identity based, not equals() based.
     * Only the first matching element is removed.
     *
     * @param element the element to remove
     */
    @Override
    public boolean remove(Object element) {
      for (int index = size - 1; index >= 0; index--) {
        if (element == elementData[index]) {
          final int numMoved = size - index - 1;
          if (numMoved > 0) {
            System.arraycopy(elementData, index + 1, elementData, index, numMoved);
          }
          elementData[--size] = null;
          return true;
        }
      }

      return false;
    }

    /**
     * Clear the FastList.
     */
    @Override
    public void clear() {
      for (int i = 0; i < size; i++) {
        elementData[i] = null;
      }

      size = 0;
    }

    /**
     * Get the current number of elements in the FastList.
     *
     * @return the number of current elements
     */
    @Override
    public int size() {
      return size;
    }

    @Override
    public boolean isEmpty() {
      return size == 0;
    }

    @Override
    public T set(int index, T element) {
      T old = elementData[index];
      elementData[index] = element;
      return old;
    }

    @Override
    public T remove(int index) {
      if (size == 0) {
        return null;
      }

      final T old = elementData[index];

      final int numMoved = size - index - 1;
      if (numMoved > 0) {
        System.arraycopy(elementData, index + 1, elementData, index, numMoved);
      }

      elementData[--size] = null;

      return old;
    }

    @Override
    public boolean contains(Object o) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Iterator<T> iterator() {
      return new Iterator<T>() {
        private int index;

        @Override
        public boolean hasNext() {
          return index < size;
        }

        @Override
        public T next() {
          if (index < size) {
            return elementData[index++];
          }

          throw new NoSuchElementException("No more elements in FastList");
        }
      };
    }

    @Override
    public Object[] toArray() {
      throw new UnsupportedOperationException();
    }

    @Override
    public <E> E[] toArray(E[] a) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean containsAll(Collection<?> c) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean addAll(Collection<? extends T> c) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean addAll(int index, Collection<? extends T> c) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean removeAll(Collection<?> c) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean retainAll(Collection<?> c) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void add(int index, T element) {
      throw new UnsupportedOperationException();
    }

    @Override
    public int indexOf(Object o) {
      throw new UnsupportedOperationException();
    }

    @Override
    public int lastIndexOf(Object o) {
      throw new UnsupportedOperationException();
    }

    @Override
    public ListIterator<T> listIterator() {
      throw new UnsupportedOperationException();
    }

    @Override
    public ListIterator<T> listIterator(int index) {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<T> subList(int fromIndex, int toIndex) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Object clone() {
      throw new UnsupportedOperationException();
    }

    @Override
    public void forEach(Consumer<? super T> action) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Spliterator<T> spliterator() {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean removeIf(Predicate<? super T> filter) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void replaceAll(UnaryOperator<T> operator) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void sort(Comparator<? super T> c) {
      throw new UnsupportedOperationException();
    }

  }
}
