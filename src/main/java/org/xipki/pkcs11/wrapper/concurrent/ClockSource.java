// #THIRDPARTY# HikariCP

/*
 * Copyright (C) 2015 Brett Wooldridge
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

package org.xipki.pkcs11.wrapper.concurrent;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * A resolution-independent provider of current time-stamps and elapsed time
 * calculations.
 *
 * @author Brett Wooldridge
 */
public interface ClockSource {
  ClockSource CLOCK = Factory.create();

  /**
   * Get the current time-stamp (resolution is opaque).
   *
   * @return the current time-stamp
   */
  static long currentTime() {
    return CLOCK.currentTime0();
  }

  long currentTime0();

  /**
   * Convert an opaque time-stamp returned by currentTime() into an
   * elapsed time in milliseconds, based on the current instant in time.
   *
   * @param startTime an opaque time-stamp returned by an instance of this class
   * @return the elapsed time between startTime and now in milliseconds
   */
  static long elapsedNanos(long startTime) {
    return CLOCK.elapsedNanos0(startTime);
  }

  long elapsedNanos0(long startTime);

  long elapsedNanos0(long startTime, long endTime);

  /**
   * Factory class used to create a platform-specific ClockSource.
   */
  class Factory {
    private static ClockSource create() {
      String os = System.getProperty("os.name");
      if ("Mac OS X".equals(os)) {
        return new MillisecondClockSource();
      }

      return new NanosecondClockSource();
    }
  }

  final class MillisecondClockSource implements ClockSource {
    @Override
    public long currentTime0() {
      return System.currentTimeMillis();
    }

    @Override
    public long elapsedNanos0(final long startTime) {
      return MILLISECONDS.toNanos(System.currentTimeMillis() - startTime);
    }

    @Override
    public long elapsedNanos0(final long startTime, final long endTime) {
      return MILLISECONDS.toNanos(endTime - startTime);
    }

  }

  class NanosecondClockSource implements ClockSource {
    @Override
    public long currentTime0() {
      return System.nanoTime();
    }

    @Override
    public long elapsedNanos0(final long startTime) {
      return System.nanoTime() - startTime;
    }

    @Override
    public long elapsedNanos0(final long startTime, final long endTime) {
      return endTime - startTime;
    }
  }

}
