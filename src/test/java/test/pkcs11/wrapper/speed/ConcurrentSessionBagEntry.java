// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.speed;

import org.xipki.pkcs11.wrapper.Session;
import org.xipki.util.concurrent.ConcurrentBagEntry;

/**
 * Concurrent bag entry for {@link Session}.
 */
public class ConcurrentSessionBagEntry extends ConcurrentBagEntry<Session> {

  public ConcurrentSessionBagEntry(Session value) {
    super(value);
  }

}
