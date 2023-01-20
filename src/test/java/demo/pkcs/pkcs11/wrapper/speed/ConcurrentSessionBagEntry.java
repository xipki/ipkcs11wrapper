// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package demo.pkcs.pkcs11.wrapper.speed;

import org.xipki.pkcs11.Session;
import org.xipki.util.concurrent.ConcurrentBagEntry;

/**
 * Concurrent bag entry for {@link Session}.
 */
public class ConcurrentSessionBagEntry extends ConcurrentBagEntry<Session> {

  public ConcurrentSessionBagEntry(Session value) {
    super(value);
  }

}
