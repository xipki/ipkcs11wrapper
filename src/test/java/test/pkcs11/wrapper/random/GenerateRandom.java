// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.random;

import org.junit.Test;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.TokenException;
import test.pkcs11.wrapper.TestBase;

/**
 * This demo program uses a PKCS#11 module to produce random data.
 */
public class GenerateRandom extends TestBase {

  @Test
  public void main() throws TokenException {
    final int n = 1057;
    LOG.info("##################################################");
    LOG.info("generating {} bytes of random data... ", n);
    byte[] dataBuffer = getToken().generateRandom(n);
    LOG.info("random is");
    LOG.info(Functions.toHex(dataBuffer));
    LOG.info("finished");
    LOG.info("##################################################");
  }

}
