package test.pkcs11.wrapper;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.util.Hex;

public class FunctionsTest {

  @Test
  public void oidNegativeTest() throws Exception {
    String[] oids = {"3.39.12", "0.40.12", "1.40.12"};

    for (int i = 0; i < oids.length; i++) {
      String oid = oids[i];
      try {
        Functions.encodeOid(oid);
        Assert.fail("error expected");
      } catch (IllegalArgumentException e) {
      }
    }
  }

  @Test
  public void oidTest() throws Exception {
    String[] oids = {"0.39.12.34567", "1.39.12.34567", "2.65512.12.34567"};
    String[] hexs  = {"0605270c828e07", "06054f0c828e07", "06078480380c828e07"};

    for (int i = 0; i < oids.length; i++) {
      String oid = oids[i];
      String hex = hexs[i];

      byte[] encoded = Functions.encodeOid(oid);
      Assert.assertEquals(hex, Hex.encode(encoded));

      String text2 = Functions.decodeOid(encoded);
      Assert.assertEquals(oid, text2);
    }
  }

}

