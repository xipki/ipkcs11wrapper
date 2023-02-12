package test.pkcs11.wrapper.basics;

import test.pkcs11.wrapper.TestBase;
import org.xipki.pkcs11.wrapper.*;

public class TestReadUnwrapTemplate extends TestBase {

  public static void main(String[] args) {
    try {
      new TestReadUnwrapTemplate().execute();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void execute() throws PKCS11Exception {
    PKCS11Module pkcs11Module = getModule();
    Slot slot = pkcs11Module.getSlotList(true)[0];
    Session session = openReadOnlySession(slot.getToken());
    try {
      AttributeVector template = AttributeVector.newAESSecretKey().valueLen(32)
          .unwrapTemplate(new AttributeVector().sensitive(false).wrapWithTrusted(false).sign(false));

      System.out.println("Template before generation\n" + template);
      long handle = session.generateKey(new Mechanism(PKCS11Constants.CKM_AES_KEY_GEN), template);

      // test the read function
      AttributeVector attrs = session.getAttrValues(handle, PKCS11Constants.CKA_UNWRAP_TEMPLATE);
      AttributeVector unwrapTemplate2 = attrs.unwrapTemplate();
      System.out.println("read unwrapTemplate: " + unwrapTemplate2);

      boolean valueCorrect = false;
      if (unwrapTemplate2 != null) {
        Boolean sensitive = unwrapTemplate2.sensitive();
        valueCorrect = (sensitive != null && sensitive);
      }

      System.out.println("Value correct: " + valueCorrect);

      // remove object
      session.destroyObject(handle);
    } finally {
      session.closeSession();
    }
  }

}
