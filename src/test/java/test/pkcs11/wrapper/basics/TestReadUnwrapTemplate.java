package test.pkcs11.wrapper.basics;

import org.xipki.pkcs11.wrapper.*;
import test.pkcs11.wrapper.TestBase;

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
          .unwrapTemplate(new AttributeVector().sensitive(true).wrapWithTrusted(true).sign(false))
          .wrapTemplate(new AttributeVector().keyType(PKCS11Constants.CKK_AES).wrapWithTrusted(true));

      System.out.println("Template before generation\n" + template);
      long handle = session.generateKey(new Mechanism(PKCS11Constants.CKM_AES_KEY_GEN), template);

      // test the read function
      AttributeVector attrs = session.getAttrValues(handle, PKCS11Constants.CKA_UNWRAP_TEMPLATE,
          PKCS11Constants.CKA_WRAP_TEMPLATE);
      System.out.println("read unwrapTemplate: " + attrs.unwrapTemplate());
      System.out.println("read wrapTemplate: " + attrs.wrapTemplate());

      // remove object
      session.destroyObject(handle);
    } finally {
      session.closeSession();
    }
  }

}
