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

  private void execute() throws TokenException {
    PKCS11Token token = getToken();
    AttributeVector template = AttributeVector.newAESSecretKey().valueLen(32)
        .unwrapTemplate(new AttributeVector().sensitive(true).wrapWithTrusted(true).sign(false))
        .wrapTemplate(new AttributeVector().keyType(PKCS11Constants.CKK_AES).wrapWithTrusted(true));

    System.out.println("Template before generation\n" + template);
    long handle = token.generateKey(new Mechanism(PKCS11Constants.CKM_AES_KEY_GEN), template);

    // test the read function
    AttributeVector attrs = token.getAttrValues(handle, PKCS11Constants.CKA_UNWRAP_TEMPLATE,
        PKCS11Constants.CKA_WRAP_TEMPLATE);
    System.out.println("read unwrapTemplate: " + attrs.unwrapTemplate());
    System.out.println("read wrapTemplate: " + attrs.wrapTemplate());

    // remove object
    token.destroyObject(handle);
  }

}
