// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.PKCS11Constants;

/**
 * This is the superclass of all checked exceptions used by this package. A
 * PKCS11Exception indicates that a function call to the underlying
 * PKCS#11 module returned a value not equal to CKR_OK. The application can get
 * the returned value by calling getErrorCode(). A return value not equal to
 * CKR_OK is the only reason for such an exception to be thrown.
 * PKCS#11 defines the meaning of an error-code, which may depend on the
 * context in which the error occurs.
 *
 * @author Karl Scheibelhofer (SIC)
 * @version 1.0
 */
public class PKCS11Exception extends Exception {

  private final long errorCode;

  /**
   * Constructor taking the error code as defined for the CKR_* constants
   * in PKCS#11.
   *
   * @param errorCode
   *          The PKCS#11 error code (return value).
   */
  public PKCS11Exception(long errorCode) {
    super(PKCS11Constants.ckrCodeToName(errorCode));
    this.errorCode = errorCode;
  }

  /**
   * Returns the PKCS#11 error code.
   *
   * @return The error code; e.g. 0x00000030.
   */
  public long getErrorCode() {
    return errorCode;
  }

}
