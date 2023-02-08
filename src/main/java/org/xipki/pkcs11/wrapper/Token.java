// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * Objects of this class represent PKCS#11 tokens. The application can get
 * information on the token, manage sessions and initialize the token. Notice
 * that objects of this class can become valid at any time. This is, the
 * user can remove the token at any time and any subsequent calls to the
 * corresponding object will fail with an exception (e.g. an exception
 * with the error code CKR_DEVICE_REMOVED).
 * First, the application may want to find out what cryptographic algorithms
 * the token supports. Implementations of such algorithms on a token are called
 * mechanisms in the context of PKCS#11. The code for this may look something
 * like this.
 * <pre><code>
 *   long[] supportedMechanisms = token.getMechanismList();
 *
 *   // check, if the token supports the required mechanism
 *   if (!contains(supportedMechanisms, CKM_RSA_PKCS)) {
 *     System.out.print("This token does not support the RSA PKCS mechanism!");
 *     System.out.flush();
 *     throw new PKCS11Exception("RSA not supported!");
 *   } else {
 *     MechanismInfo rsaMechanismInfo = token.getMechanismInfo(CKM_RSA_PKCS);
 *     // check, if the mechanism supports the required operation
 *     if (!rsaMechanismInfo.isDecrypt()) {
 *        System.out.print(
 *            "This token does not support RSA decryption according to PKCS!");
 *        System.out.flush();
 *        throw new PKCS11Exception("RSA signing not supported!");
 *     }
 *   }
 * </code></pre>
 * Being sure that the token supports the required mechanism, the application
 * can open a session. For example, it may call
 * <pre><code>
 *  Session session = token.openSession(readWrite);
 * </code></pre>
 * to open a read-only session for readWrite = false, or a read-write session if
 * readWrite = true.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class Token {

  /**
   * The reference to the slot.
   */
  private final Slot slot;

  /**
   * True, if UTF8 encoding is used as character encoding for character array
   * attributes and PINs.
   */
  private final boolean useUtf8Encoding;

  /**
   * The constructor that takes a reference to the module and the slot ID.
   *
   * @param slot
   *          The reference to the slot.
   */
  protected Token(Slot slot) {
    this.slot = Functions.requireNonNull("slot", slot);
    this.useUtf8Encoding = slot.isUseUtf8Encoding();
  }

  /**
   * Get the slot that created this Token object.
   *
   * @return The slot of this token.
   */
  public Slot getSlot() {
    return slot;
  }

  public boolean isUseUtf8Encoding() {
    return useUtf8Encoding;
  }

  /**
   * Get the ID of this token. This is the ID of the slot this token resides
   * in.
   *
   * @return The ID of this token.
   */
  public long getTokenID() {
    return slot.getSlotID();
  }

  /**
   * Get information about this token.
   *
   * @return An object containing information about this token.
   * @exception PKCS11Exception
   *              If reading the information fails.
   */
  public TokenInfo getTokenInfo() throws PKCS11Exception {
    return new TokenInfo(slot.getModule().getPKCS11Module().C_GetTokenInfo(slot.getSlotID()));
  }

  /**
   * Get the list of mechanisms that this token supports. An application can
   * use this method to determine, if this token supports the required
   * mechanism.
   *
   * @return An array of Mechanism objects. Each describes a mechanism that
   *         this token can perform. This array may be empty but not null.
   * @exception PKCS11Exception
   *              If reading the list of supported mechanisms fails.
   */
  public long[] getMechanismList() throws PKCS11Exception {
    PKCS11Module module = slot.getModule();
    long[] mechanisms = module.getPKCS11Module().C_GetMechanismList(slot.getSlotID());
    for (int i = 0; i < mechanisms.length; i++) {
      long code = mechanisms[i];
      if ((code & PKCS11Constants.CKM_VENDOR_DEFINED) != 0L) {
        mechanisms[i] = module.ckmVendorToGeneric(code);
      }
    }

    return mechanisms;
  }

  /**
   * Get more information about one supported mechanism. The application can
   * find out, e.g. if an algorithm supports the certain key length.
   *
   * @param mechanism
   *          A mechanism that is supported by this token.
   * @return An information object about the concerned mechanism.
   * @exception PKCS11Exception
   *              If reading the information fails, or if the mechanism is not
   *              supported by this token.
   */
  public MechanismInfo getMechanismInfo(long mechanism) throws PKCS11Exception {
    if ((mechanism & PKCS11Constants.CKM_VENDOR_DEFINED) != 0L) {
      mechanism = slot.getModule().ckmGenericToVendor(mechanism);
    }

    return new MechanismInfo(slot.getModule().getPKCS11Module().C_GetMechanismInfo(slot.getSlotID(), mechanism));
  }

  /**
   * Open a new session to perform operations on this token. Notice that all
   * sessions within one application (system process) have the same login
   * state.
   *
   * @param rwSession
   *          Must be either SessionReadWriteBehavior.RO_SESSION for read-only
   *          sessions or SessionReadWriteBehavior.RW_SESSION for read-write
   *          sessions.
   * @return The newly opened session.
   * @exception PKCS11Exception
   *              If the session could not be opened.
   */
  public Session openSession(boolean rwSession) throws PKCS11Exception {
    return openSession(rwSession, null);
  }

  /**
   * Open a new session to perform operations on this token. Notice that all
   * sessions within one application (system process) have the same login
   * state.
   *
   * @param rwSession
   *          Must be either SessionReadWriteBehavior.RO_SESSION for read-only
   *          sessions or SessionReadWriteBehavior.RW_SESSION for read-write
   *          sessions.
   * @param application
   *          PKCS11Object to be supplied upon notify callback. May be null.
   *          (Not implemented yet!).
   * @return The newly opened session.
   * @exception PKCS11Exception
   *              If the session could not be opened.
   */
  public Session openSession(boolean rwSession, Object application) throws PKCS11Exception {
    long flags = rwSession
        ? PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION
        : PKCS11Constants.CKF_SERIAL_SESSION;
    long sessionHandle = slot.getModule().getPKCS11Module().C_OpenSession(slot.getSlotID(), flags, application, null);
    return new Session(this, sessionHandle);
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return "Token in Slot: " + slot;
  }

}
