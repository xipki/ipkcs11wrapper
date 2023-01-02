// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package iaik.pkcs.pkcs11;

import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import sun.security.pkcs11.wrapper.CK_MECHANISM_INFO;
import sun.security.pkcs11.wrapper.CK_NOTIFY;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;

import static iaik.pkcs.pkcs11.wrapper.PKCS11Constants.*;

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
 *   List supportedMechanisms = Arrays.asList(token.getMechanismList());
 *
 *   // check, if the token supports the required mechanism
 *   if (!supportedMechanisms.contains(Mechanism.RSA_PKCS)) {
 *     System.out.print("This token does not support the RSA PKCS mechanism!");
 *     System.out.flush();
 *     throw new TokenException("RSA not supported!");
 *   } else {
 *     MechanismInfo rsaMechanismInfo =
 *         token.getMechanismInfo(Mechanism.RSA_PKCS);
 *     // check, if the mechanism supports the required operation
 *     if (!rsaMechanismInfo.isDecrypt()) {
 *        System.out.print(
 *            "This token does not support RSA decryption according to PKCS!");
 *        System.out.flush();
 *        throw new TokenException("RSA signing not supported!");
 *     }
 *   }
 * </code></pre>
 * Being sure that the token supports the required mechanism, the application
 * can open a session. For example, it may call
 * <pre><code>
 *  Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
 *      Token.SessionReadWriteBehavior.RO_SESSION, null, null);
 * </code></pre>
 * to open a simple read-only session.
 *
 * @see iaik.pkcs.pkcs11.Mechanism
 * @see iaik.pkcs.pkcs11.MechanismInfo
 * @see iaik.pkcs.pkcs11.Session
 * @see iaik.pkcs.pkcs11.TokenInfo
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class Token {

  public static final String CLASS_PKCS11Exception = "sun.security.pkcs11.wrapper.PKCS11Exception";

  private static final Constructor<?> PKCS11ExceptionConstructor;

  private static final int PKCS11ExceptionConstructorType;

  static {
    Constructor<?> constructor = null;
    int type = 0;

    try {
      Class<?> clazz = Class.forName(CLASS_PKCS11Exception);

      constructor = Util.getConstructor(clazz, long.class);
      if (constructor != null) {
        type = 1;
      } else {
        constructor= Util.getConstructor(clazz, long.class, String.class);
        if (constructor != null) {
          type = 2;
        }
      }
    } catch (Exception ex) {
    }

    PKCS11ExceptionConstructor = constructor;
    PKCS11ExceptionConstructorType = type;
  }

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
    this.slot = Util.requireNonNull("slot", slot);
    this.useUtf8Encoding = slot.isUseUtf8Encoding();
  }

  /**
   * Compares the slot of this object with the other object.
   * Returns only true, if those are equal in both objects.
   *
   * @param otherObject
   *          The other Token object.
   * @return True, if other is an instance of Token and the slot
   *         member variable of both objects are equal. False, otherwise.
   */
  public boolean equals(Object otherObject) {
    if (this == otherObject) return true;
    else if (!(otherObject instanceof Token)) return false;

    return this.slot.equals(((Token) otherObject).slot);
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
   * @exception TokenException
   *              If reading the information fails.
   */
  public TokenInfo getTokenInfo() throws TokenException {
    try {
      return new TokenInfo(slot.getModule().getPKCS11Module().C_GetTokenInfo(slot.getSlotID()));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  public List<Long> getMechanismList2() throws TokenException {
    long[] values = getMechanismList();
    List<Long> list = new ArrayList<>(values.length);
    for (long value : values) {
      list.add(value);
    }
    return list;
  }

  /**
   * Get the list of mechanisms that this token supports. An application can
   * use this method to determine, if this token supports the required
   * mechanism.
   *
   * @return An array of Mechanism objects. Each describes a mechanism that
   *         this token can perform. This array may be empty but not null.
   * @exception TokenException
   *              If reading the list of supported mechanisms fails.
   */
  public long[] getMechanismList() throws TokenException {
    long[] mechanisms;
    try {
      mechanisms = slot.getModule().getPKCS11Module().C_GetMechanismList(slot.getSlotID());
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    VendorCode vendorCode = slot.getModule().getVendorCode();
    if (vendorCode != null) {
      for (int i = 0; i < mechanisms.length; i++) {
        long code = mechanisms[i];
        if ((code & CKM_VENDOR_DEFINED) != 0 && vendorCode != null) {
          mechanisms[i] = vendorCode.ckmVendorToGeneric(code);
        }
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
   * @exception TokenException
   *              If reading the information fails, or if the mechanism is not
   *              supported by this token.
   */
  public MechanismInfo getMechanismInfo(long mechanism) throws TokenException {
    if ((mechanism & CKM_VENDOR_DEFINED) != 0) {
      VendorCode vendorCode = slot.getModule().getVendorCode();
      if (vendorCode != null) {
        mechanism = vendorCode.ckmGenericToVendor(mechanism);
      }
    }

    try {
      CK_MECHANISM_INFO info = slot.getModule().getPKCS11Module().C_GetMechanismInfo(slot.getSlotID(), mechanism);
      return new MechanismInfo(info);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object. Gained from the slot ID.
   */
  @Override
  public int hashCode() {
    return slot.hashCode();
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
   * @exception TokenException
   *              If the session could not be opened.
   */
  public Session openSession(boolean rwSession) throws TokenException {
    return openSession(rwSession, null, null);
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
   * @param notify
   *          For notifications via callback. may be null.
   *          (Not implemented yet!)
   * @return The newly opened session.
   * @exception TokenException
   *              If the session could not be opened.
   */
  public Session openSession(boolean rwSession, Object application, Notify notify) throws TokenException {
    long flags = CKF_SERIAL_SESSION;
    flags |= rwSession ? CKF_RW_SESSION : 0L;
    // we need it for the Notify already here
    final Session newSession = new Session(this, -1);
    CK_NOTIFY ckNotify = null;
    if (notify != null) {
      ckNotify = (hSession, event, pApplication) -> {
        boolean surrender = (event & CKN_SURRENDER) != 0L;
        try {
          notify.notify(newSession, surrender, pApplication);
        } catch (PKCS11Exception ex) {
          long errorCode = ex.getErrorCode();
          try {
            if (PKCS11ExceptionConstructorType == 0) {
              // ignore
            } else if (PKCS11ExceptionConstructorType == 1) {
              // JDK 8 - 16
              throw (sun.security.pkcs11.wrapper.PKCS11Exception) PKCS11ExceptionConstructor.newInstance(errorCode);
            } else if (PKCS11ExceptionConstructorType == 2) {
              // JDK 17+
              final String extraInfo = null;
              throw (sun.security.pkcs11.wrapper.PKCS11Exception)
                  PKCS11ExceptionConstructor.newInstance(errorCode, extraInfo);
            }
          } catch (Throwable th) {
            // ignore
          }
        }
      };
    }

    long sessionHandle;
    try {
      sessionHandle = slot.getModule().getPKCS11Module().C_OpenSession(slot.getSlotID(), flags, application, ckNotify);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
    //now we have the session handle available
    newSession.setSessionHandle(sessionHandle);

    return newSession;
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
