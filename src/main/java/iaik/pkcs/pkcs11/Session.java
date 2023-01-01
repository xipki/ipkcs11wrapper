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

import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.parameters.*;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_RSA_PKCS_PSS_PARAMS;
import sun.security.pkcs11.wrapper.PKCS11;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;

/**
 * Session objects are used to perform cryptographic operations on a token. The
 * application gets a Session object by calling openSession on a certain Token
 * object. Having the session object, the application may log-in the user, if
 * required.
 *
 * <pre>
 * <code>
 *   TokenInfo tokenInfo = token.getTokenInfo();
 *   // check, if log-in of the user is required at all
 *   if (tokenInfo.isLoginRequired()) {
 *     // check, if the token has own means to authenticate the user; e.g. a
 *     // PIN-pad on the reader
 *     if (tokenInfo.isProtectedAuthenticationPath()) {
 *       System.out.println("Please enter the user PIN at the PIN-pad of your reader.");
 *       // the token prompts the PIN by other means; e.g. PIN-pad
 *       session.login(Session.UserType.USER, null);
 *     } else {
 *       System.out.print("Enter user-PIN and press [return key]: ");
 *       System.out.flush();
 *       BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
 *       String userPINString = input.readLine();
 *       session.login(Session.UserType.USER, userPINString.toCharArray());
 *     }
 *   }
 * </code>
 *
 * If the application does not need the session any longer, it should close the
 * session.
 *
 * <pre>
 * <code>
 *   session.closeSession();
 * </code>
 * </pre>
 *
 * @see iaik.pkcs.pkcs11.parameters.Parameters
 * @see iaik.pkcs.pkcs11.Session
 * @see iaik.pkcs.pkcs11.SessionInfo
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class Session {

  private static final Method encrypt0;

  private static final Method encrypt1;

  private static final Method decrypt0;

  private static final Method decrypt1;

  private static final Field field_CK_MECHANISM_pParameter;

  private static final Method method_CK_MECHANISM_setParameter;

  private static final Constructor<?> constructor_CK_MECHANISM_CCM;

  private static final Constructor<?> constructor_CK_MECHANISM_GCM;

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  private final PKCS11Module module;

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  private final PKCS11 pkcs11Module;

  /**
   * The session handle to perform the operations with.
   */
  private long sessionHandle;

  private final VendorCode vendorCode;

  /**
   * The token to perform the operations on.
   */
  private final Token token;

  static {
    Class<?> clazz = PKCS11.class;
    decrypt0 = Util.getMethod(clazz, "C_Decrypt",
        long.class, byte[].class, int.class, int.class, byte[].class, int.class, int.class);

    encrypt0 = Util.getMethod(clazz, "C_Encrypt",
        long.class, byte[].class, int.class, int.class, byte[].class, int.class, int.class);

    if (decrypt0 == null) {
      decrypt1 = Util.getMethod(clazz, "C_Decrypt",
          long.class, long.class, byte[].class, int.class, int.class, long.class, byte[].class, int.class, int.class);
    } else {
      decrypt1 = null;
    }

    if (encrypt0 == null) {
      encrypt1 = Util.getMethod(clazz, "C_Encrypt",
          long.class, long.class, byte[].class, int.class, int.class, long.class, byte[].class, int.class, int.class);
    } else {
      encrypt1 = null;
    }

    clazz = CK_MECHANISM.class;
    field_CK_MECHANISM_pParameter = Util.getField(clazz, "pParameter");
    method_CK_MECHANISM_setParameter = Util.getMethod(clazz, "setParameter", CK_RSA_PKCS_PSS_PARAMS.class);

    constructor_CK_MECHANISM_CCM = getConstructofOfCK_MECHANISM(CCMParameters.CLASS_CK_PARAMS);
    constructor_CK_MECHANISM_GCM = getConstructofOfCK_MECHANISM(GCMParameters.CLASS_CK_PARAMS);
  }

  private static Constructor<?> getConstructofOfCK_MECHANISM(String paramsClassName) {
    Class<?> paramsClass;
    try {
      paramsClass = Class.forName(paramsClassName);
    } catch (ClassNotFoundException ex) {
      return null;
    }

    return Util.getConstructor(CK_MECHANISM.class, long.class, paramsClass);
  }

  /**
   * Constructor taking the token and the session handle.
   *
   * @param token
   *          The token this session operates with.
   * @param sessionHandle
   *          The session handle to perform the operations with.
   */
  protected Session(Token token, long sessionHandle) {
    this.token = Util.requireNonNull("token", token);
    this.module = token.getSlot().getModule();
    this.vendorCode = module.getVendorCode();
    this.pkcs11Module = module.getPKCS11Module();
    this.sessionHandle = sessionHandle;
  }

  /**
   * Closes this session.
   *
   * @exception TokenException
   *              If closing the session failed.
   */
  public void closeSession() throws TokenException {
    try {
      pkcs11Module.C_CloseSession(sessionHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Compares the sessionHandle and token of this object with the other
   * object. Returns only true, if those are equal in both objects.
   *
   * @param otherObject
   *          The other Session object.
   * @return True, if other is an instance of Token and the session handles
   *         and tokens of both objects are equal. False, otherwise.
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) return true;
    else if (!(otherObject instanceof Session)) return false;

    Session other = (Session) otherObject;
    return  (sessionHandle == other.sessionHandle)  && token.equals(other.token);
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object. Gained from the sessionHandle.
   */
  @Override
  public int hashCode() {
    return (int) sessionHandle;
  }

  /**
   * Get the handle of this session.
   *
   * @return The handle of this session.
   */
  public long getSessionHandle() {
    return sessionHandle;
  }

  /**
   * Get information about this session.
   *
   * @return An object providing information about this session.
   * @exception TokenException
   *              If getting the information failed.
   */
  public SessionInfo getSessionInfo() throws TokenException  {
    try {
      return new SessionInfo(pkcs11Module.C_GetSessionInfo(sessionHandle));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Get the Module which this Session object operates with.
   *
   * @return The module of this session.
   */
  public PKCS11Module getModule() {
    return module;
  }

  /**
   * Get the token that created this Session object.
   *
   * @return The token of this session.
   */
  public Token getToken() {
    return token;
  }

  /**
   * Get the current operation state. This state can be used later to restore
   * the operation to exactly this state.
   *
   * @return The current operation state as a byte array.
   * @exception TokenException
   *              If saving the state fails or is not possible.
   */
  public byte[] getOperationState() throws TokenException {
    try {
      return pkcs11Module.C_GetOperationState(sessionHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Sets the operation state of this session to a previously saved one. This
   * method may need the key used during the saved operation to continue,
   * because it may not be possible to save a key into the state's byte array.
   * Refer to the PKCS#11 standard for details on this function.
   *
   * @param operationState
   *          The previously saved state as returned by getOperationState().
   * @param encryptionKeyHandle
   *          An encryption or decryption key, if an encryption or decryption
   *          operation was saved which should be continued, but the keys
   *          could not be saved.
   * @param authenticationKeyHandle
   *          A signing, verification of MAC key, if a signing, verification
   *          or MAC operation needs to be restored that could not save the
   *          key.
   * @exception TokenException
   *              If restoring the state fails.
   * @see #getOperationState()
   */
  public void setOperationState(byte[] operationState, long encryptionKeyHandle, long authenticationKeyHandle)
      throws TokenException {
    try {
      pkcs11Module.C_SetOperationState(sessionHandle, operationState, encryptionKeyHandle, authenticationKeyHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  public void setSessionHandle(long sessionHandle) {
    this.sessionHandle = sessionHandle;
  }

  /**
   * Logs in the user or the security officer to the session. Notice that all
   * sessions of a token have the same login state; i.e. if you login the user
   * to one session all other open sessions of this token get user rights.
   *
   * @param userType
   *          PKCS11Constants.CKU_SO for the security officer or
   *          PKCS11Constants.CKU_USER to login the user.
   * @param pin
   *          The PIN. The security officer-PIN or the user-PIN depending on
   *          the userType parameter.
   * @exception TokenException
   *              If login fails.
   */
  public void login(long userType, char[] pin) throws TokenException {
    try {
      pkcs11Module.C_Login(sessionHandle, userType, pin);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Logs out this session.
   *
   * @exception TokenException
   *              If logging out the session fails.
   */
  public void logout() throws TokenException {
    try {
      pkcs11Module.C_Logout(sessionHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Create a new object on the token (or in the session). The application
   * must provide a template that holds enough information to create a certain
   * object. For instance, if the application wants to create a new DES key
   * object it creates a new instance of the DESSecretKey class to serve as a
   * template. The application must set all attributes of this new object
   * which are required for the creation of such an object on the token. Then
   * it passes this DESSecretKey object to this method to create the object on
   * the token.
   *
   * Refer to the PKCS#11 standard to find out what attributes must be
   * set for certain types of objects to create them on the token.
   *
   * @param template
   *          The template that holds all values that the new object on
   *          the token should contain.
   * @return  Handle of the new PKCS#11 PKCS11Object
   * @exception TokenException
   *              If the creation of the new object fails. If it fails, the no
   *              new object was created on the token.
   */
  public long createObject(AttributeVector template) throws TokenException {
    try {
      return pkcs11Module.C_CreateObject(sessionHandle, toOutCKAttributes(template));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Copy an existing object. The source object and a template object are
   * given. Any value set in the template object will override the
   * corresponding value from the source object, when the new object is
   * created. See the PKCS#11 standard for details.
   *
   * @param sourceObjectHandle
   *          The source object of the copy operation.
   * @param template
   *          A template object whose attribute values are used for the new
   *          object; i.e. they have higher priority than the attribute values
   *          from the source object. May be null; in that case the new object
   *          is just a one-to-one copy of the sourceObject.
   * @return The new object that is created by copying the source object and
   *         setting attributes to the values given by the templateObject.
   * @exception TokenException
   *              If copying the object fails for some reason.
   */
  public long copyObject(long sourceObjectHandle, AttributeVector template) throws TokenException {
    try {
      return pkcs11Module.C_CopyObject(sessionHandle, sourceObjectHandle, toOutCKAttributes(template));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Gets all present attributes of the given template object and writes them
   * to the object to update on the token (or in the session). Both parameters
   * may refer to the same Java object. This is possible, because this method
   * only needs the object handle of the objectToUpdate, and gets the
   * attributes to set from the template. This means, an application can get
   * the object using createObject of findObject, then modify attributes of
   * this Java object and then call this method passing this object as both
   * parameters. This will update the object on the token to the values as
   * modified in the Java object.
   *
   * @param objectToUpdateHandle
   *          The attributes of this object get updated.
   * @param templateObject
   *          This method gets all present attributes of this template object
   *          and set this attributes at the objectToUpdate.
   * @exception TokenException
   *              If update of the attributes fails. All or no attributes are
   *              updated.
   */
  public void setAttributeValues(long objectToUpdateHandle, AttributeVector template) throws TokenException {
    try {
      pkcs11Module.C_SetAttributeValue(sessionHandle, objectToUpdateHandle, toOutCKAttributes(template));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the
   * object that you want to destroy. This method uses only the internal
   * object handle of the given object to identify the object.
   *
   * @param objectHandle
   *          The object that should be destroyed.
   * @exception TokenException
   *              If the object could not be destroyed.
   */
  public void destroyObject(long objectHandle) throws TokenException {
    try {
      pkcs11Module.C_DestroyObject(sessionHandle, objectHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a find operations that provides means to find objects by
   * passing a template object. This method gets all set attributes of the
   * template object and searches for all objects on the token that match with
   * these attributes.
   *
   * @param templateObject
   *          The object that serves as a template for searching. If this
   *          object is null, the find operation will find all objects that
   *          this session can see. Notice, that only a user session will see
   *          private objects.
   * @exception TokenException
   *              If initializing the find operation fails.
   */
  public void findObjectsInit(AttributeVector template) throws TokenException {
    try {
      pkcs11Module.C_FindObjectsInit(sessionHandle, template == null ? null : toOutCKAttributes(template));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Finds objects that match the template object passed to findObjectsInit.
   * The application must call findObjectsInit before calling this method.
   * With maxObjectCount the application can specify how many objects to
   * return at once; i.e. the application can get all found objects by
   * subsequent calls to this method like maxObjectCount(1) until it receives
   * an empty array (this method never returns null!).
   *
   * @param maxObjectCount
   *          Specifies how many objects to return with this call.
   * @return An array of found objects. The maximum size of this array is
   *         maxObjectCount, the minimum length is 0. Never returns null.
   * @exception TokenException
   *              A plain TokenException if something during PKCS11 FindObject
   *              went wrong, a TokenException with a nested TokenException if
   *              the Exception is raised during object parsing.
   */
  public long[] findObjects(int maxObjectCount) throws TokenException {
    try {
      long[] handles = pkcs11Module.C_FindObjects(sessionHandle, maxObjectCount);
      return handles == null ? new long[0] : handles;
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

    /**
     * Finalizes a find operation. The application must call this method to
     * finalize a find operation before attempting to start any other operation.
     *
     * @exception TokenException
     *              If finalizing the current find operation was not possible.
     */
  public void findObjectsFinal() throws TokenException {
    try {
      pkcs11Module.C_FindObjectsFinal(sessionHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new encryption operation. The application must call this
   * method before calling any other encrypt* operation. Before initializing a
   * new operation, any currently pending operation must be finalized using
   * the appropriate *Final method (e.g. digestFinal()). There are exceptions
   * for dual-function operations. This method requires the mechanism to use
   * for encryption and the key for this operation. The key must have set its
   * encryption flag. For the mechanism the application may use a constant
   * defined in the Mechanism class. Notice that the key and the mechanism
   * must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle
   *          The decryption key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void encryptInit(Mechanism mechanism, long keyHandle) throws TokenException {
    try {
      pkcs11Module.C_EncryptInit(sessionHandle, toCkMechanism(mechanism), keyHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Encrypts the given data with the key and mechanism given to the
   * encryptInit method. This method finalizes the current encryption
   * operation; i.e. the application need (and should) not call
   * encryptFinal() after this call. For encrypting multiple pieces of data
   * use encryptUpdate and encryptFinal.
   *
   * @param in
   *          buffer containing the to-be-encrypted data
   * @param inOfs
   *          buffer offset of the to-be-encrypted data
   * @param inLen
   *          length of the to-be-encrypted data
   * @param out
   *          buffer for the encrypted data
   * @param outOfs
   *          buffer offset for the encrypted data
   * @param outLen
   *          buffer size for the encrypted data
   * @return the length of encrypted data
   * @exception TokenException
   *              If encrypting failed.
   */
  public int encrypt(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);
    try {
      if (encrypt0 != null) {
        return (int) encrypt0.invoke(pkcs11Module, sessionHandle, in, inOfs, inLen, out, outOfs, outLen);
      } else if (encrypt1 != null) {
        return (int) encrypt1.invoke(pkcs11Module, sessionHandle, 0, in, inOfs, inLen, 0, out, outOfs, outLen);
      } else {
        throw new IllegalStateException("could not find C_ENCRYPT method");
      }
    } catch (IllegalAccessException ex) {
      throw new TokenException("", ex);
    } catch (InvocationTargetException ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
        throw new PKCS11Exception(((sun.security.pkcs11.wrapper.PKCS11Exception) cause).getErrorCode());
      } else if (cause instanceof RuntimeException) {
        throw (RuntimeException) cause;
      } else {
        throw new TokenException("Error " + ex.getMessage(), ex);
      }
    }
  }

  /**
   * This method can be used to encrypt multiple pieces of data; e.g.
   * buffer-size pieces when reading the data from a stream. Encrypts the
   * given data with the key and mechanism given to the encryptInit method.
   * The application must call encryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   *
   * @param in
   *          buffer containing the to-be-encrypted data
   * @param inOfs
   *          buffer offset of the to-be-encrypted data
   * @param inLen
   *          length of the to-be-encrypted data
   * @param out
   *          buffer for the encrypted data
   * @param outOfs
   *          buffer offset for the encrypted data
   * @param outLen
   *          buffer size for the encrypted data
   * @return the length of encrypted data for this update
   * @exception TokenException
   *              If encrypting the data failed.
   */
  public int encryptUpdate(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen)
      throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_EncryptUpdate(sessionHandle, 0, in, inOfs, inLen, 0, out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method finalizes an encryption operation and returns the final
   * result. Use this method, if you fed in the data using encryptUpdate. If
   * you used the encrypt(byte[]) method, you need not (and shall not) call
   * this method, because encrypt(byte[]) finalizes the encryption itself.
   *
   * @param out
   *          buffer for the encrypted data
   * @param outOfs
   *          buffer offset for the encrypted data
   * @param outLen
   *          buffer size for the encrypted data
   * @return the length of the last part of the encrypted data
   * @exception TokenException
   *              If calculating the final result failed.
   */
  public int encryptFinal(byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_EncryptFinal(sessionHandle, 0, out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new decryption operation. The application must call this
   * method before calling any other decrypt* operation. Before initializing a
   * new operation, any currently pending operation must be finalized using
   * the appropriate *Final method (e.g. digestFinal()). There are exceptions
   * for dual-function operations. This method requires the mechanism to use
   * for decryption and the key for this operation. The key must have set its
   * decryption flag. For the mechanism the application may use a constant
   * defined in the Mechanism class. Notice that the key and the mechanism
   * must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle
   *          The decryption key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void decryptInit(Mechanism mechanism, long keyHandle) throws TokenException {
    try {
      pkcs11Module.C_DecryptInit(sessionHandle, toCkMechanism(mechanism), keyHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Decrypts the given data with the key and mechanism given to the
   * decryptInit method. This method finalizes the current decryption
   * operation; i.e. the application need (and should) not call decryptFinal()
   * after this call. For decrypting multiple pieces of data use decryptUpdate
   * and decryptFinal.
   *
   * @param in
   *          buffer containing the to-be-decrypted data
   * @param inOfs
   *          buffer offset of the to-be-decrypted data
   * @param inLen
   *          length of the to-be-decrypted data
   * @param out
   *          buffer for the decrypted data
   * @param outOfs
   *          buffer offset for the decrypted data
   * @param outLen
   *          buffer size for the decrypted data
   * @return the length of decrypted data
   * @exception TokenException
   *              If decrypting failed.
   */
  public int decrypt(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);

    try {
      if (decrypt0 != null) {
        return (int) decrypt0.invoke(pkcs11Module, sessionHandle, in, inOfs, inLen, out, outOfs, outLen);
      } else if (decrypt1 != null) {
        return (int) decrypt1.invoke(pkcs11Module, sessionHandle, 0, in, inOfs, inLen, 0, out, outOfs, outLen);
      } else {
        throw new IllegalStateException("could not find C_DECRYPT method");
      }
    } catch (IllegalAccessException ex) {
      throw new TokenException("", ex);
    } catch (InvocationTargetException ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
        throw new PKCS11Exception(((sun.security.pkcs11.wrapper.PKCS11Exception) cause).getErrorCode());
      } else if (cause instanceof RuntimeException) {
        throw (RuntimeException) cause;
      } else {
        throw new TokenException("Error " + ex.getMessage(), ex);
      }
    }
  }

  /**
   * This method can be used to decrypt multiple pieces of data; e.g.
   * buffer-size pieces when reading the data from a stream. Decrypts the
   * given data with the key and mechanism given to the decryptInit method.
   * The application must call decryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   *
   * @param in
   *          buffer containing the to-be-decrypted data
   * @param inOfs
   *          buffer offset of the to-be-decrypted data
   * @param inLen
   *          length of the to-be-decrypted data
   * @param out
   *          buffer for the decrypted data
   * @param outOfs
   *          buffer offset for the decrypted data
   * @param outLen
   *          buffer size for the decrypted data
   * @return the length of decrypted data for this update
   * @exception TokenException
   *              If decrypting the data failed.
   */
  public int decryptUpdate(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_DecryptUpdate(sessionHandle, 0, in, inOfs, inLen, 0, out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method finalizes a decryption operation and returns the final
   * result. Use this method, if you fed in the data using decryptUpdate. If
   * you used the decrypt(byte[]) method, you need not (and shall not) call
   * this method, because decrypt(byte[]) finalizes the decryption itself.
   *
   * @param out
   *          buffer for the decrypted data
   * @param outOfs
   *          buffer offset for the decrypted data
   * @param outLen
   *          buffer size for the decrypted data
   * @return the length of this last part of decrypted data
   * @exception TokenException
   *              If calculating the final result failed.
   */
  public int decryptFinal(byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_DecryptFinal(sessionHandle, 0, out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new digesting operation. The application must call this
   * method before calling any other digest* operation. Before initializing a
   * new operation, any currently pending operation must be finalized using
   * the appropriate *Final method (e.g. digestFinal()). There are exceptions
   * for dual-function operations. This method requires the mechanism to use
   * for digesting for this operation. For the mechanism the application may
   * use a constant defined in the Mechanism class.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.SHA_1.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void digestInit(Mechanism mechanism) throws TokenException {
    try {
      pkcs11Module.C_DigestInit(sessionHandle, toCkMechanism(mechanism));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Digests the given data with the mechanism given to the digestInit method.
   * This method finalizes the current digesting operation; i.e. the
   * application need (and should) not call digestFinal() after this call. For
   * digesting multiple pieces of data use digestUpdate and digestFinal.
   *
   * @param in
   *          buffer containing the to-be-digested data
   * @param inOfs
   *          buffer offset of the to-be-digested data
   * @param inLen
   *          length of the to-be-digested data
   * @param digest
   *          buffer for the digested data
   * @param digestOfs
   *          buffer offset for the digested data
   * @param digestLen
   *          buffer size for the digested data
   * @return the length of digested data for this update
   * @exception TokenException
   *              If digesting the data failed.
   */
  public int digest(byte[] in, int inOfs, int inLen, byte[] digest, int digestOfs, int digestLen)
      throws TokenException {
    digestUpdate(in, inOfs, inLen);
    return digestFinal(digest, digestOfs, digestLen);
  }

  /**
   * This method digests data in a single part.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.SHA_1.
   * @param in
   *          buffer containing the to-be-digested data
   * @param inOfs
   *          buffer offset of the to-be-digested data
   * @param inLen
   *          length of the to-be-digested data
   * @param digest
   *          buffer for the digested data
   * @param digestOfs
   *          buffer offset for the digested data
   * @param digestLen
   *          buffer size for the digested data
   * @return the length of digested data for this update
   * @throws TokenException
   *              If digesting the data failed.
   */
  public int digestSingle(Mechanism mechanism, byte[] in, int inOfs, int inLen,
                          byte[] digest, int digestOfs, int digestLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("digest", digest);

    try {
      return pkcs11Module.C_DigestSingle(sessionHandle, toCkMechanism(mechanism),
          in, inOfs, inLen, digest, digestOfs, digestLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method can be used to digest multiple pieces of data; e.g.
   * buffer-size pieces when reading the data from a stream. Digests the given
   * data with the mechanism given to the digestInit method. The application
   * must call digestFinal to get the final result of the digesting after
   * feeding in all data using this method.
   *
   * @param part
   *          buffer containing the to-be-digested data
   * @param partOfs
   *          buffer offset of the to-be-digested data
   * @param partLen
   *          length of the to-be-digested data
   * @exception TokenException
   *              If digesting the data failed.
   */
  public void digestUpdate(byte[] part, int partOfs, int partLen) throws TokenException {
    Util.requireNonNull("part", part);

    try {
      pkcs11Module.C_DigestUpdate(sessionHandle, 0, part, partOfs, partLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method is similar to digestUpdate and can be combined with it during
   * one digesting operation. This method digests the value of the given
   * secret key.
   *
   * @param keyHandle
   *          The key to digest the value of.
   * @exception TokenException
   *              If digesting the key failed.
   */
  public void digestKey(long keyHandle) throws TokenException {
    try {
      pkcs11Module.C_DigestKey(sessionHandle, keyHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method finalizes a digesting operation and returns the final result.
   * Use this method, if you fed in the data using digestUpdate and/or
   * digestKey. If you used the digest(byte[]) method, you need not (and shall
   * not) call this method, because digest(byte[]) finalizes the digesting
   * itself.
   *
   * @param digest
   *          buffer for the message digest
   * @param digestOfs
   *          buffer offset for the message digest
   * @param digestLen
   *          buffer size for the message digest
   * @return the length of message digest
   * @exception TokenException
   *              If calculating the final message digest failed.
   */
  public int digestFinal(byte[] digest, int digestOfs, int digestLen) throws TokenException {
    Util.requireNonNull("digest", digest);

    try {
      return pkcs11Module.C_DigestFinal(sessionHandle, digest, digestOfs, digestLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new signing operation. Use it for signatures and MACs. The
   * application must call this method before calling any other sign*
   * operation. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method
   * (e.g. digestFinal()). There are exceptions for dual-function operations.
   * This method requires the mechanism to use for signing and the key for
   * this operation. The key must have set its sign flag. For the mechanism
   * the application may use a constant defined in the Mechanism class. Notice
   * that the key and the mechanism must be compatible; i.e. you cannot use a
   * DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param keyHandle
   *          The signing key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void signInit(Mechanism mechanism, long keyHandle) throws TokenException {
    try {
      pkcs11Module.C_SignInit(sessionHandle, toCkMechanism(mechanism), keyHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Signs the given data with the key and mechanism given to the signInit
   * method. This method finalizes the current signing operation; i.e. the
   * application need (and should) not call signFinal() after this call. For
   * signing multiple pieces of data use signUpdate and signFinal.
   *
   * @param data
   *          The data to sign.
   * @return The signed data.
   * @exception TokenException
   *              If signing the data failed.
   */
  public byte[] sign(byte[] data) throws TokenException {
    Util.requireNonNull("data", data);

    try {
      return pkcs11Module.C_Sign(sessionHandle, data);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method can be used to sign multiple pieces of data; e.g. buffer-size
   * pieces when reading the data from a stream. Signs the given data with the
   * mechanism given to the signInit method. The application must call
   * signFinal to get the final result of the signing after feeding in all
   * data using this method.
   *
   * @param in
   *          buffer containing the to-be-signed data
   * @param inOfs
   *          buffer offset of the to-be-signed data
   * @param inLen
   *          length of the to-be-signed data
   * @exception TokenException
   *              If signing the data failed.
   */
  public void signUpdate(byte[] in, int inOfs, int inLen) throws TokenException {
    Util.requireNonNull("in", in);

    try {
      pkcs11Module.C_SignUpdate(sessionHandle, 0, in, inOfs, inLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method finalizes a signing operation and returns the final result.
   * Use this method, if you fed in the data using signUpdate. If you used the
   * sign(byte[]) method, you need not (and shall not) call this method,
   * because sign(byte[]) finalizes the signing operation itself.
   *
   * @param expectedLen
   *          expected length of the signature value.
   * @return The final result of the signing operation; i.e. the signature
   *         value.
   * @exception TokenException
   *              If calculating the final signature value failed.
   */
  public byte[] signFinal(int expectedLen) throws TokenException {
    try {
      return pkcs11Module.C_SignFinal(sessionHandle, expectedLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new signing operation for signing with recovery. The
   * application must call this method before calling signRecover. Before
   * initializing a new operation, any currently pending operation must be
   * finalized using the appropriate *Final method (e.g. digestFinal()). There
   * are exceptions for dual-function operations. This method requires the
   * mechanism to use for signing and the key for this operation. The key must
   * have set its sign-recover flag. For the mechanism the application may use
   * a constant defined in the Mechanism class. Notice that the key and the
   * mechanism must be compatible; i.e. you cannot use a DES key with the RSA
   * mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param keyHandle
   *          The signing key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void signRecoverInit(Mechanism mechanism, long keyHandle) throws TokenException {
    try {
      pkcs11Module.C_SignRecoverInit(sessionHandle, toCkMechanism(mechanism), keyHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Signs the given data with the key and mechanism given to the
   * signRecoverInit method. This method finalizes the current sign-recover
   * operation; there is no equivalent method to signUpdate for signing with
   * recovery.
   *
   * @param in
   *          buffer containing the to-be-signed data
   * @param inOfs
   *          buffer offset of the to-be-signed data
   * @param inLen
   *          length of the to-be-signed data
   * @param out
   *          buffer for the signed data
   * @param outOfs
   *          buffer offset for the signed data
   * @param outLen
   *          buffer size for the signed data
   * @return the length of signed data
   * @exception TokenException
   *              If signing the data failed.
   */
  public int signRecover(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_SignRecover(sessionHandle, in, inOfs, inLen, out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new verification operation. You can use it for verifying
   * signatures and MACs. The application must call this method before calling
   * any other verify* operation. Before initializing a new operation, any
   * currently pending operation must be finalized using the appropriate
   * *Final method (e.g. digestFinal()). There are exceptions for
   * dual-function operations. This method requires the mechanism to use for
   * verification and the key for this operation. The key must have set its
   * verify flag. For the mechanism the application may use a constant defined
   * in the Mechanism class. Notice that the key and the mechanism must be
   * compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param keyHandle
   *          The verification key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void verifyInit(Mechanism mechanism, long keyHandle) throws TokenException {
    try {
      pkcs11Module.C_VerifyInit(sessionHandle, toCkMechanism(mechanism), keyHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Verifies the given signature against the given data with the key and
   * mechanism given to the verifyInit method. This method finalizes the
   * current verification operation; i.e. the application need (and should)
   * not call verifyFinal() after this call. For verifying with multiple
   * pieces of data use verifyUpdate and verifyFinal. This method throws an
   * exception, if the verification of the signature fails.
   *
   * @param data
   *          The data that was signed.
   * @param signature
   *          The signature or MAC to verify.
   * @exception TokenException
   *              If verifying the signature fails. This is also the case, if
   *              the signature is forged.
   */
  public void verify(byte[] data, byte[] signature) throws TokenException {
    Util.requireNonNull("signature", signature);

    try {
      pkcs11Module.C_Verify(sessionHandle, data, signature);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method can be used to verify a signature with multiple pieces of
   * data; e.g. buffer-size pieces when reading the data from a stream. To
   * verify the signature or MAC call verifyFinal after feeding in all data
   * using this method.
   *
   * @param in
   *          buffer containing the to-be-verified data
   * @param inOfs
   *          buffer offset of the to-be-verified data
   * @param inLen
   *          length of the to-be-verified data
   * @exception TokenException
   *              If verifying (e.g. digesting) the data failed.
   */
  public void verifyUpdate(byte[] in, int inOfs, int inLen) throws TokenException {
    Util.requireNonNull("in", in);

    try {
      pkcs11Module.C_VerifyUpdate(sessionHandle, 0, in, inOfs, inLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * This method finalizes a verification operation. Use this method, if you
   * fed in the data using verifyUpdate. If you used the verify(byte[])
   * method, you need not (and shall not) call this method, because
   * verify(byte[]) finalizes the verification operation itself. If this
   * method verified the signature successfully, it returns normally. If the
   * verification of the signature fails, e.g. if the signature was forged or
   * the data was modified, this method throws an exception.
   *
   * @param signature
   *          The signature value.
   * @exception TokenException
   *              If verifying the signature fails. This is also the case, if
   *              the signature is forged.
   */
  public void verifyFinal(byte[] signature) throws TokenException {
    Util.requireNonNull("signature", signature);

    try {
      pkcs11Module.C_VerifyFinal(sessionHandle, signature);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Initializes a new verification operation for verification with data
   * recovery. The application must call this method before calling
   * verifyRecover. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g.
   * digestFinal()). This method requires the mechanism to use for
   * verification and the key for this operation. The key must have set its
   * verify-recover flag. For the mechanism the application may use a constant
   * defined in the Mechanism class. Notice that the key and the mechanism
   * must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param keyHandle
   *          The verification key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   */
  public void verifyRecoverInit(Mechanism mechanism, long keyHandle) throws TokenException {
    try {
      pkcs11Module.C_VerifyRecoverInit(sessionHandle, toCkMechanism(mechanism), keyHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Signs the given data with the key and mechanism given to the
   * signRecoverInit method. This method finalizes the current sign-recover
   * operation; there is no equivalent method to signUpdate for signing with
   * recovery.
   *
   * @param in
   *          buffer containing the to-be-verified data
   * @param inOfs
   *          buffer offset of the to-be-verified data
   * @param inLen
   *          length of the to-be-verified data
   * @param out
   *          buffer for the verified data
   * @param outOfs
   *          buffer offset for the verified data
   * @param outLen
   *          buffer size for the verified data
   * @return the length of verified data
   * @exception TokenException
   *              If signing the data failed.
   */
  public int verifyRecover(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws TokenException {
    Util.requireNonNull("in", in);
    Util.requireNonNull("out", out);

    try {
      return pkcs11Module.C_VerifyRecover(sessionHandle, in, inOfs, inLen, out, outOfs, outLen);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Generate a new secret key or a set of domain parameters. It uses the set
   * attributes of the template for setting the attributes of the new key
   * object. As mechanism the application can use a constant of the Mechanism
   * class.
   *
   * @param mechanism
   *          The mechanism to generate a key for; e.g. Mechanism.DES to
   *          generate a DES key.
   * @param template
   *          The template for the new key or domain parameters; e.g. a
   *          DESSecretKey object which has set certain attributes.
   * @return The newly generated secret key or domain parameters.
   * @exception TokenException
   *              If generating a new secret key or domain parameters failed.
   */
  public long generateKey(Mechanism mechanism, AttributeVector template) throws TokenException {
    try {
      return pkcs11Module.C_GenerateKey(sessionHandle, toCkMechanism(mechanism), toOutCKAttributes(template));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Generate a new public key - private key key-pair and use the set
   * attributes of the template objects for setting the attributes of the new
   * public key and private key objects. As mechanism the application can use
   * a constant of the Mechanism class.
   *
   * @param mechanism
   *          The mechanism to generate a key for; e.g. Mechanism.RSA to
   *          generate a new RSA key-pair.
   * @param publicKeyTemplate
   *          The template for the new public key part; e.g. a RSAPublicKey
   *          object which has set certain attributes (e.g. public exponent
   *          and verify).
   * @param privateKeyTemplate
   *          The template for the new private key part; e.g. a RSAPrivateKey
   *          object which has set certain attributes (e.g. sign and decrypt).
   * @return The newly generated key-pair.
   * @exception TokenException
   *              If generating a new key-pair failed.
   */
  public KeyPair generateKeyPair(Mechanism mechanism, AttributeVector publicKeyTemplate,
                                 AttributeVector privateKeyTemplate) throws TokenException {
    long[] objectHandles;
    try {
      objectHandles = pkcs11Module.C_GenerateKeyPair(sessionHandle, toCkMechanism(mechanism),
          toOutCKAttributes(publicKeyTemplate), toOutCKAttributes(privateKeyTemplate));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }

    return new KeyPair(objectHandles[0], objectHandles[1]);
  }

  /**
   * Wraps (encrypts) the given key with the wrapping key using the given
   * mechanism.
   *
   * @param mechanism
   *          The mechanism to use for wrapping the key.
   * @param wrappingKeyHandle
   *          The key to use for wrapping (encrypting).
   * @param keyHandle
   *          The key to wrap (encrypt).
   * @return The wrapped key as byte array.
   * @exception TokenException
   *              If wrapping the key failed.
   */
  public byte[] wrapKey(Mechanism mechanism, long wrappingKeyHandle, long keyHandle) throws TokenException {
    try {
      return pkcs11Module.C_WrapKey(sessionHandle, toCkMechanism(mechanism), wrappingKeyHandle, keyHandle);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Unwraps (decrypts) the given encrypted key with the unwrapping key using
   * the given mechanism. The application can also pass a template key to set
   * certain attributes of the unwrapped key. This creates a key object after
   * unwrapping the key and returns an object representing this key.
   *
   * @param mechanism
   *          The mechanism to use for unwrapping the key.
   * @param unwrappingKeyHandle
   *          The key to use for unwrapping (decrypting).
   * @param wrappedKey
   *          The encrypted key to unwrap (decrypt).
   * @param keyTemplate
   *          The template for creating the new key object.
   * @return A key object representing the newly created key object.
   * @exception TokenException
   *              If unwrapping the key or creating a new key object failed.
   */
  public long unwrapKey(Mechanism mechanism, long unwrappingKeyHandle,
                        byte[] wrappedKey, AttributeVector keyTemplate)
      throws TokenException {
    Util.requireNonNull("wrappedKey", wrappedKey);

    try {
      return pkcs11Module.C_UnwrapKey(sessionHandle, toCkMechanism(mechanism),
          unwrappingKeyHandle, wrappedKey, toOutCKAttributes(keyTemplate));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Derives a new key from a specified base key using the given mechanism.
   * After deriving a new key from the base key, a new key object is created
   * and a representation of it is returned. The application can provide a
   * template key to set certain attributes of the new key object.
   *
   * @param mechanism
   *          The mechanism to use for deriving the new key from the base key.
   * @param baseKeyHandle
   *          The key to use as base for derivation.
   * @param template
   *          The template for creating the new key object.
   * @return A key object representing the newly derived (created) key object
   *         or null, if the used mechanism uses other means to return its
   *         values; e.g. the CKM_SSL3_KEY_AND_MAC_DERIVE mechanism.
   * @exception TokenException
   *              If deriving the key or creating a new key object failed.
   */
  public long deriveKey(Mechanism mechanism, long baseKeyHandle, AttributeVector template) throws TokenException {
    CK_MECHANISM ckMechanism = toCkMechanism(mechanism);

    try {
      return pkcs11Module.C_DeriveKey(sessionHandle, ckMechanism, baseKeyHandle, toOutCKAttributes(template));
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Mixes additional seeding material into the random number generator.
   *
   * @param seed
   *          The seed bytes to mix in.
   * @exception TokenException
   *              If mixing in the seed failed.
   */
  public void seedRandom(byte[] seed) throws TokenException {
    try {
      pkcs11Module.C_SeedRandom(sessionHandle, seed);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    }
  }

  /**
   * Generates a certain number of random bytes.
   *
   * @param numberOfBytesToGenerate
   *          The number of random bytes to generate.
   * @return An array of random bytes with length numberOfBytesToGenerate.
   * @exception TokenException
   *              If generating random bytes failed.
   */
  public byte[] generateRandom(int numberOfBytesToGenerate) throws TokenException {
    byte[] randomBytesBuffer = new byte[numberOfBytesToGenerate];
    try {
      pkcs11Module.C_GenerateRandom(sessionHandle, randomBytesBuffer);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      throw new PKCS11Exception(ex);
    } // fill the buffer with random bytes
    return randomBytesBuffer;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return "Session Handle: 0x" + Long.toHexString(sessionHandle) +  "\nToken: " + token;
  }

  private CK_MECHANISM toCkMechanism(Mechanism mechanism) {
    long code = mechanism.getMechanismCode();
    if ((code & PKCS11Constants.CKM_VENDOR_DEFINED) != 0) {
      if (vendorCode != null) {
        code = vendorCode.ckmGenericToVendor(code);
      }
    }

    Parameters params = mechanism.getParameters();
    if (params == null) {
      return new CK_MECHANISM(code);
    } else if (params instanceof AesCtrParameters) {
      return new CK_MECHANISM(code, ((AesCtrParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof DHPkcsDeriveParameters) {
      return new CK_MECHANISM(code, ((DHPkcsDeriveParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof EcDH1KeyDerivationParameters) {
      return new CK_MECHANISM(code, ((EcDH1KeyDerivationParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof EcDH2KeyDerivationParameters) {
//      return new CK_MECHANISM(code, ((EcDH2KeyDerivationParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof ExtractParameters) {
      return new CK_MECHANISM(code, ((ExtractParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof InitializationVectorParameters) {
      return new CK_MECHANISM(code, ((InitializationVectorParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof MacGeneralParameters) {
      return new CK_MECHANISM(code, ((MacGeneralParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof ObjectHandleParameters) {
      return new CK_MECHANISM(code, ((ObjectHandleParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof OpaqueParameters) {
      return new CK_MECHANISM(code, ((OpaqueParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof PBEParameters) {
//      return new CK_MECHANISM(code, ((PBEParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof PKCS5PBKD2Parameters) {
//      return new CK_MECHANISM(code, ((PKCS5PBKD2Parameters) params).getPKCS11ParamsObject());
    } else if (params instanceof RSAPkcsOaepParameters) {
//      return new CK_MECHANISM(code, ((RSAPkcsOaepParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof RSAPkcsPssParameters) {
      CK_MECHANISM mech = new CK_MECHANISM(code);
      CK_RSA_PKCS_PSS_PARAMS pParams = ((RSAPkcsPssParameters) params).getPKCS11ParamsObject();
      try {
        if (field_CK_MECHANISM_pParameter != null) {
          field_CK_MECHANISM_pParameter.set(mech, pParams);
        } else if (method_CK_MECHANISM_setParameter != null) {
          method_CK_MECHANISM_setParameter.invoke(mech, pParams);
        } else {
          throw new IllegalStateException("could not construct CK_MECHANISM for RSAPkcsPssParams");
        }
      } catch (IllegalAccessException | InvocationTargetException ex) {
        throw new IllegalStateException("could not construct CK_MECHANISM for RSAPkcsPssParams", ex);
      }
      return mech;
    } else if (params instanceof VersionParameters) {
      return new CK_MECHANISM(code, ((VersionParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof X942DH1KeyDerivationParameters) {
//      return new CK_MECHANISM(code, ((X942DH1KeyDerivationParameters) params).getPKCS11ParamsObject());
    } else if (params instanceof X942DH2KeyDerivationParameters) {
//      return new CK_MECHANISM(code, ((X942DH2KeyDerivationParameters) params).getPKCS11ParamsObject());
    } else {
      Constructor<?> constructor;
      if (params instanceof CCMParameters) {
        constructor = constructor_CK_MECHANISM_CCM;
      } else if (params instanceof GCMParameters) {
        constructor = constructor_CK_MECHANISM_GCM;
      } else {
        constructor = null;
      }

      if (constructor == null) {
        throw new IllegalArgumentException("could not find constructor");
      }
      try {
        return (CK_MECHANISM) constructor.newInstance(code, params.getPKCS11ParamsObject());
      } catch (Exception ex) {
        throw new IllegalArgumentException("could not construct CK_MECHANISM", ex);
      }
    }

    throw new IllegalArgumentException("Unsupported Parameters " + params.getClass().getName());
  }

  public Long getLongAttributeValue(long objectHandle, long attributeType) throws PKCS11Exception {
    LongAttribute attr = new LongAttribute(attributeType);
    getAttributeValue(objectHandle, attr);
    return attr.getLongValue();
  }

  public Long[] getLongAttributeValues(long objectHandle, long... attributeTypes) throws PKCS11Exception {
    LongAttribute[] attrs = new LongAttribute[attributeTypes.length];
    int idx = 0;
    for (long attrType : attributeTypes) {
      attrs[idx++] = new LongAttribute(attrType);
    }

    getAttributeValues(objectHandle, attrs);

    Long[] ret = new Long[attributeTypes.length];
    idx = 0;
    for (LongAttribute attr : attrs) {
      ret[idx++] = attr.getLongValue();
    }
    return ret;
  }

  public char[] getCharAttributeValue(long objectHandle, long attributeType) throws PKCS11Exception {
    CharArrayAttribute attr = new CharArrayAttribute(attributeType);
    getAttributeValue(objectHandle, attr);
    return attr.getCharArrayValue();
  }

  public char[][] getCharAttributeValues(long objectHandle, long... attributeTypes) throws PKCS11Exception {
    CharArrayAttribute[] attrs = new CharArrayAttribute[attributeTypes.length];
    int idx = 0;
    for (long attrType : attributeTypes) {
      attrs[idx++] = new CharArrayAttribute(attrType);
    }

    getAttributeValues(objectHandle, attrs);

    char[][] ret = new char[attributeTypes.length][];
    idx = 0;
    for (CharArrayAttribute attr : attrs) {
      ret[idx++] = attr.getCharArrayValue();
    }
    return ret;
  }

  public String getCharAttributeStringValue(long objectHandle, long attributeType) throws PKCS11Exception {
    char[] chars = getCharAttributeValue(objectHandle, attributeType);
    return chars == null ? null : new String(chars);
  }

  public String[] getCharAttributeStringValues(long objectHandle, long... attributeTypes) throws PKCS11Exception {
    char[][] charsArray = getCharAttributeValues(objectHandle, attributeTypes);

    String[] ret = new String[attributeTypes.length];
    int idx = 0;
    for (char[] chars : charsArray) {
      ret[idx++] = chars == null ? null : new String(chars);
    }
    return ret;
  }

  public BigInteger getByteArrayAttributeBigIntValue(long objectHandle, long attributeType) throws PKCS11Exception {
    byte[] value = getByteArrayAttributeValue(objectHandle, attributeType);
    return value == null ? null : new BigInteger(1, value);
  }

  public BigInteger[] getByteArrayAttributeBigIntValues(long objectHandle, long... attributeTypes) throws PKCS11Exception {
    byte[][] values = getByteArrayAttributeValues(objectHandle, attributeTypes);
    BigInteger[] ret = new BigInteger[attributeTypes.length];
    for (int i = 0; i < values.length; i++) {
      ret[i] = new BigInteger(1, values[i]);
    }
    return ret;
  }

  public byte[] getByteArrayAttributeValue(long objectHandle, long attributeType) throws PKCS11Exception {
    ByteArrayAttribute attr = new ByteArrayAttribute(attributeType);
    getAttributeValue(objectHandle, attr);
    return attr.getByteArrayValue();
  }

  public byte[][] getByteArrayAttributeValues(long objectHandle, long... attributeTypes) throws PKCS11Exception {
    ByteArrayAttribute[] attrs = new ByteArrayAttribute[attributeTypes.length];
    int idx = 0;
    for (long attrType : attributeTypes) {
      attrs[idx++] = new ByteArrayAttribute(attrType);
    }

    getAttributeValues(objectHandle, attrs);

    byte[][] ret = new byte[attributeTypes.length][];
    idx = 0;
    for (ByteArrayAttribute attr : attrs) {
      ret[idx++] = attr.getByteArrayValue();
    }
    return ret;
  }

  /**
   * This method reads the attributes at once. This can lead  to performance
   * improvements. If reading all attributes at once fails, it tries to read
   * each attributes individually.
   *
   * @param objectHandle
   *          The handle of the object which contains the attributes.
   * @param attributes
   *          The objects specifying the attribute types
   *          (see {@link Attribute#getType()}) and receiving the attribute
   *          values (see {@link Attribute#setCkAttribute(CK_ATTRIBUTE)}).
   * @exception PKCS11Exception
   *              If getting the attributes failed.
   */
  public void getAttributeValues(long objectHandle, Attribute... attributes) throws PKCS11Exception {
    Util.requireNonNull("attributes", attributes);

    PKCS11 pkcs11Module = module.getPKCS11Module();

    CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[attributes.length];
    for (int i = 0; i < attributeTemplateList.length; i++) {
      CK_ATTRIBUTE attribute = new CK_ATTRIBUTE();
      attribute.type = attributes[i].getType();
      attributeTemplateList[i] = attribute;
      attributes[i].setStateKnown(false);
    }

    PKCS11Exception delayedEx = null;
    try {
      pkcs11Module.C_GetAttributeValue(sessionHandle, objectHandle, attributeTemplateList);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      delayedEx = new PKCS11Exception(ex);
    }

    for (int i = 0; i < attributes.length; i++) {
      Attribute attribute = attributes[i];
      CK_ATTRIBUTE template = attributeTemplateList[i];
      if (template != null) {
        attribute.setStateKnown(true);
        attribute.setPresent(true);
        attribute.setSensitive(false);

        if (attribute instanceof BooleanAttribute) {
          fixBooleanAttrValue(template);
        }
        attribute.setCkAttribute(template);
      } else {
        attribute.setStateKnown(false);
        attribute.setPresent(false);
        attribute.setSensitive(true);
      }
    }

    if (delayedEx == null) {
      for (Attribute attr : attributes) {
        postProcessGetAttribute(attr);
      }
      return;
    }

    // do all separately again.
    delayedEx = null;
    for (Attribute attr : attributes) {
      try {
        getAttributeValue(objectHandle, attr, true);
      } catch (PKCS11Exception ex) {
        if (delayedEx == null) {
          delayedEx = ex;
        }
      }
    }

    if (delayedEx != null) {
      throw delayedEx;
    }
  }

  /**
   * This method reads the attribute specified by <code>attribute</code> from
   * the token using the given <code>session</code>.
   * The object from which to read the attribute is specified using the
   * <code>objectHandle</code>. The <code>attribute</code> will contain
   * the results.
   * If the attempt to read the attribute returns
   * <code>CKR_ATTRIBUTE_TYPE_INVALID</code>, this will be indicated by
   * setting {@link Attribute#setPresent(boolean)} to <code>false</code>.
   * It CKR_ATTRIBUTE_SENSITIVE is returned, the attribute object is
   * marked as present
   * (by calling {@link Attribute#setPresent(boolean)} with
   * <code>true</code>), and in addition as sensitive by calling
   * {@link Attribute#setSensitive(boolean)} with <code>true</code>.
   *
   * @param objectHandle
   *          The handle of the object which contains the attribute.
   * @param attribute
   *          The object specifying the attribute type
   *          (see {@link Attribute#getType()}) and receiving the attribute
   *          value (see {@link Attribute#setCkAttribute(CK_ATTRIBUTE)}).
   * @exception PKCS11Exception
   *              If getting the attribute failed.
   */
  public void getAttributeValue(long objectHandle, Attribute attribute) throws PKCS11Exception {
    getAttributeValue(objectHandle, attribute, true);
  }

  public void getAttributeValue(long objectHandle, Attribute attribute, boolean ignoreParsableException)
      throws PKCS11Exception {
    PKCS11 pkcs11Module = module.getPKCS11Module();
    long attributeCode = attribute.getType();
    attribute.setStateKnown(false);
    attribute.setPresent(false);

    try {
      CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
      attributeTemplateList[0] = new CK_ATTRIBUTE();
      attributeTemplateList[0].type = attributeCode;
      pkcs11Module.C_GetAttributeValue(sessionHandle, objectHandle, attributeTemplateList);

      if (attribute instanceof BooleanAttribute) {
        fixBooleanAttrValue(attributeTemplateList[0]);
      }

      attribute.setCkAttribute(attributeTemplateList[0]);
      attribute.setStateKnown(true);
      attribute.setPresent(true);
      attribute.setSensitive(false);
      postProcessGetAttribute(attribute);
    } catch (sun.security.pkcs11.wrapper.PKCS11Exception ex) {
      long ec = ex.getErrorCode();
      if (ec == PKCS11Constants.CKR_ATTRIBUTE_TYPE_INVALID) {
        // this means, that some requested attributes are missing, but
        // we can ignore this and proceed; e.g. a v2.01 module won't
        // have the object ID attribute
        attribute.getCkAttribute().pValue = null;
        attribute.setStateKnown(true);
        attribute.setPresent(false);
        if (!ignoreParsableException) {
          throw new PKCS11Exception(ex);
        }
      } else if (ec == PKCS11Constants.CKR_ATTRIBUTE_SENSITIVE) {
        // this means, that some requested attributes are missing, but
        // we can ignore this and proceed; e.g. a v2.01 module won't
        // have the object ID attribute
        attribute.getCkAttribute().pValue = null;
        attribute.setStateKnown(true);
        attribute.setPresent(true);
        attribute.setSensitive(true);
        if (!ignoreParsableException) {
          throw new PKCS11Exception(ex);
        }
      } else if (ec == PKCS11Constants.CKR_ARGUMENTS_BAD || ec == PKCS11Constants.CKR_FUNCTION_FAILED
          || ec == PKCS11Constants.CKR_FUNCTION_REJECTED) {
        attribute.getCkAttribute().pValue = null;
        attribute.setStateKnown(true);
        attribute.setPresent(false);
        attribute.setSensitive(false);
        if (!ignoreParsableException) {
          throw new PKCS11Exception(ex);
        }
      } else {
        // there was a different error that we should propagate
        throw new PKCS11Exception(ex);
      }
    }
  }

  private CK_ATTRIBUTE[] toOutCKAttributes(AttributeVector attributeVector) {
    CK_ATTRIBUTE[] ret = attributeVector.toCkAttributes();
    if (vendorCode != null) {
      for (CK_ATTRIBUTE ckAttr : ret) {
        if (ckAttr.type == PKCS11Constants.CKA_KEY_TYPE && ckAttr.pValue != null) {
          long value = (long) ckAttr.pValue;
          if ((value & PKCS11Constants.CKK_VENDOR_DEFINED) != 0L) {
            long vendorValue = vendorCode.ckkGenericToVendor(value);
            if (vendorValue != value) {
              ckAttr.pValue = vendorValue;
            }
          }
        }
      }
    }
    return ret;
  }

  private void postProcessGetAttribute(Attribute attr) {
    CK_ATTRIBUTE ckAttr = attr.getCkAttribute();
    if (ckAttr.type == PKCS11Constants.CKA_KEY_TYPE && ckAttr.pValue != null) {
      long value = (long) ckAttr.pValue;
      if ((value & PKCS11Constants.CKK_VENDOR_DEFINED) != 0L) {
        long genericValue = vendorCode.ckkVendorToGeneric(value);
        if (value != genericValue) {
          ckAttr.pValue = value;
        }
      }
    }
  }

  private static void fixBooleanAttrValue(CK_ATTRIBUTE attr) {
    if (!(attr.pValue instanceof byte[])) {
      return;
    }

    byte[] value = (byte[]) attr.pValue;
    boolean allZeros = true;
    for (byte b : value) {
      if (b != 0) {
        allZeros = false;
        break;
      }
    }
    attr.pValue = !allZeros;
  }

}
