// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
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
//    Technology" must not be used to endorse or promote products derived from this
//    software without prior written permission.
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

package org.xipki.pkcs11;

import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import org.xipki.pkcs11.objects.*;
import org.xipki.pkcs11.parameters.CcmMessageParameters;
import org.xipki.pkcs11.parameters.MessageParameters;
import org.xipki.pkcs11.parameters.Parameters;
import org.xipki.pkcs11.parameters.Salsa20Chacha20Poly1305MessageParameters;

import java.math.BigInteger;
import java.util.Arrays;

import static org.xipki.pkcs11.PKCS11Constants.*;

/**
 * Session objects are used to perform cryptographic operations on a token. The application gets a
 * Session object by calling openSession on a certain Token object. Having the session object, the
 * application may log-in the user, if required.
 *
 * <pre>
 * <code>
 *   TokenInfo tokenInfo = token.getTokenInfo();
 *   // check, if log-in of the user is required at all
 *   if (tokenInfo.isLoginRequired()) {
 *     // check, if the token has own means to authenticate the user; e.g. a PIN-pad on the reader
 *     if (tokenInfo.isProtectedAuthenticationPath()) {
 *       System.out.println("Please enter the user PIN at the PIN-pad of your reader.");
 *       session.login(CKU_USER, null); // the token prompts the PIN by other means; e.g. PIN-pad
 *     } else {
 *       System.out.print("Enter user-PIN and press [return key]: ");
 *       System.out.flush();
 *       BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
 *       String userPINString = input.readLine();
 *       session.login(Session.UserType.USER, userPINString.toCharArray());
 *     }
 *   }
 * </code>
 * </pre>
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
 * @author Karl Scheibelhofer
 * @author Lijun Liao (xipki)
 */
public class Session {

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  private final PKCS11Module module;

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  private final PKCS11 pkcs11;

  /**
   * The session handle to perform the operations with.
   */
  private long sessionHandle;

  private final VendorCode vendorCode;

  /**
   * The token to perform the operations on.
   */
  protected Token token;

  /**
   * True, if UTF8 encoding is used as character encoding for character array attributes and PINs.
   */
  private final boolean useUtf8;

  /**
   * True, if this is an R/W session.
   */
  private Boolean rwSession = null;

  /**
   * Constructor taking the token and the session handle.
   *
   * @param token
   *          The token this session operates with.
   * @param sessionHandle
   *          The session handle to perform the operations with.
   */
  protected Session(Token token, long sessionHandle) {
    this.token = Functions.requireNonNull("token", token);
    this.module = token.getSlot().getModule();
    this.pkcs11 = module.getPKCS11Module();
    this.vendorCode = module.getVendorCode();
    this.sessionHandle = sessionHandle;
    this.useUtf8 = token.isUseUtf8Encoding();
  }

  /**
   * Initializes the user-PIN. Can only be called from a read-write security officer session. May be
   * used to set a new user-PIN if the user-PIN is locked.
   *
   * @param pin
   *          The new user-PIN. This parameter may be null, if the token has a protected
   *          authentication path. Refer to the PKCS#11 standard for details.
   * @exception PKCS11Exception
   *              If the session has not the right to set the PIN of if the operation fails for some
   *              other reason.
   */
  public void initPIN(char[] pin) throws PKCS11Exception {
    pkcs11.C_InitPIN(sessionHandle, pin, useUtf8);
  }

  /**
   * Set the user-PIN to a new value. Can only be called from a read-write sessions.
   *
   * @param oldPin
   *          The old (current) user-PIN.
   * @param newPin
   *          The new value for the user-PIN.
   * @exception PKCS11Exception
   *              If setting the new PIN fails.
   */
  public void setPIN(char[] oldPin, char[] newPin) throws PKCS11Exception {
    pkcs11.C_SetPIN(sessionHandle, oldPin, newPin, useUtf8);
  }

  /**
   * Closes this session.
   *
   * @exception PKCS11Exception
   *              If closing the session failed.
   */
  public void closeSession() throws PKCS11Exception {
    pkcs11.C_CloseSession(sessionHandle);
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
   * @exception PKCS11Exception
   *              If getting the information failed.
   */
  public SessionInfo getSessionInfo() throws PKCS11Exception {
    return new SessionInfo(pkcs11.C_GetSessionInfo(sessionHandle));
  }

  /**
   * terminates active session based operations.
   *
   * @exception PKCS11Exception
   *              If terminiating operations failed
   */
  public void sessionCancel() throws PKCS11Exception {
    long flags = 0L; //Add Flags?
    pkcs11.C_SessionCancel(sessionHandle, flags);
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
   * Get the current operation state. This state can be used later to restore the operation to
   * exactly this state.
   *
   * @return The current operation state as a byte array.
   * @exception PKCS11Exception
   *              If saving the state fails or is not possible.
   */
  public byte[] getOperationState() throws PKCS11Exception {
    return pkcs11.C_GetOperationState(sessionHandle);
  }

  /**
   * Sets the operation state of this session to a previously saved one. This method may need the
   * key used during the saved operation to continue, because it may not be possible to save a key
   * into the state's byte array. Refer to the PKCS#11 standard for details on this function.
   *
   * @param operationState
   *          The previously saved state as returned by getOperationState().
   * @param encryptionKeyHandle
   *          An encryption or decryption key handle, if an encryption or decryption operation was saved
   *          which should be continued, but the keys could not be saved.
   * @param authenticationKeyHandle
   *          A signing, verification of MAC key handle, if a signing, verification or MAC operation needs
   *          to be restored that could not save the key.
   * @exception PKCS11Exception
   *              If restoring the state fails.
   */
  public void setOperationState(byte[] operationState, long encryptionKeyHandle, long authenticationKeyHandle)
      throws PKCS11Exception {
    pkcs11.C_SetOperationState(sessionHandle, operationState, encryptionKeyHandle, authenticationKeyHandle);
  }

  public void setSessionHandle(long sessionHandle) {
    this.sessionHandle = sessionHandle;
  }

  /**
   * Returns whether UTF8 encoding is set.
   *
   * @return true, if UTF8 is used as character encoding for character array attributes and PINs.
   */
  public boolean isSetUtf8Encoding() {
    return useUtf8;
  }

  /**
   * Logs in the user or the security officer to the session. Notice that all sessions of a token
   * have the same login state; i.e. if you login the user to one session all other open sessions of
   * this token get user rights.
   *
   * @param userType
   *          CKU_SO for the security officer or CKU_USER to login the user.
   * @param pin
   *          The PIN. The security officer-PIN or the user-PIN depending on the userType parameter.
   * @exception PKCS11Exception
   *              If login fails.
   */
  public void login(long userType, char[] pin) throws PKCS11Exception {
    pkcs11.C_Login(sessionHandle, userType, pin, useUtf8);
  }

  /**
   * Logs in the user or the security officer to the session. Notice that all sessions of a token
   * have the same login state; i.e. if you log in the user to one session all other open sessions of
   * this token get user rights.
   *
   * @param userType
   *          CKU_SO for the security officer or CKU_USER to log in the user.
   * @param pin
   *          The PIN. The security officer-PIN or the user-PIN depending on the userType parameter.
   * @param username
   *          The username of the user.
   * @exception PKCS11Exception
   *              If login fails.
   */
  public void loginUser(long userType, char[] pin, char[] username) throws PKCS11Exception {
    pkcs11.C_LoginUser(sessionHandle, userType, pin, username, useUtf8);
  }

  /**
   * Logs out this session.
   *
   * @exception PKCS11Exception
   *              If logging out the session fails.
   */
  public void logout() throws PKCS11Exception {
    pkcs11.C_Logout(sessionHandle);
  }

  /**
   * Create a new object on the token (or in the session). The application must provide a template
   * that holds enough information to create a certain object. For instance, if the application
   * wants to create a new DES key object it creates a new instance of the AttributeVector class to
   * serve as a template. The application must set all attributes of this new object which are
   * required for the creation of such an object on the token. Then it passes this DESSecretKey
   * object to this method to create the object on the token. Example: <code>
   *   AttributeVector desKeyTemplate = new AttributeVector()
   *       .class_(CKO_SECRET_KEY).keytype(CKK_DES3);
   *   // the key type is set by the DESSecretKey's constructor, so you need not do it
   *   desKeyTemplate.value(myDesKeyValueAs8BytesLongByteArray)
   *     .token(true)
   *     .private(true);
   *     .encrypt(true);
   *     .decrypt(true);
   *   ...
   *   DESSecretKey theCreatedDESKeyObject = (DESSecretKey) userSession.createObject(desKeyTemplate);
   * </code> Refer to the PKCS#11 standard to find out what attributes must be set for certain types
   * of objects to create them on the token.
   *
   * @param template
   *          The template object that holds all values that the new object on the token should
   *          contain.
   * @return A new PKCS#11 Object that serves holds all the
   *         (readable) attributes of the object on the token. In contrast to the templateObject,
   *         this object might have certain attributes set to token-dependent default-values.
   * @exception PKCS11Exception
   *              If the creation of the new object fails. If it fails, the no new object was
   *              created on the token.
   */
  public long createObject(AttributeVector template) throws PKCS11Exception {
    return pkcs11.C_CreateObject(sessionHandle, toOutCKAttributes(template), useUtf8);
  }

  /**
   * Copy an existing object. The source object and a template object are given. Any value set in
   * the template object will override the corresponding value from the source object, when the new
   * object is created. See the PKCS#11 standard for details.
   *
   * @param sourceObjectHandle
   *          The source object of the copy operation.
   * @param template
   *          A template object whose attribute values are used for the new object; i.e. they have
   *          higher priority than the attribute values from the source object. May be null; in that
   *          case the new object is just a one-to-one copy of the sourceObject.
   * @return The new object that is created by copying the source object and setting attributes to
   *         the values given by the template.
   * @exception PKCS11Exception
   *              If copying the object fails for some reason.
   */
  public long copyObject(long sourceObjectHandle, AttributeVector template) throws PKCS11Exception {
    return pkcs11.C_CopyObject(sessionHandle, sourceObjectHandle, toOutCKAttributes(template), useUtf8);
  }

  /**
   * Gets all present attributes of the given template object an writes them to the object to update
   * on the token (or in the session). Both parameters may refer to the same Java object. This is
   * possible, because this method only needs the object handle of the objectToUpdate, and gets the
   * attributes to set from the template. This means, an application can get the object using
   * createObject of findObject, then modify attributes of this Java object and then call this
   * method passing this object as both parameters. This will update the object on the token to the
   * values as modified in the Java object.
   *
   * @param objectToUpdateHandle
   *          The attributes of this object get updated.
   * @param template
   *          This methods gets all present attributes of this template object and set this
   *          attributes at the objectToUpdate.
   * @exception PKCS11Exception
   *              If updateing the attributes fails. All or no attributes are updated.
   *
   */
  public void setAttributeValues(long objectToUpdateHandle, AttributeVector template) throws PKCS11Exception {
    pkcs11.C_SetAttributeValue(sessionHandle, objectToUpdateHandle, toOutCKAttributes(template), useUtf8);
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the object that you want to
   * destroy. This method uses only the internal object handle of the given object to identify the
   * object.
   *
   * @param objectHandle
   *          The object handle that should be destroyed.
   * @exception PKCS11Exception
   *              If the object could not be destroyed.
   */
  public void destroyObject(long objectHandle) throws PKCS11Exception {
    pkcs11.C_DestroyObject(sessionHandle, objectHandle);
  }

  /**
   * Get the size of the specified object in bytes. This size specifies how much memory the object
   * takes up on the token.
   *
   * @param objectHandle
   *          The object to get the size for.
   * @return The object's size bytes.
   * @exception PKCS11Exception
   *              If determining the size fails.
   *
   */
  public long getObjectSize(long objectHandle) throws PKCS11Exception {
    return pkcs11.C_GetObjectSize(sessionHandle, objectHandle);
  }

  /**
   * Initializes a find operations that provides means to find objects by passing a template object.
   * This method get all set attributes of the template object ans searches for all objects on the
   * token that match with these attributes.
   *
   * @param template
   *          The object that serves as a template for searching. If this object is null, the find
   *          operation will find all objects that this session can see. Notice, that only a user
   *          session will see private objects.
   * @exception PKCS11Exception
   *              If initializing the find operation fails.
   */
  public void findObjectsInit(AttributeVector template) throws PKCS11Exception {
    pkcs11.C_FindObjectsInit(sessionHandle, toOutCKAttributes(template), useUtf8);
  }

  /**
   * Finds objects that match the template object passed to findObjectsInit. The application must
   * call findObjectsInit before calling this method. With maxObjectCount the application can
   * specifay how many objects to return at once; i.e. the application can get all found objects by
   * susequent calls to this method like maxObjectCount(1) until it receives an empty array (this
   * method never returns null!).
   *
   * @param maxObjectCount
   *          Specifies how many objects to return with this call.
   * @return An array of found objects. The maximum size of this array is maxObjectCount, the
   *         minimum length is 0. Never returns null.
   * @exception PKCS11Exception
   *              A plain PKCS11Exception if something during PKCS11 FindObject went wrong, a
   *              PKCS11Exception with a nested PKCS11Exception if the Exception is raised during
   *              object parsing.
   */
  public long[] findObjects(int maxObjectCount) throws PKCS11Exception {
    return pkcs11.C_FindObjects(sessionHandle, maxObjectCount);
  }

  /**
   * Finalizes a find operation. The application must call this method to finalize a find operation
   * before attempting to start any other operation.
   *
   * @exception PKCS11Exception
   *              If finalizing the current find operation was not possible.
   */
  public void findObjectsFinal() throws PKCS11Exception {
    pkcs11.C_FindObjectsFinal(sessionHandle);
  }

  /**
   * Initializes a new encryption operation. The application must call this method before calling
   * any other encrypt* operation. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechanism to use for
   * encryption and the key for this operation. The key must have set its encryption flag. For the
   * mechanism the application may use a constant defined in the Mechanism class. Notice that the
   * key and the mechanism must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle
   *          The decryption key to use.
   * @exception PKCS11Exception
   *              If initializing this operation failed.
   */
  public void encryptInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_EncryptInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  private static byte[] copy(byte[] bytes, int off, int len) {
    return (off == 0 && len == bytes.length) ? bytes : Arrays.copyOfRange(bytes, off, off + len);
  }

  private static int copyResToBuffer(byte[] res, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkOutParams(out, outOfs, outLen);
    int resLen = res == null ? 0 : res.length;

    if (resLen > outLen) {
      throw new PKCS11Exception(CKR_BUFFER_TOO_SMALL);
    } else if (resLen > 0) {
      System.arraycopy(res, 0, out, outOfs, res.length);
    }

    return resLen;
  }

  /**
   * Encrypts the given data with the key and mechansim given to the encryptInit method. This method
   * finalizes the current encryption operation; i.e. the application need (and should) not call
   * encryptFinal() after this call. For encrypting multiple pices of data use encryptUpdate and
   * encryptFinal.
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
   * @exception PKCS11Exception
   *              If encrypting failed.
   */
  public int encrypt(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    byte[] res = pkcs11.C_Encrypt(sessionHandle, copy(in, inOfs, inLen));
    return copyResToBuffer(res, out, outOfs, outLen);
  }

  /**
   * This method can be used to encrypt multiple pieces of data; e.g. buffer-size pieces when
   * reading the data from a stream. Encrypts the given data with the key and mechansim given to the
   * encryptInit method. The application must call encryptFinal to get the final result of the
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
   * @exception PKCS11Exception
   *              If encrypting the data failed.
   */
  public int encryptUpdate(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    byte[] res = pkcs11.C_EncryptUpdate(sessionHandle, copy(in, inOfs, inLen));
    return copyResToBuffer(res, out, outOfs, outLen);
  }

  /**
   * This method finalizes an encrpytion operation and returns the final result. Use this method, if
   * you fed in the data using encryptUpdate. If you used the encrypt(byte[]) method, you need not
   * (and shall not) call this method, because encrypt(byte[]) finalizes the encryption itself.
   *
   * @param out
   *          buffer for the encrypted data
   * @param outOfs
   *          buffer offset for the encrypted data
   * @param outLen
   *          buffer size for the encrypted data
   * @return the length of the last part of the encrypted data
   * @exception PKCS11Exception
   *              If calculating the final result failed.
   */
  public int encryptFinal(byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    byte[] res = pkcs11.C_EncryptFinal(sessionHandle);
    return copyResToBuffer(res, out, outOfs, outLen);
  }

  /**
   * Initializes a new message encryption operation. The application must call this method before calling
   * any other encryptMessage* operation. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechanism to use for
   * encryption and the key for this operation. The key must have set its encryption flag. For the
   * mechanism the application may use a constant defined in the Mechanism class. Notice that the
   * key and the mechanism must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle
   *          The decryption key to use.
   * @exception PKCS11Exception
   *              If initializing this operation failed.
   *
   */
  public void messageEncryptInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_MessageEncryptInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Encrypts the given message with the key and mechanism given to the MessageEncryptInit method.
   * Contrary to the encrypt-Function, the encryptMessage-Function can be called any number of times and does
   * not finalize the encryption-operation
   *
   * @param parameter
   *         The parameter object
   * @param associatedData
   *          The associated Data for AEAS Mechanisms
   * @param plaintext
   *          The plaintext getting encrypted
   *
   * @return The ciphertext
   * @exception PKCS11Exception
   *              If encrypting failed.
   */
  public byte[] encryptMessage(Parameters parameter, byte[] associatedData, byte[] plaintext) throws PKCS11Exception {
    Object paramObject = toCkParameters(parameter);
    byte[] rv = pkcs11.C_EncryptMessage(sessionHandle, paramObject, associatedData, plaintext, useUtf8);

    if(parameter instanceof MessageParameters) {
      ((MessageParameters) parameter).setValuesFromPKCS11Object(paramObject);
    } else if(parameter instanceof CcmMessageParameters) {
      ((CcmMessageParameters) parameter).setValuesFromPKCS11Object(paramObject);
    } else if(parameter instanceof Salsa20Chacha20Poly1305MessageParameters) {
      ((Salsa20Chacha20Poly1305MessageParameters) parameter).setValuesFromPKCS11Object(paramObject);
    }

    return rv;
  }

  /**
   * Starts a multi-part message-encryption operation. Can only be called when an encryption operation has been
   * initialized before.
   *
   * @param parameter
   *            The IV or nonce
   * @param associatedData
   *            The associated Data for AEAS Mechanisms
   * @throws PKCS11Exception in case of error.
   */
  public void encryptMessageBegin(Parameters parameter, byte[] associatedData) throws PKCS11Exception {
    pkcs11.C_EncryptMessageBegin(sessionHandle, toCkParameters(parameter), associatedData, useUtf8);
  }

  /**
   * Encrypts one part of a multi-part encryption operation. The multi-part operation must have been started
   * with encryptMessageBegin before calling this function. If the isLastOperation is set, the multi-part operation
   * finishes and if present the TAG or MAC is returned in the parameters.
   *
   * @param parameter
   *            The parameter object
   * @param plaintext
   *           The associated Data for AEAS Mechanisms
   * @param isLastOperation
   *          If this is the last part of the multi-part message encryption, this should be true
   * @return The encrypted message part
   * @throws PKCS11Exception in case of error.
   */
  public byte[] encryptMessageNext(Parameters parameter, byte[] plaintext, boolean isLastOperation)
      throws PKCS11Exception {
    Object paramObject = toCkParameters(parameter);
    if(parameter instanceof MessageParameters) {
      ((MessageParameters) parameter).setValuesFromPKCS11Object(paramObject);
    }
    return pkcs11.C_EncryptMessageNext(sessionHandle, paramObject, plaintext,
              isLastOperation ? CKF_END_OF_MESSAGE : 0, useUtf8);
  }

  /**
   * Finishes a Message Encryption Operation which has previously been started with messageEncryptInit.
   *
   * @throws PKCS11Exception in case of error.
   */
  public void messageEncryptFinal() throws PKCS11Exception {
    pkcs11.C_MessageEncryptFinal(sessionHandle);
  }

  /**
   * Initializes a new decryption operation. The application must call this method before calling
   * any other decrypt* operation. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechanism to use for
   * decryption and the key for this operation. The key must have set its decryption flag. For the
   * mechanism the application may use a constant defined in the Mechanism class. Notice that the
   * key and the mechanism must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle
   *          The decryption key to use.
   * @exception PKCS11Exception
   *              If initializing this operation failed.
   *
   */
  public void decryptInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_DecryptInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Decrypts the given data with the key and mechanism given to the decryptInit method. This method
   * finalizes the current decryption operation; i.e. the application need (and should) not call
   * decryptFinal() after this call. For decrypting multiple pieces of data use decryptUpdate and
   * decryptFinal.
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
   * @exception PKCS11Exception
   *              If decrypting failed.
   */
  public int decrypt(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    byte[] res = pkcs11.C_Decrypt(sessionHandle, copy(in, inOfs, inLen));
    return copyResToBuffer(res, out, outOfs, outLen);
  }

  /**
   * This method can be used to decrypt multiple pieces of data; e.g. buffer-size pieces when
   * reading the data from a stream. Decrypts the given data with the key and mechansim given to the
   * decryptInit method. The application must call decryptFinal to get the final result of the
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
   * @exception PKCS11Exception
   *              If decrypting the data failed.
   */
  public int decryptUpdate(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    byte[] res = pkcs11.C_DecryptUpdate(sessionHandle, copy(in, inOfs, inLen));
    return copyResToBuffer(res, out, outOfs, outLen);
  }

  /**
   * This method finalizes a decryption operation and returns the final result. Use this method, if
   * you fed in the data using decryptUpdate. If you used the decrypt(byte[]) method, you need not
   * (and shall not) call this method, because decrypt(byte[]) finalizes the decryption itself.
   *
   * @param out
   *          buffer for the decrypted data
   * @param outOfs
   *          buffer offset for the decrypted data
   * @param outLen
   *          buffer size for the decrypted data
   * @return the length of this last part of decrypted data
   * @exception PKCS11Exception
   *              If calculating the final result failed.
   */
  public int decryptFinal(byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkOutParams(out, outOfs, outLen);
    byte[] res = pkcs11.C_DecryptFinal(sessionHandle);
    return copyResToBuffer(res, out, outOfs, outLen);
  }

  /**
   * Initializes a new message decryption operation. The application must call this method before calling
   * any other decryptMessage* operation. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechanism to use for
   * encryption and the key for this operation. The key must have set its encryption flag. For the
   * mechanism the application may use a constant defined in the Mechanism class. Notice that the
   * key and the mechanism must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle
   *          The decryption key to use.
   * @exception PKCS11Exception
   *              If initializing this operation failed.
   */
  public void messageDecryptInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_MessageDecryptInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Decrypts the given message with the key and mechanism given to the MessageDecryptInit method.
   * Contrary to the decrypt-Function, the decryptMessage-Function can be called any number of times and does
   * not finalize the decryption-operation
   *
   * @param parameter
   *          The parameter object
   * @param associatedData
   *          The associated Data for AEAS Mechanisms
   * @param plaintext
   *          The plaintext getting encrypted
   *
   * @return The ciphertext
   * @exception PKCS11Exception
   *              If encrypting failed.
   */
  public byte[] decryptMessage(Parameters parameter, byte[] associatedData, byte[] plaintext) throws PKCS11Exception {
    return pkcs11.C_DecryptMessage(sessionHandle, toCkParameters(parameter), associatedData, plaintext, useUtf8);
  }

  /**
   * Starts a multi-part message-decryption operation.
   * @param parameter
   *          The parameter object
   * @param associatedData
   *            The associated Data for AEAS Mechanisms
   * @throws PKCS11Exception in case of error.
   */
  public void decryptMessageBegin(Parameters parameter, byte[] associatedData) throws PKCS11Exception {
    pkcs11.C_DecryptMessageBegin(sessionHandle, toCkParameters(parameter), associatedData, useUtf8);
  }

  /**
   * Decrypts one part of a multi-part decryption operation. The multi-part operation must have been started
   * with decryptMessageBegin before calling this function. If the isLastOperation is set, the multi-part operation
   * finishes.
   *
   * @param parameter
   *          The parameter object
   * @param ciphertext
   *           The ciphertext getting decrypted
   * @param isLastOperation
   *          If this is the last part of the multi-part message encryption, this should be true
   * @return the decrypted message part
   * @throws PKCS11Exception in case of error.
   */
  public byte[] decryptMessageNext(Parameters parameter, byte[] ciphertext, boolean isLastOperation)
      throws PKCS11Exception {
    return pkcs11.C_DecryptMessageNext(sessionHandle, toCkParameters(parameter),
        ciphertext, isLastOperation ? CKF_END_OF_MESSAGE : 0, useUtf8);
  }

  /**
   * finishes multi-part message decryption operation.
   *
   * @throws PKCS11Exception in case of error.
   */
  public void messageDecryptFinal() throws PKCS11Exception {
    pkcs11.C_MessageDecryptFinal(sessionHandle);
  }

  /**
   * Initializes a new digesting operation. The application must call this method before calling any
   * other digest* operation. Before initializing a new operation, any currently pending operation
   * must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechanism to use for
   * digesting for this operation. For the mechanism the application may use a constant defined in
   * the Mechanism class.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.SHA_1.
   * @exception PKCS11Exception
   *              If initializing this operation failed.
   */
  public void digestInit(Mechanism mechanism) throws PKCS11Exception {
    pkcs11.C_DigestInit(sessionHandle, toCkMechanism(mechanism), useUtf8);
  }

  /**
   * Digests the given data with the mechanism given to the digestInit method. This method finalizes
   * the current digesting operation; i.e. the application need (and should) not call digestFinal()
   * after this call. For digesting multiple pieces of data use digestUpdate and digestFinal.
   *
   * @param in
   *          buffer containing the to-be-digested data
   * @param inOfs
   *          buffer offset of the to-be-digested data
   * @param inLen
   *          length of the to-be-digested data
   * @param out
   *          buffer for the digested data
   * @param outOfs
   *          buffer offset for the digested data
   * @param outLen
   *          buffer size for the digested data
   * @return the length of digested data for this update
   * @exception PKCS11Exception
   *              If digesting the data failed.
   */
  public int digest(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    byte[] res = pkcs11.C_Digest(sessionHandle, copy(in, inOfs, inLen));
    return copyResToBuffer(res, out, outOfs, outLen);
  }

  /**
   * This method can be used to digest multiple pieces of data; e.g. buffer-size pieces when reading
   * the data from a stream. Digests the given data with the mechansim given to the digestInit
   * method. The application must call digestFinal to get the final result of the digesting after
   * feeding in all data using this method.
   *
   * @param part
   *          buffer containing the to-be-digested data
   * @param partOfs
   *          buffer offset of the to-be-digested data
   * @param partLen
   *          length of the to-be-digested data
   * @exception PKCS11Exception
   *              If digesting the data failed.
   */
  public void digestUpdate(byte[] part, int partOfs, int partLen) throws PKCS11Exception {
    pkcs11.C_DigestUpdate(sessionHandle, part);
  }

  /**
   * This method is similar to digestUpdate and can be combined with it during one digesting
   * operation. This method digests the value of the given secret key.
   *
   * @param keyHandle
   *          The key to digest the value of.
   * @exception PKCS11Exception
   *              If digesting the key failed.
   */
  public void digestKey(long keyHandle) throws PKCS11Exception {
    pkcs11.C_DigestKey(sessionHandle, keyHandle);
  }

  /**
   * This method finalizes a digesting operation and returns the final result. Use this method, if
   * you fed in the data using digestUpdate and/or digestKey. If you used the digest(byte[]) method,
   * you need not (and shall not) call this method, because digest(byte[]) finalizes the digesting
   * itself.
   *
   * @param out
   *          buffer for the message digest
   * @param outOfs
   *          buffer offset for the message digest
   * @param outLen
   *          buffer size for the message digest
   * @return the length of message digest
   * @exception PKCS11Exception
   *              If calculating the final message digest failed.
   */
  public int digestFinal(byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkOutParams(out, outOfs, outLen);
    byte[] res = pkcs11.C_DigestFinal(sessionHandle);
    return copyResToBuffer(res, out, outOfs, outLen);
  }

  /**
   * Initializes a new signing operation. Use it for signatures and MACs. The application must call
   * this method before calling any other sign* operation. Before initializing a new operation, any
   * currently pending operation must be finalized using the appropriate *Final method (e.g.
   * digestFinal()). There are exceptions for dual-function operations. This method requires the
   * mechanism to use for signing and the key for this operation. The key must have set its sign
   * flag. For the mechanism the application may use a constant defined in the Mechanism class.
   * Notice that the key and the mechanism must be compatible; i.e. you cannot use a DES key with
   * the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param keyHandle
   *          The signing key to use.
   * @exception PKCS11Exception
   *              If initializing this operation failed.
   */
  public void signInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_SignInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Signs the given data with the key and mechansim given to the signInit method. This method
   * finalizes the current signing operation; i.e. the application need (and should) not call
   * signFinal() after this call. For signing multiple pices of data use signUpdate and signFinal.
   *
   * @param data
   *          The data to sign.
   * @return The signed data.
   * @exception PKCS11Exception
   *              If signing the data failed.
   */
  public byte[] sign(byte[] data) throws PKCS11Exception {
    return pkcs11.C_Sign(sessionHandle, data);
  }

  /**
   * This method can be used to sign multiple pieces of data; e.g. buffer-size pieces when reading
   * the data from a stream. Signs the given data with the mechansim given to the signInit method.
   * The application must call signFinal to get the final result of the signing after feeding in all
   * data using this method.
   *
   * @param in
   *          buffer containing the to-be-signed data
   * @param inOfs
   *          buffer offset of the to-be-signed data
   * @param inLen
   *          length of the to-be-signed data
   * @exception PKCS11Exception
   *              If signing the data failed.
   */
  public void signUpdate(byte[] in, int inOfs, int inLen) throws PKCS11Exception {
    checkInParams(in, inOfs, inLen);
    pkcs11.C_SignUpdate(sessionHandle, copy(in, inOfs, inLen));
  }

  /**
   * This method finalizes a signing operation and returns the final result. Use this method, if you
   * fed in the data using signUpdate. If you used the sign(byte[]) method, you need not (and shall
   * not) call this method, because sign(byte[]) finalizes the signing operation itself.
   *
   * @param expectedLen
   *          expected length of the signature value.
   * @return The final result of the signing operation; i.e. the signature
   *         value.
   * @exception PKCS11Exception
   *              If calculating the final signature value failed.
   */
  public byte[] signFinal(int expectedLen) throws PKCS11Exception {
    return pkcs11.C_SignFinal(sessionHandle);
  }

  /**
   * Initializes a new signing operation for signing with recovery. The application must call this
   * method before calling signRecover. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechanism to use for signing
   * and the key for this operation. The key must have set its sign-recover flag. For the mechanism
   * the application may use a constant defined in the Mechanism class. Notice that the key and the
   * mechanism must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param keyHandle
   *          The signing key to use.
   * @exception PKCS11Exception
   *              If initializing this operation failed.
   */
  public void signRecoverInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_SignRecoverInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Signs the given data with the key and mechanism given to the signRecoverInit method. This
   * method finalizes the current sign-recover operation; there is no equivalent method to
   * signUpdate for signing with recovery.
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
   * @exception PKCS11Exception
   *              If signing the data failed.
   */
  public int signRecover(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    byte[] res = pkcs11.C_SignRecover(sessionHandle, copy(in, inOfs, inLen));
    return copyResToBuffer(res, out, outOfs, outLen);
  }

  /**
   *
   * @param mechanism
   *          the mechanism parameter to use
   * @param keyHandle
   *          the key to sign the data with
   * @throws PKCS11Exception in case of error.
   */
  public void messageSignInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_MessageSignInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   *
   * @param parameter the mechanism parameter to use
   * @param data the data to sign
   * @throws PKCS11Exception if signing failed.
   * @return the signature
   */
  public byte[] signMessage(Parameters parameter, byte[] data) throws PKCS11Exception {
    return pkcs11.C_SignMessage(sessionHandle, toCkParameters(parameter), data, useUtf8);
  }

  /**
   * SignMessageBegin begins a multiple-part message signature operation, where the signature is an
   * appendix to the message.
   *
   * @param parameter
   *          the mechanism parameter to use
   * @throws PKCS11Exception in case of error.
   */
  public void signMessageBegin(Parameters parameter) throws PKCS11Exception{
    pkcs11.C_SignMessageBegin(sessionHandle, toCkParameters(parameter), useUtf8);
  }

  /**
   * SignMessageNext continues a multiple-part message signature operation, processing another data
   * part, or finishes a multiple-part message signature operation, returning the signature.
   *
   * @param parameter
   *          the mechanism parameter to use
   * @param data
   *          the message to sign
   * @param isLastOperation specifies if this is the last part of this messsage.
   * @return the signature
   * @throws PKCS11Exception in case of error.
   */
  public byte[] signMessageNext(Parameters parameter, byte[] data, boolean isLastOperation) throws PKCS11Exception {
    return pkcs11.C_SignMessageNext(sessionHandle, toCkParameters(parameter), data, isLastOperation, useUtf8);
  }

  /**
   * finishes a message-based signing process.
   * The message-based signing process MUST have been initialized with messageSignInit.
   *
   * @throws PKCS11Exception in case of error.
   */
  public void messageSignFinal() throws PKCS11Exception {
    pkcs11.C_MessageSignFinal(sessionHandle);
  }

  /**
   * Initializes a new verification operation. You can use it for verifying signatures and MACs. The
   * application must call this method before calling any other verify* operation. Before
   * initializing a new operation, any currently pending operation must be finalized using the
   * appropriate *Final method (e.g. digestFinal()). There are exceptions for dual-function
   * operations. This method requires the mechanism to use for verification and the key for this
   * operation. The key must have set its verify flag. For the mechanism the application may use a
   * constant defined in the Mechanism class. Notice that the key and the mechanism must be
   * compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param keyHandle
   *          The verification key to use.
   * @exception PKCS11Exception
   *              If initializing this operation failed.
   */
  public void verifyInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_VerifyInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Verifies the given signature against the given data with the key and mechansim given to the
   * verifyInit method. This method finalizes the current verification operation; i.e. the
   * application need (and should) not call verifyFinal() after this call. For verifying with
   * multiple pices of data use verifyUpdate and verifyFinal. This method throws an exception, if
   * the verification of the signature fails.
   *
   * @param data
   *          The data that was signed.
   * @param signature
   *          The signature or MAC to verify.
   * @exception PKCS11Exception
   *              If verifying the signature fails. This is also the case, if the signature is
   *              forged.
   */
  public void verify(byte[] data, byte[] signature) throws PKCS11Exception {
    pkcs11.C_Verify(sessionHandle, data, signature);
  }

  /**
   * This method can be used to verify a signature with multiple pieces of data; e.g. buffer-size
   * pieces when reading the data from a stream. To verify the signature or MAC call verifyFinal
   * after feeding in all data using this method.
   *
   * @param in
   *          buffer containing the to-be-verified data
   * @param inOfs
   *          buffer offset of the to-be-verified data
   * @param inLen
   *          length of the to-be-verified data
   * @exception PKCS11Exception
   *              If verifying (e.g. digesting) the data failed.
   */
  public void verifyUpdate(byte[] in, int inOfs, int inLen) throws PKCS11Exception {
    checkInParams(in, inOfs, inLen);
    pkcs11.C_VerifyUpdate(sessionHandle, copy(in, inOfs, inLen));
  }

  /**
   * This method finalizes a verification operation. Use this method, if you fed in the data using
   * verifyUpdate. If you used the verify(byte[]) method, you need not (and shall not) call this
   * method, because verify(byte[]) finalizes the verification operation itself. If this method
   * verified the signature successfully, it returns normally. If the verification of the signature
   * fails, e.g. if the signature was forged or the data was modified, this method throws an
   * exception.
   *
   * @param signature
   *          The signature value.
   * @exception PKCS11Exception
   *              If verifying the signature fails. This is also the case, if the signature is
   *              forged.
   */
  public void verifyFinal(byte[] signature) throws PKCS11Exception {
    pkcs11.C_VerifyFinal(sessionHandle, signature);
  }

  /**
   * Initializes a new verification operation for verification with data recovery. The application
   * must call this method before calling verifyRecover. Before initializing a new operation, any
   * currently pending operation must be finalized using the appropriate *Final method (e.g.
   * digestFinal()). This method requires the mechansim to use for verification and the key for this
   * oepration. The key must have set its verify-recover flag. For the mechanism the application may
   * use a constant defined in the Mechanism class. Notice that the key and the mechanism must be
   * compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param keyHandle
   *          The verification key to use.
   * @exception PKCS11Exception
   *              If initializing this operation failed.
   */
  public void verifyRecoverInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_VerifyRecoverInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Verifies the given data with the key and mechansim given to the verifyRecoverInit method. This
   * method finalizes the current verify-recover operation; there is no equivalent method to
   * verifyUpdate for signing with recovery.
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
   * @exception PKCS11Exception
   *              If signing the data failed.
   */
  public int verifyRecover(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    checkParams(in, inOfs, inLen, out, outOfs, outLen);
    byte[] res = pkcs11.C_VerifyRecover(sessionHandle, copy(in, inOfs, inLen));
    return copyResToBuffer(res, out, outOfs, outLen);
  }

  /**
   * Initiates a message verification operation, preparing a session for one or
   * more verification operations (where the signature is an appendix to the data) that use the same
   * verification mechanism and verification key.
   *
   * @param mechanism
   *          the mechanism to use
   * @param keyHandle
   *          the verification key to use
   * @throws PKCS11Exception in case of error.
   */
  public void messageVerifyInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_MessageVerifyInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Verifies a signature on a message in a single part operation. messageVerifyInit must previously
   * been called on the session.
   *
   * @param parameter
   *          the mechanism parameter to use
   * @param data
   *          the message to verify with the signature
   * @param signature
   *          the signature of the message
   * @throws PKCS11Exception if the message cant be verified
   */
  public void verifyMessage(Parameters parameter, byte[] data, byte[] signature) throws PKCS11Exception {
    pkcs11.C_VerifyMessage(sessionHandle, toCkParameters(parameter), data, signature, useUtf8);
  }

  /**
   * Begins a multi-part message verification operation.
   * MessageVerifyInit must previously been called on the session
   *
   * @param parameter
   *          the mechanism parameter to use
   * @throws PKCS11Exception in case of error.
   */
  public void verifyMessageBegin(Parameters parameter) throws PKCS11Exception {
    pkcs11.C_VerifyMessageBegin(sessionHandle, toCkParameters(parameter), useUtf8);
  }

  /**
   * continues a multiple-part message verification operation, processing another data
   * part, or finishes a multiple-part message verification operation, checking the signature.
   * The signature argument is set to NULL if there is more data part to follow, or set to a non-NULL value
   * (pointing to the signature to verify) if this is the last data part.
   *
   * @param parameter
   *          the mechanism parameter to use
   * @param data
   *          the data to be verified
   * @param signature
   *           NUll if there is data follow, the signature if its the last part of the signing operation
   * @throws PKCS11Exception
   *            if The Signature is invalid
   */
  public void verifyMessageNext(Parameters parameter, byte[] data, byte[] signature) throws PKCS11Exception {
    pkcs11.C_VerifyMessageNext(sessionHandle, toCkParameters(parameter), data, signature, useUtf8);
  }

  /**
   * finishes a message-based verification process.
   * The message-based verification process must have been initialized with messageVerifyInit.
   * @throws PKCS11Exception in case of error.
   */
  public void messageVerifyFinal() throws PKCS11Exception {
    pkcs11.C_MessageVerifyFinal(sessionHandle);
  }

  /**
   * Dual-function. Continues a multipart dual digest and encryption operation. This method call can
   * also be combined with calls to digestUpdate, digestKey and encryptUpdate. Call digestFinal and
   * encryptFinal to get the final results.
   *
   * @param part
   *          The piece of data to digest and encrypt.
   * @return The intermediate result of the encryption.
   * @exception PKCS11Exception
   *              If digesting or encrypting the data failed.
   */
  public byte[] digestEncryptedUpdate(byte[] part) throws PKCS11Exception {
    return pkcs11.C_DigestEncryptUpdate(sessionHandle, part);
  }

  /**
   * Dual-function. Continues a multipart dual decrypt and digest operation. This method call can
   * also be combined with calls to digestUpdate, digestKey and decryptUpdate. It is the recovered
   * plaintext that gets digested in this method call, not the given encryptedPart. Call digestFinal
   * and decryptFinal to get the final results.
   *
   * @param part
   *          The piece of data to decrypt and digest.
   * @return The intermediate result of the decryption; the decrypted data.
   * @exception PKCS11Exception
   *              If decrypting or digesting the data failed.
   */
  public byte[] decryptDigestUpdate(byte[] part) throws PKCS11Exception {
    return pkcs11.C_DecryptDigestUpdate(sessionHandle, part);
  }

  /**
   * Dual-function. Continues a multipart dual sign and encrypt operation. Calls to this method can
   * also be combined with calls to signUpdate and encryptUpdate. Call signFinal and encryptFinal to
   * get the final results.
   *
   * @param part
   *          The piece of data to sign and encrypt.
   * @return The intermediate result of the encryption; the encrypted data.
   * @exception PKCS11Exception
   *              If signing or encrypting the data failed.
   */
  public byte[] signEncryptUpdate(byte[] part) throws PKCS11Exception {
    return pkcs11.C_SignEncryptUpdate(sessionHandle, part);
  }

  /**
   * Dual-function. Continues a multipart dual decrypt and verify operation. This method call can
   * also be combined with calls to decryptUpdate and verifyUpdate. It is the recovered plaintext
   * that gets verified in this method call, not the given encryptedPart. Call decryptFinal and
   * verifyFinal to get the final results.
   *
   * @param encryptedPart
   *          The piece of data to decrypt and verify.
   * @return The intermediate result of the decryption; the decrypted data.
   * @exception PKCS11Exception
   *              If decrypting or verifying the data failed.
   */
  public byte[] decryptVerifyUpdate(byte[] encryptedPart) throws PKCS11Exception {
    return pkcs11.C_DecryptVerifyUpdate(sessionHandle, encryptedPart);
  }

  /**
   * Generate a new secret key or a set of domain parameters. It uses the set attributes of the
   * template for setting the attributes of the new key object. As mechanism the application can use
   * a constant of the Mechanism class.
   *
   * @param mechanism
   *          The mechanism to generate a key for; e.g. Mechanism.DES to generate a DES key.
   * @param template
   *          The template for the new key or domain parameters; e.g. a DESSecretKey object which
   *          has set certain attributes.
   * @return The newly generated secret key or domain parameters.
   * @exception PKCS11Exception
   *              If generating a new secret key or domain parameters failed.
   */
  public long generateKey(Mechanism mechanism, AttributeVector template) throws PKCS11Exception {
    return pkcs11.C_GenerateKey(sessionHandle, toCkMechanism(mechanism), toOutCKAttributes(template), useUtf8);
  }

  /**
   * Generate a new public key - private key key-pair and use the set attributes of the template
   * objects for setting the attributes of the new public key and private key objects. As mechanism
   * the application can use a constant of the Mechanism class.
   *
   * @param mechanism
   *          The mechanism to generate a key for; e.g. Mechanism.RSA to generate a new RSA
   *          key-pair.
   * @param publicKeyTemplate
   *          The template for the new public key part; e.g. a RSAPublicKey object which has set
   *          certain attributes (e.g. public exponent and verify).
   * @param privateKeyTemplate
   *          The template for the new private key part; e.g. a RSAPrivateKey object which has set
   *          certain attributes (e.g. sign and decrypt).
   * @return The newly generated key-pair.
   * @exception PKCS11Exception
   *              If generating a new key-pair failed.
   */
  public KeyPair generateKeyPair(Mechanism mechanism, AttributeVector publicKeyTemplate,
                                 AttributeVector privateKeyTemplate) throws PKCS11Exception {
    long[] objectHandles = pkcs11.C_GenerateKeyPair(sessionHandle, toCkMechanism(mechanism),
        toOutCKAttributes(publicKeyTemplate), toOutCKAttributes(privateKeyTemplate), useUtf8);
    return new KeyPair(objectHandles[0], objectHandles[1]);
  }

  /**
   * Wraps (encrypts) the given key with the wrapping key using the given mechanism.
   *
   * @param mechanism
   *          The mechanism to use for wrapping the key.
   * @param wrappingKeyHandle
   *          The key to use for wrapping (encrypting).
   * @param keyHandle
   *          The key to wrap (encrypt).
   * @return The wrapped key as byte array.
   * @exception PKCS11Exception
   *              If wrapping the key failed.
   */
  public byte[] wrapKey(Mechanism mechanism, long wrappingKeyHandle, long keyHandle) throws PKCS11Exception {
    return pkcs11.C_WrapKey(sessionHandle, toCkMechanism(mechanism), wrappingKeyHandle, keyHandle, useUtf8);
  }

  /**
   * Unwraps (decrypts) the given encrypted key with the unwrapping key using the given mechanism.
   * The application can also pass a template key to set certain attributes of the unwrapped key.
   * This creates a key object after unwrapping the key and returns an object representing this key.
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
   * @exception PKCS11Exception
   *              If unwrapping the key or creating a new key object failed.
   */
  public long unwrapKey(Mechanism mechanism, long unwrappingKeyHandle, byte[] wrappedKey, AttributeVector keyTemplate)
      throws PKCS11Exception {
    return pkcs11.C_UnwrapKey(sessionHandle, toCkMechanism(mechanism),
        unwrappingKeyHandle, wrappedKey, toOutCKAttributes(keyTemplate), useUtf8);
  }

  /**
   * Derives a new key from a specified base key unsing the given mechanism. After deriving a new
   * key from the base key, a new key object is created and a representation of it is returned. The
   * application can provide a template key to set certain attributes of the new key object.
   *
   * @param mechanism
   *          The mechanism to use for deriving the new key from the base key.
   * @param baseKeyHandle
   *          The key to use as base for derivation.
   * @param template
   *          The template for creating the new key object.
   * @return A key object representing the newly derived (created) key object or null, if the used
   *         mechanism uses other means to return its values; e.g. the CKM_SSL3_KEY_AND_MAC_DERIVE
   *         mechanism.
   * @exception PKCS11Exception
   *              If deriving the key or creating a new key object failed.
   */
  public long deriveKey(Mechanism mechanism, long baseKeyHandle, AttributeVector template) throws PKCS11Exception {
    return pkcs11.C_DeriveKey(sessionHandle, toCkMechanism(mechanism), baseKeyHandle,
        toOutCKAttributes(template), useUtf8);
  }

  /**
   * Mixes additional seeding material into the random number generator.
   *
   * @param seed
   *          The seed bytes to mix in.
   * @exception PKCS11Exception
   *              If mixing in the seed failed.
   */
  public void seedRandom(byte[] seed) throws PKCS11Exception {
    pkcs11.C_SeedRandom(sessionHandle, seed);
  }

  /**
   * Generates a certain number of random bytes.
   *
   * @param numberOfBytesToGenerate
   *          The number of random bytes to generate.
   * @return An array of random bytes with length numberOfBytesToGenerate.
   * @exception PKCS11Exception
   *              If generating random bytes failed.
   */
  public byte[] generateRandom(int numberOfBytesToGenerate) throws PKCS11Exception {
    byte[] randomBytesBuffer = new byte[numberOfBytesToGenerate];
    pkcs11.C_GenerateRandom(sessionHandle, randomBytesBuffer);
    return randomBytesBuffer;
  }

  /**
   * Legacy function that will normally throw an PKCS11Exception with the error-code
   * CKR_FUNCTION_NOT_PARALLEL.
   *
   * @exception PKCS11Exception
   *              Throws always an PKCS11Excption.
   */
  public void getFunctionStatus() throws PKCS11Exception {
    pkcs11.C_GetFunctionStatus(sessionHandle);
  }

  /**
   * Legacy function that will normally throw an PKCS11Exception with the error-code
   * CKR_FUNCTION_NOT_PARALLEL.
   *
   * @exception PKCS11Exception
   *              Throws always an PKCS11Excption.
   */
  public void cancelFunction() throws PKCS11Exception {
    pkcs11.C_CancelFunction(sessionHandle);
  }

  /**
   * Determines if this session is a R/W session.
   * @return true if this is a R/W session, false otherwise.
   * @throws PKCS11Exception in case of error.
   */
  public boolean isRwSession() throws PKCS11Exception {
    if (this.rwSession == null) this.rwSession = getSessionInfo().isRwSession();

    return this.rwSession.booleanValue();
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  public String toString() {
    return "Session Handle: 0x" + Long.toHexString(sessionHandle) +  "\nToken: " + token;
  }

  private CK_MECHANISM toCkMechanism(Mechanism mechanism) {
    long code = mechanism.getMechanismCode();
    if ((code & CKM_VENDOR_DEFINED) != 0) {
      if (vendorCode != null) code = vendorCode.ckmGenericToVendor(code);
    }

    CK_MECHANISM ret = new CK_MECHANISM();
    ret.mechanism = code;
    ret.pParameter = toCkParameters(mechanism.getParameters());
    return ret;
  }

  private Object toCkParameters(Parameters parameter) {
    return parameter == null ? null : parameter.getPKCS11ParamsObject();
  }

  public Integer getIntAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    Long value = getLongAttrValue(objectHandle, attributeType);
    return value == null ? null : value.intValue();
  }

  public Integer[] getIntAttrValues(long objectHandle, long... attributeTypes) throws PKCS11Exception {
    Long[] value = getLongAttrValues(objectHandle, attributeTypes);
    if (value == null) return null;

    Integer[] ret = new Integer[value.length];
    for (int i = 0; i < value.length; i++) {
      if (value[i] != null) ret[i] = value[i].intValue();
    }
    return ret;
  }

  public Long getLongAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    LongAttribute attr = new LongAttribute(attributeType);
    getAttrValue(objectHandle, attr);
    return attr.getLongValue();
  }

  public Long[] getLongAttrValues(long objectHandle, long... attributeTypes) throws PKCS11Exception {
    LongAttribute[] attrs = new LongAttribute[attributeTypes.length];
    int idx = 0;
    for (long attrType : attributeTypes) {
      attrs[idx++] = new LongAttribute(attrType);
    }

    getAttrValues(objectHandle, attrs);

    Long[] ret = new Long[attributeTypes.length];
    idx = 0;
    for (LongAttribute attr : attrs) {
      ret[idx++] = attr.getLongValue();
    }
    return ret;
  }

  public String getStringAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    CharArrayAttribute attr = new CharArrayAttribute(attributeType);
    getAttrValue(objectHandle, attr);
    return attr.getStringValue();
  }

  public String[] getCharArrayAttrValues(long objectHandle, long... attributeTypes) throws PKCS11Exception {
    CharArrayAttribute[] attrs = new CharArrayAttribute[attributeTypes.length];
    int idx = 0;
    for (long attrType : attributeTypes) {
      attrs[idx++] = new CharArrayAttribute(attrType);
    }

    getAttrValues(objectHandle, attrs);

    String[] ret = new String[attributeTypes.length];
    idx = 0;
    for (CharArrayAttribute attr : attrs) {
      ret[idx++] = attr.getStringValue();
    }
    return ret;
  }

  public BigInteger getBigIntAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    byte[] value = getByteArrayAttrValue(objectHandle, attributeType);
    return value == null ? null : new BigInteger(1, value);
  }

  public BigInteger[] getBigIntAttrValues(long objectHandle, long... attributeTypes)
      throws PKCS11Exception {
    byte[][] values = getByteArrayAttrValues(objectHandle, attributeTypes);
    BigInteger[] ret = new BigInteger[attributeTypes.length];
    for (int i = 0; i < values.length; i++) {
      ret[i] = new BigInteger(1, values[i]);
    }
    return ret;
  }

  public byte[] getByteArrayAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    ByteArrayAttribute attr = new ByteArrayAttribute(attributeType);
    getAttrValue(objectHandle, attr);
    return attr.getByteArrayValue();
  }

  public byte[][] getByteArrayAttrValues(long objectHandle, long... attributeTypes) throws PKCS11Exception {
    ByteArrayAttribute[] attrs = new ByteArrayAttribute[attributeTypes.length];
    int idx = 0;
    for (long attrType : attributeTypes) {
      attrs[idx++] = new ByteArrayAttribute(attrType);
    }

    getAttrValues(objectHandle, attrs);

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
   *          values (see {@link Attribute#ckAttribute(iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE)}).
   * @exception PKCS11Exception
   *              If getting the attributes failed.
   */
  public void getAttrValues(long objectHandle, Attribute... attributes) throws PKCS11Exception {
    Functions.requireNonNull("attributes", attributes);

    CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[attributes.length];
    for (int i = 0; i < attributeTemplateList.length; i++) {
      CK_ATTRIBUTE attribute = new CK_ATTRIBUTE();
      attribute.type = attributes[i].getType();
      attributeTemplateList[i] = attribute;
      attributes[i].stateKnown(false);
    }

    PKCS11Exception delayedEx = null;
    try {
      pkcs11.C_GetAttributeValue(sessionHandle, objectHandle, attributeTemplateList, useUtf8);
    } catch (PKCS11Exception ex) {
      delayedEx = ex;
    }

    for (int i = 0; i < attributes.length; i++) {
      Attribute attribute = attributes[i];
      CK_ATTRIBUTE template = attributeTemplateList[i];
      boolean templateNotNull = template != null;
      attribute.stateKnown(templateNotNull).present(templateNotNull).sensitive(!templateNotNull);

      if (templateNotNull) {
        if (attribute instanceof BooleanAttribute) fixBooleanAttrValue(template);

        attribute.ckAttribute(template);
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
        getAttrValue(objectHandle, attr, true);
      } catch (PKCS11Exception ex) {
        if (delayedEx == null) delayedEx = ex;
      }
    }

    if (delayedEx != null) throw delayedEx;
  }

  /**
   * This method reads the attribute specified by <code>attribute</code> from
   * the token using the given <code>session</code>.
   * The object from which to read the attribute is specified using the
   * <code>objectHandle</code>. The <code>attribute</code> will contain
   * the results.
   * If the attempt to read the attribute returns
   * <code>CKR_ATTRIBUTE_TYPE_INVALID</code>, this will be indicated by
   * setting {@link Attribute#present(boolean)} to <code>false</code>.
   * It CKR_ATTRIBUTE_SENSITIVE is returned, the attribute object is
   * marked as present
   * (by calling {@link Attribute#present(boolean)} with
   * <code>true</code>), and in addition as sensitive by calling
   * {@link Attribute#sensitive(boolean)} with <code>true</code>.
   *
   * @param objectHandle
   *          The handle of the object which contains the attribute.
   * @param attribute
   *          The object specifying the attribute type
   *          (see {@link Attribute#getType()}) and receiving the attribute
   *          value (see {@link Attribute#ckAttribute(CK_ATTRIBUTE)}).
   * @exception PKCS11Exception
   *              If getting the attribute failed.
   */
  public void getAttrValue(long objectHandle, Attribute attribute) throws PKCS11Exception {
    getAttrValue(objectHandle, attribute, true);
  }

  public void getAttrValue(long objectHandle, Attribute attribute, boolean ignoreParsableException)
      throws PKCS11Exception {
    attribute.stateKnown(false).present(false);

    try {
      CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
      attributeTemplateList[0] = new CK_ATTRIBUTE();
      attributeTemplateList[0].type = attribute.getType();
      pkcs11.C_GetAttributeValue(sessionHandle, objectHandle, attributeTemplateList, useUtf8);

      if (attribute instanceof BooleanAttribute) fixBooleanAttrValue(attributeTemplateList[0]);

      attribute.ckAttribute(attributeTemplateList[0]).stateKnown(true).present(true).sensitive(false);
      postProcessGetAttribute(attribute);
    } catch (PKCS11Exception ex) {
      long ec = ex.getErrorCode();
      if (ec == CKR_ATTRIBUTE_TYPE_INVALID) {
        // this means, that some requested attributes are missing, but
        // we can ignore this and proceed; e.g. a v2.01 module won't
        // have the object ID attribute
        attribute.stateKnown(true).present(false).getCkAttribute().pValue = null;
        if (!ignoreParsableException) throw ex;
      } else if (ec == CKR_ATTRIBUTE_SENSITIVE) {
        // this means, that some requested attributes are missing, but we can ignore this and
        // proceed; e.g. a v2.01 module won't have the object ID attribute
        attribute.stateKnown(true).present(true).sensitive(true).getCkAttribute().pValue = null;
        if (!ignoreParsableException) throw ex;
      } else if (ec == CKR_ARGUMENTS_BAD || ec == CKR_FUNCTION_FAILED || ec == CKR_FUNCTION_REJECTED) {
        attribute.stateKnown(true).present(false).sensitive(false).getCkAttribute().pValue = null;
        if (!ignoreParsableException) throw ex;
      } else {
        // there was a different error that we should propagate
        throw ex;
      }
    }
  }

  private CK_ATTRIBUTE[] toOutCKAttributes(AttributeVector attributeVector) {
    if (attributeVector == null) return null;

    CK_ATTRIBUTE[] ret = attributeVector.toCkAttributes();
    if (vendorCode != null) {
      for (CK_ATTRIBUTE ckAttr : ret) {
        if (ckAttr.type == CKA_KEY_TYPE && ckAttr.pValue != null) {
          long value = (long) ckAttr.pValue;
          if ((value & CKK_VENDOR_DEFINED) != 0L) ckAttr.pValue = vendorCode.ckkGenericToVendor(value);
        }
      }
    }
    return ret;
  }

  private void postProcessGetAttribute(Attribute attr) {
    CK_ATTRIBUTE ckAttr = attr.getCkAttribute();
    if (ckAttr.type == CKA_KEY_TYPE && ckAttr.pValue != null) {
      long value = (long) ckAttr.pValue;
      if ((value & CKK_VENDOR_DEFINED) != 0L) ckAttr.pValue = vendorCode.ckkVendorToGeneric(value);
    }
  }

  private static void fixBooleanAttrValue(CK_ATTRIBUTE attr) {
    if (attr.pValue instanceof byte[]) {
      boolean allZeros = true;
      for (byte b : (byte[]) attr.pValue) {
        if (b != 0) {
          allZeros = false;
          break;
        }
      }
      attr.pValue = !allZeros;
    }
  }

  private static void checkParams(byte[] in, int inOfs, int inLen, byte[] out, int outOfs, int outLen) {
    checkInParams(in, inOfs, inLen);
    checkOutParams(out, outOfs, outLen);
  }

  private static void checkInParams(byte[] in, int inOfs, int inLen) {
    Functions.requireNonNull("in", in);
    if (inOfs < 0 || inLen <= 0) throw new IllegalArgumentException("inOfs or inLen is invalid");
    if (in.length < inOfs + inLen) throw new IllegalArgumentException("inOfs + inLen > in.length");
  }

  private static void checkOutParams(byte[] out, int outOfs, int outLen) {
    Functions.requireNonNull("out", out);
    if (outOfs < 0 || outLen <= 0) throw new IllegalArgumentException("outOfs or outLen is invalid");
    if (out.length < outOfs + outLen) throw new IllegalArgumentException("outOfs + outLen > out.length");
  }

}
