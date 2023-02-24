// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import org.xipki.pkcs11.wrapper.attrs.*;
import org.xipki.pkcs11.wrapper.params.CkMessageParams;
import org.xipki.pkcs11.wrapper.params.CkParams;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.*;

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
 *       session.login(CKU_USER, userPINString.toCharArray());
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
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class Session {

  private static final int SIGN_TYPE_ECDSA = 1;

  private static final int SIGN_TYPE_SM2 = 2;

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

  private int signatureType;

  private long signOrVerifyKeyHandle;

  private final LruCache<Long, byte[]> handleEcParamsMap = new LruCache<>(1000);

  /**
   * Constructor taking the token and the session handle.
   *
   * @param token         The token this session operates with.
   * @param sessionHandle The session handle to perform the operations with.
   */
  protected Session(Token token, long sessionHandle) {
    this.token = Functions.requireNonNull("token", token);
    this.module = token.getSlot().getModule();
    this.pkcs11 = module.getPKCS11Module();
    this.sessionHandle = sessionHandle;
    this.useUtf8 = token.isUseUtf8Encoding();
  }

  /**
   * Initializes the user-PIN. Can only be called from a read-write security officer session. May be
   * used to set a new user-PIN if the user-PIN is locked.
   *
   * @param pin The new user-PIN. This parameter may be null, if the token has a protected
   *            authentication path. Refer to the PKCS#11 standard for details.
   * @throws PKCS11Exception If the session has not the right to set the PIN of if the operation fails for some
   *                         other reason.
   */
  public void initPIN(char[] pin) throws PKCS11Exception {
    pkcs11.C_InitPIN(sessionHandle, pin, useUtf8);
  }

  /**
   * Set the user-PIN to a new value. Can only be called from a read-write sessions.
   *
   * @param oldPin The old (current) user-PIN.
   * @param newPin The new value for the user-PIN.
   * @throws PKCS11Exception If setting the new PIN fails.
   */
  public void setPIN(char[] oldPin, char[] newPin) throws PKCS11Exception {
    pkcs11.C_SetPIN(sessionHandle, oldPin, newPin, useUtf8);
  }

  /**
   * Closes this session.
   *
   * @throws PKCS11Exception If closing the session failed.
   */
  public void closeSession() throws PKCS11Exception {
    this.handleEcParamsMap.evictAll();
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
   * @throws PKCS11Exception If getting the information failed.
   */
  public SessionInfo getSessionInfo() throws PKCS11Exception {
    return new SessionInfo(pkcs11.C_GetSessionInfo(sessionHandle));
  }

  /**
   * terminates active session based operations.
   *
   * @throws PKCS11Exception If terminiating operations failed
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
   * @throws PKCS11Exception If saving the state fails or is not possible.
   */
  public byte[] getOperationState() throws PKCS11Exception {
    return pkcs11.C_GetOperationState(sessionHandle);
  }

  /**
   * Sets the operation state of this session to a previously saved one. This method may need the
   * key used during the saved operation to continue, because it may not be possible to save a key
   * into the state's byte array. Refer to the PKCS#11 standard for details on this function.
   *
   * @param operationState          The previously saved state as returned by getOperationState().
   * @param encryptionKeyHandle     An encryption or decryption key handle, if an encryption or
   *                                decryption operation was saved  which should be continued, but
   *                                the keys could not be saved.
   * @param authenticationKeyHandle A signing, verification of MAC key handle, if a signing,
   *                                verification or MAC operation needs to be restored that could
   *                                not save the key.
   * @throws PKCS11Exception If restoring the state fails.
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
   * @param userType CKU_SO for the security officer or CKU_USER to login the user.
   * @param pin      The PIN. The security officer-PIN or the user-PIN depending on the userType parameter.
   * @throws PKCS11Exception If login fails.
   */
  public void login(long userType, char[] pin) throws PKCS11Exception {
    pkcs11.C_Login(sessionHandle, userType, pin, useUtf8);
  }

  /**
   * Logs in the user or the security officer to the session. Notice that all sessions of a token
   * have the same login state; i.e. if you log in the user to one session all other open sessions of
   * this token get user rights.
   *
   * @param userType CKU_SO for the security officer or CKU_USER to log in the user.
   * @param pin      The PIN. The security officer-PIN or the user-PIN depending on the userType parameter.
   * @param username The username of the user.
   * @throws PKCS11Exception If login fails.
   */
  public void loginUser(long userType, char[] pin, char[] username) throws PKCS11Exception {
    pkcs11.C_LoginUser(sessionHandle, userType, pin, username, useUtf8);
  }

  /**
   * Logs out this session.
   *
   * @throws PKCS11Exception If logging out the session fails.
   */
  public void logout() throws PKCS11Exception {
    pkcs11.C_Logout(sessionHandle);
  }

  /**
   * Create a new object on the token (or in the session). The application must provide a template
   * that holds enough information to create a certain object. For instance, if the application
   * wants to create a new DES key object it creates a new instance of the AttributesTemplate class to
   * serve as a template. The application must set all attributes of this new object which are
   * required for the creation of such an object on the token. Then it passes this DESSecretKey
   * object to this method to create the object on the token. Example: <code>
   * AttributesTemplate desKeyTemplate = AttributesTemplate.newSecretKey(CKK_DES3);
   * // the key type is set by the DESSecretKey's constructor, so you need not do it
   * desKeyTemplate.value(myDesKeyValueAs8BytesLongByteArray)
   * .token(true)
   * .private(true);
   * .encrypt(true);
   * .decrypt(true);
   * ...
   * long theCreatedDESKeyObjectHandle = userSession.createObject(desKeyTemplate);
   * </code> Refer to the PKCS#11 standard to find out what attributes must be set for certain types
   * of objects to create them on the token.
   *
   * @param template The template object that holds all values that the new object on the token should
   *                 contain.
   * @return A new PKCS#11 Object that serves holds all the
   * (readable) attributes of the object on the token. In contrast to the templateObject,
   * this object might have certain attributes set to token-dependent default-values.
   * @throws PKCS11Exception If the creation of the new object fails. If it fails, the no new object was
   *                         created on the token.
   */
  public long createObject(AttributeVector template) throws PKCS11Exception {
    return pkcs11.C_CreateObject(sessionHandle, toOutCKAttributes(template), useUtf8);
  }

  public long createPrivateKeyObject(AttributeVector template, PublicKey publicKey) throws PKCS11Exception {
    if (publicKey instanceof ECPublicKey && privateKeyWithEcPoint(template.keyType())) {
      byte[] ecParams = template.ecParams();
      Integer fieldSize = Functions.getECFieldSize(ecParams);
      ECPoint w = ((ECPublicKey) publicKey).getW();

      byte[] wx = Functions.asUnsignedByteArray(w.getAffineX());
      byte[] wy = Functions.asUnsignedByteArray(w.getAffineY());
      if (fieldSize == null) {
        fieldSize = Math.max(wx.length, wy.length);
      } else {
        if (wx.length > fieldSize || wy.length > fieldSize) {
          throw new IllegalStateException("should not happen, public key and ecParams do not match");
        }
      }

      byte[] ecPoint = new byte[1 + 2 * fieldSize];
      ecPoint[0] = 4;
      System.arraycopy(wx, 0, ecPoint, 1 + fieldSize - wx.length,  wx.length);
      System.arraycopy(wy, 0, ecPoint, ecPoint.length - wy.length, wy.length);

      template.ecPoint(ecPoint);
    }
    return createObject(template);
  }

  public long createECPrivateKeyObject(AttributeVector template, byte[] ecPoint) throws PKCS11Exception {
    if (ecPoint != null && privateKeyWithEcPoint(template.keyType())) {
      template.ecPoint(ecPoint);
    }

    return createObject(template);
  }

  private boolean privateKeyWithEcPoint(Long keyType) {
    if (keyType == null) {
      return false;
    }

    if (PKCS11Constants.CKK_EC == keyType) {
      return module.hasVendorBehaviour(PKCS11Module.BEHAVIOUR_EC_PRIVATEKEY_ECPOINT);
    } else if (PKCS11Constants.CKK_VENDOR_SM2 == keyType) {
      return module.hasVendorBehaviour(PKCS11Module.BEHAVIOUR_SM2_PRIVATEKEY_ECPOINT);
    } else {
      return false;
    }
  }

  /**
   * Copy an existing object. The source object and a template object are given. Any value set in
   * the template object will override the corresponding value from the source object, when the new
   * object is created. See the PKCS#11 standard for details.
   *
   * @param sourceObjectHandle The source object of the copy operation.
   * @param template           A template object whose attribute values are used for the new object; i.e. they have
   *                           higher priority than the attribute values from the source object. May be null; in that
   *                           case the new object is just a one-to-one copy of the sourceObject.
   * @return The new object that is created by copying the source object and setting attributes to
   * the values given by the template.
   * @throws PKCS11Exception If copying the object fails for some reason.
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
   * @param objectToUpdateHandle The attributes of this object get updated.
   * @param template             This methods gets all present attributes of this template object and set this
   *                             attributes at the objectToUpdate.
   * @throws PKCS11Exception If updateing the attributes fails. All or no attributes are updated.
   */
  public void setAttributeValues(long objectToUpdateHandle, AttributeVector template) throws PKCS11Exception {
    pkcs11.C_SetAttributeValue(sessionHandle, objectToUpdateHandle, toOutCKAttributes(template), useUtf8);
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the object that you want to
   * destroy. This method uses only the internal object handle of the given object to identify the
   * object.
   *
   * @param objectHandle The object handle that should be destroyed.
   * @throws PKCS11Exception If the object could not be destroyed.
   */
  public void destroyObject(long objectHandle) throws PKCS11Exception {
    pkcs11.C_DestroyObject(sessionHandle, objectHandle);
  }

  /**
   * Get the size of the specified object in bytes. This size specifies how much memory the object
   * takes up on the token.
   *
   * @param objectHandle The object to get the size for.
   * @return The object's size bytes.
   * @throws PKCS11Exception If determining the size fails.
   */
  public long getObjectSize(long objectHandle) throws PKCS11Exception {
    return pkcs11.C_GetObjectSize(sessionHandle, objectHandle);
  }

  /**
   * Initializes a find operations that provides means to find objects by passing a template object.
   * This method get all set attributes of the template object ans searches for all objects on the
   * token that match with these attributes.
   *
   * @param template The object that serves as a template for searching. If this object is null, the find
   *                 operation will find all objects that this session can see. Notice, that only a user
   *                 session will see private objects.
   * @throws PKCS11Exception If initializing the find operation fails.
   */
  public void findObjectsInit(AttributeVector template) throws PKCS11Exception {
    pkcs11.C_FindObjectsInit(sessionHandle, toOutCKAttributes(template, true), useUtf8);
  }

  /**
   * Finds objects that match the template object passed to findObjectsInit. The application must
   * call findObjectsInit before calling this method. With maxObjectCount the application can
   * specifay how many objects to return at once; i.e. the application can get all found objects by
   * susequent calls to this method like maxObjectCount(1) until it receives an empty array (this
   * method never returns null!).
   *
   * @param maxObjectCount Specifies how many objects to return with this call.
   * @return An array of found objects. The maximum size of this array is maxObjectCount, the
   * minimum length is 0. Never returns null.
   * @throws PKCS11Exception A plain PKCS11Exception if something during PKCS11 FindObject went wrong, a
   *                         PKCS11Exception with a nested PKCS11Exception if the Exception is raised during
   *                         object parsing.
   */
  public long[] findObjects(int maxObjectCount) throws PKCS11Exception {
    return pkcs11.C_FindObjects(sessionHandle, maxObjectCount);
  }

  /**
   * Finalizes a find operation. The application must call this method to finalize a find operation
   * before attempting to start any other operation.
   *
   * @throws PKCS11Exception If finalizing the current find operation was not possible.
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
   * @param mechanism The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle The decryption key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void encryptInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_EncryptInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Encrypts the given data with the key and mechanism given to the encryptInit method. This method
   * finalizes the current encryption operation; i.e. the application need (and should) not call
   * encryptFinal() after this call. For encrypting multiple pices of data use encryptUpdate and
   * encryptFinal.
   *
   * @param plaintext the to-be-encrypted data
   * @return the encrypted data. Never returns {@code null}.
   * @throws PKCS11Exception If encrypting failed.
   */
  public byte[] encrypt(byte[] plaintext) throws PKCS11Exception {
    return toNonNull(pkcs11.C_Encrypt(sessionHandle, plaintext));
  }

  /**
   * This method can be used to encrypt multiple pieces of data; e.g. buffer-size pieces when
   * reading the data from a stream. Encrypts the given data with the key and mechanism given to the
   * encryptInit method. The application must call encryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   *
   * @param plaintextPat Piece of the to-be-encrypted data
   * @return the encrypted data for this update. Never returns {@code null}.
   * @throws PKCS11Exception If encrypting the data failed.
   */
  public byte[] encryptUpdate(byte[] plaintextPat) throws PKCS11Exception {
    return toNonNull(pkcs11.C_EncryptUpdate(sessionHandle, plaintextPat));
  }

  /**
   * This method finalizes an encrpytion operation and returns the final result. Use this method, if
   * you fed in the data using encryptUpdate. If you used the encrypt(byte[]) method, you need not
   * (and shall not) call this method, because encrypt(byte[]) finalizes the encryption itself.
   *
   * @return the last part of the encrypted data. Never returns {@code null}.
   * @throws PKCS11Exception If calculating the final result failed.
   */
  public byte[] encryptFinal() throws PKCS11Exception {
    return toNonNull(pkcs11.C_EncryptFinal(sessionHandle));
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
   * @param mechanism The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle The decryption key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void messageEncryptInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_MessageEncryptInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Encrypts the given message with the key and mechanism given to the MessageEncryptInit method.
   * Contrary to the encrypt-Function, the encryptMessage-Function can be called any number of times and does
   * not finalize the encryption-operation
   *
   * @param params         The parameter object
   * @param associatedData The associated Data for AEAS Mechanisms
   * @param plaintext      The plaintext getting encrypted
   * @return The ciphertext. Never returns {@code null}.
   * @throws PKCS11Exception If encrypting failed.
   */
  public byte[] encryptMessage(CkParams params, byte[] associatedData, byte[] plaintext) throws PKCS11Exception {
    Object paramObject = toCkParameters(params);
    byte[] rv = pkcs11.C_EncryptMessage(sessionHandle, paramObject, associatedData, plaintext, useUtf8);

    if (params instanceof CkMessageParams) {
      ((CkMessageParams) params).setValuesFromPKCS11Object(paramObject);
    }

    return toNonNull(rv);
  }

  /**
   * Starts a multi-part message-encryption operation. Can only be called when an encryption operation has been
   * initialized before.
   *
   * @param params         The IV or nonce
   * @param associatedData The associated Data for AEAS Mechanisms
   * @throws PKCS11Exception in case of error.
   */
  public void encryptMessageBegin(CkParams params, byte[] associatedData) throws PKCS11Exception {
    pkcs11.C_EncryptMessageBegin(sessionHandle, toCkParameters(params), associatedData, useUtf8);
  }

  /**
   * Encrypts one part of a multi-part encryption operation. The multi-part operation must have been started
   * with encryptMessageBegin before calling this function. If the isLastOperation is set, the multi-part operation
   * finishes and if present the TAG or MAC is returned in the parameters.
   *
   * @param params          The parameter object
   * @param plaintext       The associated Data for AEAS Mechanisms
   * @param isLastOperation If this is the last part of the multi-part message encryption, this should be true
   * @return The encrypted message part. Never returns {@code null}.
   * @throws PKCS11Exception in case of error.
   */
  public byte[] encryptMessageNext(CkParams params, byte[] plaintext, boolean isLastOperation)
      throws PKCS11Exception {
    Object paramObject = toCkParameters(params);
    if (params instanceof CkMessageParams) {
      ((CkMessageParams) params).setValuesFromPKCS11Object(paramObject);
    }
    return toNonNull(pkcs11.C_EncryptMessageNext(sessionHandle, paramObject, plaintext,
        isLastOperation ? PKCS11Constants.CKF_END_OF_MESSAGE : 0, useUtf8));
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
   * @param mechanism The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle The decryption key to use.
   * @throws PKCS11Exception If initializing this operation failed.
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
   * @param ciphertext the to-be-decrypted data
   * @return the decrypted data. Never returns {@code null}.
   * @throws PKCS11Exception If decrypting failed.
   */
  public byte[] decrypt(byte[] ciphertext) throws PKCS11Exception {
    return toNonNull(pkcs11.C_Decrypt(sessionHandle, ciphertext));
  }

  /**
   * This method can be used to decrypt multiple pieces of data; e.g. buffer-size pieces when
   * reading the data from a stream. Decrypts the given data with the key and mechanism given to the
   * decryptInit method. The application must call decryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   *
   * @param ciphertextPart Piece of the to-be-decrypted data for this update
   * @return the decrypted data for this update. Never returns {@code null}.
   * @throws PKCS11Exception If decrypting the data failed.
   */
  public byte[] decryptUpdate(byte[] ciphertextPart) throws PKCS11Exception {
    return toNonNull(pkcs11.C_DecryptUpdate(sessionHandle, ciphertextPart));
  }

  /**
   * This method finalizes a decryption operation and returns the final result. Use this method, if
   * you fed in the data using decryptUpdate. If you used the decrypt(byte[]) method, you need not
   * (and shall not) call this method, because decrypt(byte[]) finalizes the decryption itself.
   *
   * @return the last part of decrypted data. Never returns {@code null}.
   * @throws PKCS11Exception If calculating the final result failed.
   */
  public byte[] decryptFinal() throws PKCS11Exception {
    return toNonNull(pkcs11.C_DecryptFinal(sessionHandle));
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
   * @param mechanism The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle The decryption key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void messageDecryptInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_MessageDecryptInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Decrypts the given message with the key and mechanism given to the MessageDecryptInit method.
   * Contrary to the decrypt-Function, the decryptMessage-Function can be called any number of times and does
   * not finalize the decryption-operation
   *
   * @param params         The parameter object
   * @param associatedData The associated Data for AEAS Mechanisms
   * @param plaintext      The plaintext getting encrypted
   * @return The ciphertext. Never returns {@code null}.
   * @throws PKCS11Exception If encrypting failed.
   */
  public byte[] decryptMessage(CkParams params, byte[] associatedData, byte[] plaintext) throws PKCS11Exception {
    return toNonNull(pkcs11.C_DecryptMessage(sessionHandle, toCkParameters(params),
            associatedData, plaintext, useUtf8));
  }

  /**
   * Starts a multi-part message-decryption operation.
   *
   * @param params         The parameter object
   * @param associatedData The associated Data for AEAS Mechanisms
   * @throws PKCS11Exception in case of error.
   */
  public void decryptMessageBegin(CkParams params, byte[] associatedData) throws PKCS11Exception {
    pkcs11.C_DecryptMessageBegin(sessionHandle, toCkParameters(params), associatedData, useUtf8);
  }

  /**
   * Decrypts one part of a multi-part decryption operation. The multi-part operation must have been started
   * with decryptMessageBegin before calling this function. If the isLastOperation is set, the multi-part operation
   * finishes.
   *
   * @param params          The parameter object
   * @param ciphertext      The ciphertext getting decrypted
   * @param isLastOperation If this is the last part of the multi-part message encryption, this should be true
   * @return the decrypted message part. Never returns {@code null}.
   * @throws PKCS11Exception in case of error.
   */
  public byte[] decryptMessageNext(CkParams params, byte[] ciphertext, boolean isLastOperation)
      throws PKCS11Exception {
    return toNonNull(pkcs11.C_DecryptMessageNext(sessionHandle, toCkParameters(params),
        ciphertext, isLastOperation ? PKCS11Constants.CKF_END_OF_MESSAGE : 0, useUtf8));
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
   * @param mechanism The mechanism to use; e.g. Mechanism.SHA_1.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void digestInit(Mechanism mechanism) throws PKCS11Exception {
    pkcs11.C_DigestInit(sessionHandle, toCkMechanism(mechanism), useUtf8);
  }

  /**
   * Digests the given data with the mechanism given to the digestInit method. This method finalizes
   * the current digesting operation; i.e. the application need (and should) not call digestFinal()
   * after this call. For digesting multiple pieces of data use digestUpdate and digestFinal.
   *
   * @param data the to-be-digested data
   * @return the message digest. Never returns {@code null}.
   * @throws PKCS11Exception If digesting the data failed.
   */
  public byte[] digest(byte[] data) throws PKCS11Exception {
    return toNonNull(pkcs11.C_Digest(sessionHandle, data));
  }

  /**
   * This method can be used to digest multiple pieces of data; e.g. buffer-size pieces when reading
   * the data from a stream. Digests the given data with the mechanism given to the digestInit
   * method. The application must call digestFinal to get the final result of the digesting after
   * feeding in all data using this method.
   *
   * @param dataPart Piece of the to-be-digested data
   * @throws PKCS11Exception If digesting the data failed.
   */
  public void digestUpdate(byte[] dataPart) throws PKCS11Exception {
    pkcs11.C_DigestUpdate(sessionHandle, dataPart);
  }

  /**
   * This method is similar to digestUpdate and can be combined with it during one digesting
   * operation. This method digests the value of the given secret key.
   *
   * @param keyHandle The key to digest the value of.
   * @throws PKCS11Exception If digesting the key failed.
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
   * @return the message digest. Never returns {@code null}.
   * @throws PKCS11Exception If calculating the final message digest failed.
   */
  public byte[] digestFinal() throws PKCS11Exception {
    return toNonNull(pkcs11.C_DigestFinal(sessionHandle));
  }

  /**
   * This method finalizes a digesting operation and returns the final result. Use this method, if
   * you fed in the data using digestUpdate and/or digestKey. If you used the digest(byte[]) method,
   * you need not (and shall not) call this method, because digest(byte[]) finalizes the digesting
   * itself.
   *
   * @param out    buffer for the message digest
   * @param outOfs buffer offset for the message digest
   * @param outLen buffer size for the message digest
   * @return the length of message digest
   * @throws PKCS11Exception If calculating the final message digest failed.
   */
  public int digestFinal(byte[] out, int outOfs, int outLen) throws PKCS11Exception {
    byte[] digest = pkcs11.C_DigestFinal(sessionHandle);
    if (digest.length > outLen) {
      throw new PKCS11Exception(PKCS11Constants.CKR_BUFFER_TOO_SMALL);
    }
    System.arraycopy(digest, 0, out, outOfs, digest.length);
    return digest.length;
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
   * @param mechanism The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param keyHandle The signing key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void signInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    initSignVerify(mechanism, keyHandle);
    pkcs11.C_SignInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  private void initSignVerify(Mechanism mechanism, long keyHandle) {
    this.signOrVerifyKeyHandle = keyHandle;
    long code = mechanism.getMechanismCode();
    if (code == PKCS11Constants.CKM_ECDSA             || code == PKCS11Constants.CKM_ECDSA_SHA1
        || code == PKCS11Constants.CKM_ECDSA_SHA224   || code == PKCS11Constants.CKM_ECDSA_SHA256
        || code == PKCS11Constants.CKM_ECDSA_SHA384   || code == PKCS11Constants.CKM_ECDSA_SHA512
        || code == PKCS11Constants.CKM_ECDSA_SHA3_224 || code == PKCS11Constants.CKM_ECDSA_SHA3_256
        || code == PKCS11Constants.CKM_ECDSA_SHA3_384 || code == PKCS11Constants.CKM_ECDSA_SHA3_512) {
      signatureType = SIGN_TYPE_ECDSA;
    } else if (code == PKCS11Constants.CKM_VENDOR_SM2 || code == PKCS11Constants.CKM_VENDOR_SM2_SM3) {
      signatureType = SIGN_TYPE_SM2;
    } else {
      signatureType = 0;
    }
  }

  /**
   * Signs the given data with the key and mechanism given to the signInit method. This method
   * finalizes the current signing operation; i.e. the application need (and should) not call
   * signFinal() after this call. For signing multiple pices of data use signUpdate and signFinal.
   *
   * @param data The data to sign.
   * @return The signed data. Never returns {@code null}.
   * @throws PKCS11Exception If signing the data failed.
   */
  public byte[] sign(byte[] data) throws PKCS11Exception {
    byte[] sigValue = pkcs11.C_Sign(sessionHandle, data);
    return toNonNull(fixSignOutput(sigValue));
  }

  /**
   * This method can be used to sign multiple pieces of data; e.g. buffer-size pieces when reading
   * the data from a stream. Signs the given data with the mechanism given to the signInit method.
   * The application must call signFinal to get the final result of the signing after feeding in all
   * data using this method.
   *
   * @param dataPart Piece of the to-be-signed data
   * @throws PKCS11Exception If signing the data failed.
   */
  public void signUpdate(byte[] dataPart) throws PKCS11Exception {
    pkcs11.C_SignUpdate(sessionHandle, dataPart);
  }

  /**
   * This method can be used to sign multiple pieces of data; e.g. buffer-size pieces when reading
   * the data from a stream. Signs the given data with the mechanism given to the signInit method.
   * The application must call signFinal to get the final result of the signing after feeding in all
   * data using this method.
   *
   * @param in    buffer containing the to-be-signed data
   * @param inOfs buffer offset of the to-be-signed data
   * @param inLen length of the to-be-signed data
   * @throws PKCS11Exception If signing the data failed.
   */
  public void signUpdate(byte[] in, int inOfs, int inLen) throws PKCS11Exception {
    if (inOfs == 0 && inLen == in.length) {
      pkcs11.C_SignUpdate(sessionHandle, in);
    } else {
      pkcs11.C_SignUpdate(sessionHandle, Arrays.copyOfRange(in, inOfs, inOfs + inLen));
    }
  }

  /**
   * This method finalizes a signing operation and returns the final result. Use this method, if you
   * fed in the data using signUpdate. If you used the sign(byte[]) method, you need not (and shall
   * not) call this method, because sign(byte[]) finalizes the signing operation itself.
   *
   * @return The final result of the signing operation; i.e. the signature
   * value. Never returns {@code null}.
   * @throws PKCS11Exception If calculating the final signature value failed.
   */
  public byte[] signFinal() throws PKCS11Exception {
    byte[] sigValue = pkcs11.C_SignFinal(sessionHandle);
    return toNonNull(fixSignOutput(sigValue));
  }

  private byte[] fixSignOutput(byte[] signatureValue) {
    if (signatureType == 0) {
      return signatureValue;
    }

    synchronized (module) {
      if (signatureType == SIGN_TYPE_ECDSA) {
        Boolean b = module.getEcdsaSignatureFixNeeded();
        if (b == null || b) {
          // get the ecParams
          byte[] ecParams = handleEcParamsMap.get(signOrVerifyKeyHandle);
          if (ecParams == null) {
            try {
              ecParams = getByteArrayAttrValue(signOrVerifyKeyHandle, PKCS11Constants.CKA_EC_PARAMS);
            } catch (PKCS11Exception e) {
              return signatureValue;
            }

            if (ecParams != null) {
              handleEcParamsMap.put(signOrVerifyKeyHandle, ecParams);
            }
          }

          if (ecParams != null) {
            byte[] fixedSigValue = Functions.fixECDSASignature(signatureValue, ecParams);
            boolean fixed = !Arrays.equals(fixedSigValue, signatureValue);
            if (b == null) {
              module.setEcdsaSignatureFixNeeded(fixed);
            }
            return fixedSigValue;
          }
        }
      } else if (signatureType == SIGN_TYPE_SM2) {
        Boolean b = module.getSm2SignatureFixNeeded();
        if (b == null || b) {
          byte[] fixedSigValue = Functions.fixECDSASignature(signatureValue, 32);
          boolean fixed = !Arrays.equals(fixedSigValue, signatureValue);
          if (b == null) {
            module.setSm2SignatureFixNeeded(fixed);
          }
          return fixedSigValue;
        }
      }

      return signatureValue;
    }
  }

  private byte[] fixSignatureToVerify(byte[] signatureValue) {
    if (signatureType == SIGN_TYPE_ECDSA) {
      if (module.hasVendorBehaviour(PKCS11Module.BEHAVIOUR_ECDSA_SIGNATURE_X962)) {
        return Functions.toX962DSASignature(signatureValue);
      }
    } else if (signatureType == SIGN_TYPE_SM2) {
      if (module.hasVendorBehaviour(PKCS11Module.BEHAVIOUR_SM2_SIGNATURE_X962)) {
        return Functions.toX962DSASignature(signatureValue);
      }
    }

    return signatureValue;
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
   * @param mechanism The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param keyHandle The signing key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void signRecoverInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_SignRecoverInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Signs the given data with the key and mechanism given to the signRecoverInit method. This
   * method finalizes the current sign-recover operation; there is no equivalent method to
   * signUpdate for signing with recovery.
   *
   * @param data the to-be-signed data
   * @return the signed data. Never returns {@code null}.
   * @throws PKCS11Exception If signing the data failed.
   */
  public byte[] signRecover(byte[] data) throws PKCS11Exception {
    return toNonNull(pkcs11.C_SignRecover(sessionHandle, data));
  }

  /**
   * @param mechanism the mechanism parameter to use
   * @param keyHandle the key to sign the data with
   * @throws PKCS11Exception in case of error.
   */
  public void messageSignInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    initSignVerify(mechanism, keyHandle);
    pkcs11.C_MessageSignInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * @param params    the mechanism parameter to use
   * @param data      the data to sign
   * @return the signature. Never returns {@code null}.
   * @throws PKCS11Exception if signing failed.
   */
  public byte[] signMessage(CkParams params, byte[] data) throws PKCS11Exception {
    return toNonNull(pkcs11.C_SignMessage(sessionHandle, toCkParameters(params), data, useUtf8));
  }

  /**
   * SignMessageBegin begins a multiple-part message signature operation, where the signature is an
   * appendix to the message.
   *
   * @param params    the mechanism parameter to use
   * @throws PKCS11Exception in case of error.
   */
  public void signMessageBegin(CkParams params) throws PKCS11Exception {
    pkcs11.C_SignMessageBegin(sessionHandle, toCkParameters(params), useUtf8);
  }

  /**
   * SignMessageNext continues a multiple-part message signature operation, processing another data
   * part, or finishes a multiple-part message signature operation, returning the signature.
   *
   * @param params          the mechanism parameter to use
   * @param data            the message to sign
   * @param isLastOperation specifies if this is the last part of this message.
   * @return the signature. Never returns {@code null}.
   * @throws PKCS11Exception in case of error.
   */
  public byte[] signMessageNext(CkParams params, byte[] data, boolean isLastOperation) throws PKCS11Exception {
    byte[] signature = pkcs11.C_SignMessageNext(sessionHandle, toCkParameters(params), data, isLastOperation, useUtf8);
    return toNonNull(fixSignOutput(signature));
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
   * @param mechanism The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param keyHandle The verification key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void verifyInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    initSignVerify(mechanism, keyHandle);
    pkcs11.C_VerifyInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Verifies the given signature against the given data with the key and mechanism given to the
   * verifyInit method. This method finalizes the current verification operation; i.e. the
   * application need (and should) not call verifyFinal() after this call. For verifying with
   * multiple pices of data use verifyUpdate and verifyFinal. This method throws an exception, if
   * the verification of the signature fails.
   *
   * @param data      The data that was signed.
   * @param signature The signature or MAC to verify.
   * @throws PKCS11Exception If verifying the signature fails. This is also the case, if the signature is
   *                         forged.
   */
  public void verify(byte[] data, byte[] signature) throws PKCS11Exception {
    pkcs11.C_Verify(sessionHandle, data, fixSignatureToVerify(signature));
  }

  /**
   * This method can be used to verify a signature with multiple pieces of data; e.g. buffer-size
   * pieces when reading the data from a stream. To verify the signature or MAC call verifyFinal
   * after feeding in all data using this method.
   *
   * @param dataPart Piece of the to-be-verified data.
   * @throws PKCS11Exception If verifying (e.g. digesting) the data failed.
   */
  public void verifyUpdate(byte[] dataPart) throws PKCS11Exception {
    pkcs11.C_VerifyUpdate(sessionHandle, dataPart);
  }

  /**
   * This method finalizes a verification operation. Use this method, if you fed in the data using
   * verifyUpdate. If you used the verify(byte[]) method, you need not (and shall not) call this
   * method, because verify(byte[]) finalizes the verification operation itself. If this method
   * verified the signature successfully, it returns normally. If the verification of the signature
   * fails, e.g. if the signature was forged or the data was modified, this method throws an
   * exception.
   *
   * @param signature The signature value.
   * @throws PKCS11Exception If verifying the signature fails. This is also the case, if the signature is
   *                         forged.
   */
  public void verifyFinal(byte[] signature) throws PKCS11Exception {
    pkcs11.C_VerifyFinal(sessionHandle, fixSignatureToVerify(signature));
  }

  /**
   * Initializes a new verification operation for verification with data recovery. The application
   * must call this method before calling verifyRecover. Before initializing a new operation, any
   * currently pending operation must be finalized using the appropriate *Final method (e.g.
   * digestFinal()). This method requires the mechanism to use for verification and the key for this
   * oepration. The key must have set its verify-recover flag. For the mechanism the application may
   * use a constant defined in the Mechanism class. Notice that the key and the mechanism must be
   * compatible; i.e. you cannot use a DES key with the RSA mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param keyHandle The verification key to use.
   * @throws PKCS11Exception If initializing this operation failed.
   */
  public void verifyRecoverInit(Mechanism mechanism, long keyHandle) throws PKCS11Exception {
    pkcs11.C_VerifyRecoverInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Verifies the given data with the key and mechanism given to the verifyRecoverInit method. This
   * method finalizes the current verify-recover operation; there is no equivalent method to
   * verifyUpdate for signing with recovery.
   *
   * @param data the to-be-verified data
   * @return the verified data. Never returns {@code null}.
   * @exception PKCS11Exception
   *              If signing the data failed.
   */
  public byte[] verifyRecover(byte[] data) throws PKCS11Exception {
    return toNonNull(pkcs11.C_VerifyRecover(sessionHandle, data));
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
    initSignVerify(mechanism, keyHandle);
    pkcs11.C_MessageVerifyInit(sessionHandle, toCkMechanism(mechanism), keyHandle, useUtf8);
  }

  /**
   * Verifies a signature on a message in a single part operation. messageVerifyInit must previously
   * been called on the session.
   *
   * @param params
   *          the mechanism parameter to use
   * @param data
   *          the message to verify with the signature
   * @param signature
   *          the signature of the message
   * @throws PKCS11Exception if the message cant be verified
   */
  public void verifyMessage(CkParams params, byte[] data, byte[] signature) throws PKCS11Exception {
    pkcs11.C_VerifyMessage(sessionHandle, toCkParameters(params), data, fixSignatureToVerify(signature), useUtf8);
  }

  /**
   * Begins a multi-part message verification operation.
   * MessageVerifyInit must previously been called on the session
   *
   * @param params
   *          the mechanism parameter to use
   * @throws PKCS11Exception in case of error.
   */
  public void verifyMessageBegin(CkParams params) throws PKCS11Exception {
    pkcs11.C_VerifyMessageBegin(sessionHandle, toCkParameters(params), useUtf8);
  }

  /**
   * continues a multiple-part message verification operation, processing another data
   * part, or finishes a multiple-part message verification operation, checking the signature.
   * The signature argument is set to NULL if there is more data part to follow, or set to a non-NULL value
   * (pointing to the signature to verify) if this is the last data part.
   *
   * @param params
   *          the mechanism parameter to use
   * @param data
   *          the data to be verified
   * @param signature
   *           NUll if there is data follow, the signature if its the last part of the signing operation
   * @throws PKCS11Exception
   *            if The Signature is invalid
   */
  public void verifyMessageNext(CkParams params, byte[] data, byte[] signature) throws PKCS11Exception {
    pkcs11.C_VerifyMessageNext(sessionHandle, toCkParameters(params), data, fixSignatureToVerify(signature), useUtf8);
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
   * @return The intermediate result of the encryption. Never returns {@code null}.
   * @exception PKCS11Exception
   *              If digesting or encrypting the data failed.
   */
  public byte[] digestEncryptedUpdate(byte[] part) throws PKCS11Exception {
    return toNonNull(pkcs11.C_DigestEncryptUpdate(sessionHandle, part));
  }

  /**
   * Dual-function. Continues a multipart dual decrypt and digest operation. This method call can
   * also be combined with calls to digestUpdate, digestKey and decryptUpdate. It is the recovered
   * plaintext that gets digested in this method call, not the given encryptedPart. Call digestFinal
   * and decryptFinal to get the final results.
   *
   * @param part
   *          The piece of data to decrypt and digest.
   * @return The intermediate result of the decryption; the decrypted data. Never returns {@code null}.
   * @exception PKCS11Exception
   *              If decrypting or digesting the data failed.
   */
  public byte[] decryptDigestUpdate(byte[] part) throws PKCS11Exception {
    return toNonNull(pkcs11.C_DecryptDigestUpdate(sessionHandle, part));
  }

  /**
   * Dual-function. Continues a multipart dual sign and encrypt operation. Calls to this method can
   * also be combined with calls to signUpdate and encryptUpdate. Call signFinal and encryptFinal to
   * get the final results.
   *
   * @param part
   *          The piece of data to sign and encrypt.
   * @return The intermediate result of the encryption; the encrypted data. Never returns {@code null}.
   * @exception PKCS11Exception
   *              If signing or encrypting the data failed.
   */
  public byte[] signEncryptUpdate(byte[] part) throws PKCS11Exception {
    return toNonNull(pkcs11.C_SignEncryptUpdate(sessionHandle, part));
  }

  /**
   * Dual-function. Continues a multipart dual decrypt and verify operation. This method call can
   * also be combined with calls to decryptUpdate and verifyUpdate. It is the recovered plaintext
   * that gets verified in this method call, not the given encryptedPart. Call decryptFinal and
   * verifyFinal to get the final results.
   *
   * @param encryptedPart
   *          The piece of data to decrypt and verify.
   * @return The intermediate result of the decryption; the decrypted data. Never returns {@code null}.
   * @exception PKCS11Exception
   *              If decrypting or verifying the data failed.
   */
  public byte[] decryptVerifyUpdate(byte[] encryptedPart) throws PKCS11Exception {
    return toNonNull(pkcs11.C_DecryptVerifyUpdate(sessionHandle, encryptedPart));
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
   * @param template
   *          The template for the new keypair.
   * @return The newly generated key-pair.
   * @exception PKCS11Exception
   *              If generating a new key-pair failed.
   */
  public PKCS11KeyPair generateKeyPair(Mechanism mechanism, KeyPairTemplate template) throws PKCS11Exception {
    template.id();
    long[] objectHandles = pkcs11.C_GenerateKeyPair(sessionHandle, toCkMechanism(mechanism),
        toOutCKAttributes(template.publicKey()), toOutCKAttributes(template.privateKey()), useUtf8);
    return new PKCS11KeyPair(objectHandles[0], objectHandles[1]);
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
   * @return The wrapped key as byte array. Never returns {@code null}.
   * @exception PKCS11Exception
   *              If wrapping the key failed.
   */
  public byte[] wrapKey(Mechanism mechanism, long wrappingKeyHandle, long keyHandle) throws PKCS11Exception {
    return toNonNull(pkcs11.C_WrapKey(sessionHandle, toCkMechanism(mechanism), wrappingKeyHandle, keyHandle, useUtf8));
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
  public long unwrapKey(Mechanism mechanism, long unwrappingKeyHandle, byte[] wrappedKey,
                        AttributeVector keyTemplate) throws PKCS11Exception {
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
    if (this.rwSession == null) {
      this.rwSession = getSessionInfo().isRwSession();
    }

    return this.rwSession;
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
    CK_MECHANISM ckMechanism = mechanism.toCkMechanism();
    long code = ckMechanism.mechanism;
    if ((code & PKCS11Constants.CKM_VENDOR_DEFINED) != 0) {
      ckMechanism.mechanism = module.ckmGenericToVendor(code);
    }
    return ckMechanism;
  }

  private Object toCkParameters(CkParams params) {
    return params == null ? null : params.getParams();
  }

  public Integer getIntAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    Long value = getLongAttrValue(objectHandle, attributeType);
    return value == null ? null : value.intValue();
  }

  public Long getLongAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    LongAttribute attr = new LongAttribute(attributeType);
    doGetAttrValue(objectHandle, attr);
    return attr.getValue();
  }

  public String getStringAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    CharArrayAttribute attr = new CharArrayAttribute(attributeType);
    doGetAttrValue(objectHandle, attr);
    return attr.getValue();
  }

  public BigInteger getBigIntAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    byte[] value = getByteArrayAttrValue(objectHandle, attributeType);
    return value == null ? null : new BigInteger(1, value);
  }

  public byte[] getByteArrayAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    ByteArrayAttribute attr = new ByteArrayAttribute(attributeType);
    doGetAttrValue(objectHandle, attr);
    return attr.getValue();
  }

  public Boolean getBooleanAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    BooleanAttribute attr = new BooleanAttribute(attributeType);
    doGetAttrValue(objectHandle, attr);
    return attr.getValue();
  }

  public String getCkaLabel(long objectHandle) throws PKCS11Exception {
    return getStringAttrValue(objectHandle, PKCS11Constants.CKA_LABEL);
  }

  public byte[] getCkaId(long objectHandle) throws PKCS11Exception {
    return getByteArrayAttrValue(objectHandle, PKCS11Constants.CKA_ID);
  }

  public Long getCkaClass(long objectHandle) throws PKCS11Exception {
    return getLongAttrValue(objectHandle, PKCS11Constants.CKA_CLASS);
  }

  public Long getCkaKeyType(long objectHandle) throws PKCS11Exception {
    return getLongAttrValue(objectHandle, PKCS11Constants.CKA_KEY_TYPE);
  }

  public Long getCkaCertificateType(long objectHandle) throws PKCS11Exception {
    return getLongAttrValue(objectHandle, PKCS11Constants.CKA_CERTIFICATE_TYPE);
  }

  public Object getAttrValue(long objectHandle, long attributeType) throws PKCS11Exception {
    Attribute attr = Attribute.getInstance(attributeType);
    doGetAttrValue(objectHandle, attr);
    return attr.getValue();
  }

  public AttributeVector getAttrValues(long objectHandle, long... attributeTypes) throws PKCS11Exception {
    List<Long> typeList = new ArrayList<>(attributeTypes.length);
    for (long attrType : attributeTypes) {
      typeList.add(attrType);
    }

    if (typeList.contains(PKCS11Constants.CKA_EC_POINT) && !typeList.contains(PKCS11Constants.CKA_EC_PARAMS)) {
      synchronized (module) {
        Boolean b = module.getEcPointFixNeeded();
        if (b == null || b) {
          typeList.add(PKCS11Constants.CKA_EC_PARAMS);
        }
      }
    }

    Attribute[] attrs = new Attribute[typeList.size()];
    int index = 0;

    // we need to fix attributes EC_PARAMS and EC_POINT. Where EC_POINT needs EC_PARAMS,
    // and EC_PARAMS needs KEY_TYPE.
    long[] firstTypes = {PKCS11Constants.CKA_CLASS, PKCS11Constants.CKA_KEY_TYPE,
                          PKCS11Constants.CKA_EC_PARAMS, PKCS11Constants.CKA_EC_POINT};

    for (long type : firstTypes) {
      if (typeList.remove(type)) {
        attrs[index++] =  Attribute.getInstance(type);
      }
    }

    for (long type : typeList) {
      attrs[index++] =  Attribute.getInstance(type);
    }

    doGetAttrValues(objectHandle, attrs);
    return new AttributeVector(attrs);
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
   *          values (see {@link Attribute#ckAttribute(CK_ATTRIBUTE)}).
   * @exception PKCS11Exception
   *              If getting the attributes failed.
   */
  private void doGetAttrValues(long objectHandle, Attribute... attributes) throws PKCS11Exception {
    Functions.requireNonNull("attributes", attributes);

    if (attributes.length == 1) {
      doGetAttrValue(objectHandle, attributes[0]);
      return;
    }

    CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[attributes.length];
    for (int i = 0; i < attributes.length; i++) {
      attributeTemplateList[i] = new CK_ATTRIBUTE();
      attributeTemplateList[i].type = attributes[i].getType();
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
      if (template != null) {
        attribute.present(true).sensitive(false).ckAttribute(template);
      }
    }

    if (delayedEx != null) {
      // do all failed separately again.
      delayedEx = null;
      for (Attribute attr : attributes) {
        if (attr.getCkAttribute() == null || attr.getCkAttribute().pValue == null) {
          try {
            doGetAttrValue0(objectHandle, attr, false);
          } catch (PKCS11Exception ex) {
            if (delayedEx == null) {
              delayedEx = ex;
            }
          }
        }
      }
    }

    for (Attribute attr : attributes) {
      postProcessGetAttribute(attr, objectHandle, attributes);
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
  private void doGetAttrValue(long objectHandle, Attribute attribute)
      throws PKCS11Exception {
    if (attribute.getType() == PKCS11Constants.CKA_EC_POINT) {
      Boolean b = module.getEcPointFixNeeded();
      if ((b == null || b)) {
        doGetAttrValues(objectHandle, new ByteArrayAttribute(PKCS11Constants.CKA_EC_PARAMS), attribute);
        return;
      }
    }

    doGetAttrValue0(objectHandle, attribute, true);
  }

  private void doGetAttrValue0(long objectHandle, Attribute attribute, boolean postProcess)
      throws PKCS11Exception {
    attribute.present(false);

    try {
      CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
      attributeTemplateList[0] = new CK_ATTRIBUTE();
      attributeTemplateList[0].type = attribute.getType();
      // attributeTemplateList[0].pValue;
      pkcs11.C_GetAttributeValue(sessionHandle, objectHandle, attributeTemplateList, useUtf8);

      attribute.ckAttribute(attributeTemplateList[0]).present(true).sensitive(false);
    } catch (PKCS11Exception ex) {
      long ec = ex.getErrorCode();
      if (ec == PKCS11Constants.CKR_ATTRIBUTE_TYPE_INVALID) {
        if (attribute.getType() == PKCS11Constants.CKA_EC_PARAMS) {
          // this means, that some requested attributes are missing, but
          // we can ignore this and proceed; e.g. a v2.01 module won't
          // have the object ID attribute
          attribute.present(false).getCkAttribute().pValue = null;
        }
      } else if (ec == PKCS11Constants.CKR_ATTRIBUTE_SENSITIVE) {
        // this means, that some requested attributes are missing, but
        // we can ignore this and proceed; e.g. a v2.01 module won't
        // have the object ID attribute
        attribute.getCkAttribute().pValue = null;
        attribute.present(true).sensitive(true).getCkAttribute().pValue = null;
      } else if (ec == PKCS11Constants.CKR_ARGUMENTS_BAD || ec == PKCS11Constants.CKR_FUNCTION_FAILED
          || ec == PKCS11Constants.CKR_FUNCTION_REJECTED) {
        attribute.present(false).sensitive(false).getCkAttribute().pValue = null;
      } else {
        // there was a different error that we should propagate
        throw ex;
      }
    }

    if (postProcess) {
      postProcessGetAttribute(attribute, objectHandle);
    }
  }

  private CK_ATTRIBUTE[] toOutCKAttributes(AttributeVector template) {
    return toOutCKAttributes(template, false);
  }

  private CK_ATTRIBUTE[] toOutCKAttributes(AttributeVector template, boolean withoutNullValueAttr) {
    if (template == null) {
      return null;
    }

    CK_ATTRIBUTE[] ckAttrs = template.toCkAttributes();
    List<CK_ATTRIBUTE> nonNullCkAttrs = null;
    if (withoutNullValueAttr) {
      nonNullCkAttrs = new ArrayList<>(ckAttrs.length);
    }

    for (CK_ATTRIBUTE ckAttr : ckAttrs) {
      if (ckAttr.pValue == null) {
        continue;
      } else {
        if (withoutNullValueAttr) {
          nonNullCkAttrs.add(ckAttr);
        }
      }

      if (ckAttr.type == PKCS11Constants.CKA_KEY_TYPE) {
        long value = (long) ckAttr.pValue;
        if ((value & PKCS11Constants.CKK_VENDOR_DEFINED) != 0L) {
          ckAttr.pValue = module.ckkGenericToVendor(value);
        }
      } else if (ckAttr.type == PKCS11Constants.CKA_EC_POINT) {
        ckAttr.pValue = Functions.toOctetString((byte[]) ckAttr.pValue);
      }
    }

    return nonNullCkAttrs != null && nonNullCkAttrs.size() != ckAttrs.length
        ? nonNullCkAttrs.toArray(new CK_ATTRIBUTE[0]) : ckAttrs;
  }

  private void postProcessGetAttribute(Attribute attr, long objectHandle, Attribute... otherAttrs) {
    long type = attr.getType();
    CK_ATTRIBUTE ckAttr = attr.getCkAttribute();

    if (type == PKCS11Constants.CKA_EC_PARAMS) {
      if (ckAttr.pValue == null) {
        // Some HSMs do not return EC_PARAMS
        Long keyType = null;
        if (otherAttrs != null) {
          for (Attribute otherAttr : otherAttrs) {
            if (otherAttr.type() == PKCS11Constants.CKA_KEY_TYPE) {
              keyType = ((LongAttribute) otherAttr).getValue();
            }
          }
        }

        if (keyType == null) {
          try {
            keyType = getCkaKeyType(objectHandle);
          } catch (PKCS11Exception e2) {
          }
        }

        if (keyType != null && keyType == PKCS11Constants.CKK_VENDOR_SM2) {
          attr.present(false).getCkAttribute().pValue = Functions.decodeHex("06082a811ccf5501822d");
        }
      } else {
        byte[] ecParams = (byte[]) ckAttr.pValue;
        if (ecParams[0] != 0x06) { // 06: OBJECT IDENTIFIER
          ckAttr.pValue = Functions.fixECParams((byte[]) ckAttr.pValue);
        }
      }

      return;
    }

    if (ckAttr == null || ckAttr.pValue == null) {
      return;
    }

    if (type == PKCS11Constants.CKA_KEY_TYPE) {
      long value = (long) ckAttr.pValue;
      if ((value & PKCS11Constants.CKK_VENDOR_DEFINED) != 0L && !PKCS11Constants.isUnavailableInformation(value)) {
        ckAttr.pValue = module.ckkVendorToGeneric(value);
      }
    } else if (type == PKCS11Constants.CKA_KEY_GEN_MECHANISM) {
      long value = (long) ckAttr.pValue;
      if ((value & PKCS11Constants.CKM_VENDOR_DEFINED) != 0L && !PKCS11Constants.isUnavailableInformation(value)) {
        ckAttr.pValue = module.ckmVendorToGeneric(value);
      }
    } else if (type == PKCS11Constants.CKA_ALLOWED_MECHANISMS) {
      long[] mechs = ((MechanismArrayAttribute) attr).getValue();
      for (long mech : mechs) {
        if ((mech & PKCS11Constants.CKM_VENDOR_DEFINED) != 0L) {
          ckAttr.pValue = module.ckmVendorToGeneric(mech);
        }
      }
    } else if (type == PKCS11Constants.CKA_EC_POINT) {
      Boolean b = module.getEcPointFixNeeded();
      byte[] pValue = (byte[]) ckAttr.pValue;

      if (b == null || b) {
        byte[] ecParams = null;
        if (otherAttrs != null) {
          for (Attribute otherAttr : otherAttrs) {
            if (otherAttr.getType() == PKCS11Constants.CKA_EC_PARAMS) {
              ecParams = ((ByteArrayAttribute) otherAttr).getValue();
              break;
            }
          }
        }

        byte[] fixedCoreEcPoint = Functions.getCoreECPoint(pValue, ecParams);
        if (b == null) {
          byte[] coreEcPoint = Functions.getCoreECPoint(pValue);
          module.setEcPointFixNeeded(!Arrays.equals(coreEcPoint, fixedCoreEcPoint));
        }
        ckAttr.pValue = fixedCoreEcPoint;
      } else {
        ckAttr.pValue = Functions.getCoreECPoint(pValue);
      }
    } else if (attr instanceof BooleanAttribute) {
      if (ckAttr.pValue instanceof byte[]) {
        byte[] value = (byte[]) ckAttr.pValue;
        boolean allZeros = true;
        for (byte b : value) {
          if (b != 0) {
            allZeros = false;
            break;
          }
        }
        ckAttr.pValue = !allZeros;
      }
    }
  }

  private static byte[] toNonNull(byte[] bytes) {
    return bytes == null ? new byte[0] : bytes;
  }

  private static class LruCache<K, V> {

    private final LinkedHashMap<K, V> map;

    /** Size of this cache in units. Not necessarily the number of elements. */
    private int size;

    private final int maxSize;

    public LruCache(int maxSize) {
      if (maxSize < 0) {
        throw new IllegalArgumentException("maxSize is not positive: " + maxSize);
      }
      this.maxSize = maxSize;
      this.map = new LinkedHashMap<>(0, 0.75f, true);
    }

    public final V get(K key) {
      if (key == null) {
        throw new NullPointerException("key == null");
      }

      V mapValue;
      synchronized (this) {
        mapValue = map.get(key);
        if (mapValue != null) {
          return mapValue;
        }
      }

      return null;
    }

    public final V put(K key, V value) {
      if (key == null || value == null) {
        throw new NullPointerException("key == null || value == null");
      }

      V previous;
      synchronized (this) {
        size++;
        previous = map.put(key, value);
        if (previous != null) {
          size--;
        }
      }

      trimToSize(maxSize);
      return previous;
    }

    /**
     * Remove the eldest entries until the total of remaining entries is at or
     * below the requested size.
     *
     * @param maxSize the maximum size of the cache before returning. Could be -1
     *            to evict even 0-sized elements.
     */
    public void trimToSize(int maxSize) {
      while (true) {
        K key;
        synchronized (this) {
          if (size < 0 || (map.isEmpty() && size != 0)) {
            throw new IllegalStateException(getClass().getName()
                + ".sizeOf() is reporting inconsistent results!");
          }

          if (size <= maxSize || map.isEmpty()) {
            break;
          }

          Map.Entry<K, V> toEvict = map.entrySet().iterator().next();
          key = toEvict.getKey();
          map.remove(key);
          size--;
        }
      }
    }

    public final void evictAll() {
      trimToSize(-1); // -1 will evict 0-sized elements
    }

  } // class LruCache

}
