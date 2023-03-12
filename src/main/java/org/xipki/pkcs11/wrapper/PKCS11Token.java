// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.concurrent.ConcurrentBag;
import org.xipki.pkcs11.wrapper.concurrent.ConcurrentBagEntry;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

public class PKCS11Token {

  private static final Clock clock = Clock.systemUTC();

  private int defaultBufferSize = 1024;

  private final Token token;

  private final Map<Long, MechanismInfo> mechanisms = new HashMap<>();

  private final long userType;

  private final char[] userName;

  private final char[] pin;

  private final int maxSessionCount;

  private final boolean readOnly;

  private final boolean isProtectedAuthenticationPath;

  private final long timeOutWaitNewSession = 10000; // maximal wait for 10 second

  private final AtomicLong countSessions = new AtomicLong(0);

  private final ConcurrentBag<ConcurrentBagEntry<Session>> sessions = new ConcurrentBag<>();

  public PKCS11Token(Token token, boolean readOnly, char[] pin)
      throws TokenException {
    this(token, readOnly, CKU_USER, null, pin, null);
  }

  public PKCS11Token(Token token, boolean readOnly, long userType, char[] username, char[] pin, Integer numSessions)
      throws TokenException {
    this.token = token;
    this.readOnly = readOnly;
    this.userType = userType;
    this.userName = username;
    this.pin = pin;

    TokenInfo tokenInfo = token.getTokenInfo();
    int tokenMaxSessionCount = (int) tokenInfo.getMaxSessionCount();
    this.isProtectedAuthenticationPath = tokenInfo.isProtectedAuthenticationPath();

    if (numSessions == null) {
      this.maxSessionCount = (tokenMaxSessionCount < 1) ? 32 : Math.max(1, tokenMaxSessionCount - 2);
    } else {
      this.maxSessionCount = numSessions;
    }

    StaticLogger.info("tokenMaxSessionCount={}, maxSessionCount={}", tokenMaxSessionCount, this.maxSessionCount);

    for (long mech : token.getMechanismList()) {
      MechanismInfo mechInfo = token.getMechanismInfo(mech);
      mechanisms.put(mech, mechInfo);
    }
  }

  /**
   * Sets the default buffer size. It specifies the maximal length to send to the command, if the input data
   * is contained in a {@link java.io.InputStream}.
   * @param defaultBufferSize the default buffer size.
   */
  public void setDefaultBufferSize(int defaultBufferSize) {
    if (defaultBufferSize < 256) {
      throw new IllegalArgumentException("defaultBufferSize too small, at least 256 is required: " + defaultBufferSize);
    }
    this.defaultBufferSize = defaultBufferSize;
  }

  public MechanismInfo getMechanismInfo(long mechanism) {
    return mechanisms.get(mechanism);
  }

  /**
   * Returns whether the mechanism for given purpose is supported.
   * @param mechanism The mechanism.
   * @param flagBit The purpose. Valid values are (may be extended in the future PKCS#11 version):
   *                {@link PKCS11Constants#CKF_SIGN}, {@link PKCS11Constants#CKF_VERIFY},
   *                {@link PKCS11Constants#CKF_SIGN_RECOVER}, {@link PKCS11Constants#CKF_VERIFY_RECOVER},
   *                {@link PKCS11Constants#CKF_ENCRYPT}, {@link PKCS11Constants#CKF_DECRYPT},
   *                {@link PKCS11Constants#CKF_DERIVE}, {@link PKCS11Constants#CKF_DIGEST},
   *                {@link PKCS11Constants#CKF_UNWRAP}, {@link PKCS11Constants#CKF_WRAP}.
   * @return
   */
  public boolean supportsMechanism(long mechanism, long flagBit) {
    MechanismInfo info = mechanisms.get(mechanism);
    return info == null ? false : info.hasFlagBit(flagBit);
  }

  /**
   * Set the user-PIN to a new value. Can only be called from a read-write sessions.
   *
   * @param oldPin The old (current) user-PIN.
   * @param newPin The new value for the user-PIN.
   * @throws PKCS11Exception If setting the new PIN fails.
   */
  public void setPIN(char[] oldPin, char[] newPin) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      long sessionState = session.getSessionInfo().getState();
      if (sessionState == CKS_RO_PUBLIC_SESSION) {
        return;
      }

      if (sessionState != CKS_RW_SO_FUNCTIONS) {
        throw new TokenException("Session is not logged in as CKU_SO");
      }
      session.setPIN(oldPin, newPin);
      StaticLogger.info("setPIN");
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Closes all sessions.
   */
  public void closeSessions() {
    if (token != null) {
      try {
        StaticLogger.info("close all sessions on token: {}", token.getTokenInfo());

        for (ConcurrentBagEntry<Session> session : sessions.values()) {
          session.value().closeSession();
        }
      } catch (Throwable th) {
        StaticLogger.error("error closing sessions, {}", th.getMessage());
      }
    }

    // clear the session pool
    sessions.close();
    countSessions.lazySet(0);
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
   * Login this session as CKU_SO (Security Officer).
   *
   * @throws PKCS11Exception If logging out the session fails.
   */
  public void logInSo(char[] userName, char[] pin) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      login(session, CKU_SO, userName, pin);
      StaticLogger.info("logIn CKU_SO");
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Logs out this session.
   *
   * @throws PKCS11Exception If logging out the session fails.
   */
  public void logout() throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      session.logout();
      StaticLogger.info("logout");
    } finally {
      sessions.requite(session0);
    }
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
  public long createObject(AttributeVector template) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.createObject(template);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.createObject(template);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  public long createPrivateKeyObject(AttributeVector template, PublicKey publicKey) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.createPrivateKeyObject(template, publicKey);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.createPrivateKeyObject(template, publicKey);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  public long createECPrivateKeyObject(AttributeVector template, byte[] ecPoint) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.createECPrivateKeyObject(template, ecPoint);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.createECPrivateKeyObject(template, ecPoint);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
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
  public long copyObject(long sourceObjectHandle, AttributeVector template) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.copyObject(sourceObjectHandle, template);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.copyObject(sourceObjectHandle, template);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
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
   * @throws PKCS11Exception If updating the attributes fails. All or no attributes are updated.
   */
  public void setAttributeValues(long objectToUpdateHandle, AttributeVector template) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      session.setAttributeValues(objectToUpdateHandle, template);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        session.setAttributeValues(objectToUpdateHandle, template);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the object that you want to
   * destroy. This method uses only the internal object handle of the given object to identify the
   * object.
   *
   * @param objectHandle The object handle that should be destroyed.
   * @throws PKCS11Exception If the object could not be destroyed.
   */
  public void destroyObject(long objectHandle) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      session.destroyObject(objectHandle);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        session.destroyObject(objectHandle);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Get the size of the specified object in bytes. This size specifies how much memory the object
   * takes up on the token.
   *
   * @param objectHandle The object to get the size for.
   * @return The object's size bytes.
   * @throws PKCS11Exception If determining the size fails.
   */
  public long getObjectSize(long objectHandle) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.getObjectSize(objectHandle);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.getObjectSize(objectHandle);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Finds objects that match the template.
   *
   * @param maxObjectCount Specifies how many objects to return with this call.
   * @return An array of found objects. The maximum size of this array is maxObjectCount, the
   * minimum length is 0. Never returns null.
   * @throws PKCS11Exception A plain PKCS11Exception if something during PKCS11 FindObject went wrong, a
   *                         PKCS11Exception with a nested PKCS11Exception if the Exception is raised during
   *                         object parsing.
   */
  public long[] findObjects(AttributeVector template, int maxObjectCount) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.findObjectsSingle(template, maxObjectCount);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.findObjectsSingle(template, maxObjectCount);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Encrypts the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param keyHandle The decryption key to use.
   * @param plaintext the to-be-encrypted data
   * @return the encrypted data. Never returns {@code null}.
   * @throws PKCS11Exception If encrypting failed.
   */
  public byte[] encrypt(Mechanism mechanism, long keyHandle, byte[] plaintext) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.encryptSingle(mechanism, keyHandle, plaintext);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.encryptSingle(mechanism, keyHandle, plaintext);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * This method can be used to encrypt large data, with default buffer size.
   *
   * @param out        Stream to which the cipher text is written.
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The decryption key to use.
   * @param plaintext  Input-stream of the to-be-encrypted data
   * @return length of the encrypted data.
   * @throws TokenException If encrypting the data failed.
   */
  public int encrypt(OutputStream out, Mechanism mechanism, long keyHandle, InputStream plaintext)
      throws TokenException, IOException {
    return encrypt(out, mechanism, keyHandle, plaintext, 0);
  }

  /**
   * This method can be used to encrypt large data.
   *
   * @param out        Stream to which the cipher text is written.
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The decryption key to use.
   * @param plaintext  Input-stream of the to-be-encrypted data
   * @param bufferSize size of data sent to HSM in one command. If less than 1,
   *                   default value 1024 will be used.
   * @return length of the encrypted data.
   * @throws TokenException If encrypting the data failed.
   */
  public int encrypt(OutputStream out, Mechanism mechanism, long keyHandle,
                     InputStream plaintext, int bufferSize) throws TokenException, IOException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      // encryptInit
      try {
        session.encryptInit(mechanism, keyHandle);
      } catch (PKCS11Exception e) {
        if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
          login(session);
          session.encryptInit(mechanism, keyHandle);
        } else {
          throw e;
        }
      }

      if (bufferSize < 1) {
        bufferSize = defaultBufferSize;
      }
      byte[] buffer = new byte[bufferSize];
      int readed = 0;

      int resSum = 0;
      while ((readed = plaintext.read(buffer)) != -1) {
        if (readed > 0) {
          byte[] res = session.encryptUpdate(copyOfLen(buffer, readed));
          if (res != null && res.length > 0) {
            resSum += res.length;
            out.write(res, 0, res.length);
          }
        }
      }

      byte[] res = session.encryptFinal();
      if (res != null && res.length > 0) {
        resSum += res.length;
        out.write(res, 0, res.length);
      }

      return resSum;
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Decrypts the given data with the key and mechanism.
   *
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The decryption key to use.
   * @param ciphertext the to-be-decrypted data
   * @return the decrypted data. Never returns {@code null}.
   * @throws PKCS11Exception If encrypting failed.
   */
  public byte[] decrypt(Mechanism mechanism, long keyHandle, byte[] ciphertext) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.decryptSingle(mechanism, keyHandle, ciphertext);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.encryptSingle(mechanism, keyHandle, ciphertext);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * This method can be used to decrypt large data with default buffer size.
   *
   * @param out        Stream to which the plain text is written.
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The decryption key to use.
   * @param ciphertext Input-stream of the to-be-encrypted data
   * @return length of the decrypted data.
   * @throws TokenException If decrypting the data failed.
   */
  public int decrypt(OutputStream out, Mechanism mechanism, long keyHandle, InputStream ciphertext)
      throws TokenException, IOException {
    return decrypt(out, mechanism, keyHandle, ciphertext, 0);
  }

  /**
   * This method can be used to decrypt large data.
   *
   * @param out        Stream to which the plain text is written.
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The decryption key to use.
   * @param ciphertext Input-stream of the to-be-encrypted data
   * @param bufferSize size of data sent to HSM in one command. If less than 1,
   *                   default value 1024 will be used.
   * @return length of the decrypted data.
   * @throws TokenException If decrypting the data failed.
   */
  public int decrypt(OutputStream out, Mechanism mechanism, long keyHandle,
                     InputStream ciphertext, int bufferSize) throws TokenException, IOException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      // decryptInit
      try {
        session.decryptInit(mechanism, keyHandle);
      } catch (PKCS11Exception e) {
        if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
          login(session);
          session.decryptInit(mechanism, keyHandle);
        } else {
          throw e;
        }
      }

      if (bufferSize < 1) {
        bufferSize = defaultBufferSize;
      }
      byte[] buffer = new byte[bufferSize];
      int readed;

      int resSum = 0;
      while ((readed = ciphertext.read(buffer)) != -1) {
        if (readed > 0) {
          byte[] res = session.decryptUpdate(copyOfLen(buffer, readed));
          if (res != null && res.length > 0) {
            resSum += res.length;
            out.write(res, 0, res.length);
          }
        }
      }

      byte[] res = session.decryptFinal();
      if (res != null && res.length > 0) {
        resSum += res.length;
        out.write(res, 0, res.length);
      }

      return resSum;
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Digests the given data with the mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.SHA_1.
   * @param data      the to-be-digested data
   * @return the message digest. Never returns {@code null}.
   * @throws PKCS11Exception If digesting the data failed.
   */
  public byte[] digest(Mechanism mechanism, byte[] data) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.digestSingle(mechanism, data);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.digestSingle(mechanism, data);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Digests the given key with the mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.SHA_1.
   * @param keyHandle handle of the to-be-digested key.
   * @return the message digest. Never returns {@code null}.
   * @throws PKCS11Exception If digesting the data failed.
   */
  public byte[] digestKey(Mechanism mechanism, long keyHandle) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      try {
        session.digestInit(mechanism);
      } catch (PKCS11Exception e) {
        if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
          login(session);
          session.digestInit(mechanism);
        } else {
          throw e;
        }
      }

      session.digestKey(keyHandle);
      return session.digestFinal();
    } finally {
      sessions.requite(session0);
    }
  }


  /**
   * Digests the large data, with default buffer size, with the mechanism.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.SHA_1.
   * @param data      the to-be-digested data
   * @return the message digest. Never returns {@code null}.
   * @throws PKCS11Exception If digesting the data failed.
   */
  public byte[] digest(Mechanism mechanism, InputStream data) throws TokenException, IOException {
    return digest(mechanism, data, 0);
  }

  /**
   * Digests the large data with the mechanism.
   *
   * @param mechanism  The mechanism to use; e.g. Mechanism.SHA_1.
   * @param data       the to-be-digested data
   * @param bufferSize size of data sent to HSM in one command. If less than 1,
   *                   default value 1024 will be used.
   * @return the message digest. Never returns {@code null}.
   * @throws PKCS11Exception If digesting the data failed.
   */
  public byte[] digest(Mechanism mechanism, InputStream data, int bufferSize) throws TokenException, IOException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      try {
        session.digestInit(mechanism);
      } catch (PKCS11Exception e) {
        if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
          login(session);
          session.digestInit(mechanism);
        } else {
          throw e;
        }
      }

      if (bufferSize < 1) {
        bufferSize = defaultBufferSize;
      }
      byte[] buffer = new byte[bufferSize];
      int readed;

      while ((readed = data.read(buffer)) != -1) {
        if (readed > 0) {
          session.digestUpdate(copyOfLen(buffer, readed));
        }
      }

      return session.digestFinal();
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Signs the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The signing key to use.
   * @param data      The data to sign.
   * @return The signed data. Never returns {@code null}.
   * @throws PKCS11Exception If signing the data failed.
   */
  public byte[] sign(Mechanism mechanism, long keyHandle, byte[] data) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.signSingle(mechanism, keyHandle, data);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.signSingle(mechanism, keyHandle, data);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * This method can be used to sign large data, with default buffer size.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The signing key to use.
   * @param data      Input-stream of the to-be-signed data
   * @return length of the signature.
   * @throws TokenException If signing the data failed.
   */
  public byte[] sign(Mechanism mechanism, long keyHandle, InputStream data)
      throws TokenException, IOException {
    return sign(mechanism, keyHandle, data, 0);
  }

  /**
   * This method can be used to sign large data.
   *
   * @param mechanism  The mechanism to use.
   * @param keyHandle  The signing key to use.
   * @param data       Input-stream of the to-be-signed data
   * @param bufferSize size of data sent to HSM in one command. If less than 1,
   *                   default value 1024 will be used.
   * @return length of the signature.
   * @throws TokenException If signing the data failed.
   */
  public byte[] sign(Mechanism mechanism, long keyHandle, InputStream data, int bufferSize)
      throws TokenException, IOException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      // signInit
      try {
        session.signInit(mechanism, keyHandle);
      } catch (PKCS11Exception e) {
        if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
          login(session);
          session.signInit(mechanism, keyHandle);
        } else {
          throw e;
        }
      }

      if (bufferSize < 1) {
        bufferSize = defaultBufferSize;
      }
      byte[] buffer = new byte[bufferSize];
      int readed;

      while ((readed = data.read(buffer)) != -1) {
        if (readed > 0) {
          session.signUpdate(copyOfLen(buffer, readed));
        }
      }

      return session.signFinal();
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Sign-recovers the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The signing key to use.
   * @param data      The data to sign-recovers.
   * @return The signed data. Never returns {@code null}.
   * @throws PKCS11Exception If signing the data failed.
   */
  public byte[] signRecover(Mechanism mechanism, long keyHandle, byte[] data) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.signRecoverSingle(mechanism, keyHandle, data);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.signRecoverSingle(mechanism, keyHandle, data);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Verifies the given signature against the given data with the key and mechanism.
   * This method throws an exception, if the verification of the signature fails.
   *
   * @param mechanism The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param keyHandle The verification key to use.
   * @param data      The data that was signed.
   * @param signature The signature or MAC to verify.
   * @throws PKCS11Exception If verifying the signature fails. This is also the case, if the signature is
   *                         forged.
   */
  public void verify(Mechanism mechanism, long keyHandle, byte[] data, byte[] signature) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      session.verifySingle(mechanism, keyHandle, data, signature);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        session.verifySingle(mechanism, keyHandle, data, signature);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * This method can be used to verify large data, with default buffer size.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The signing key to use.
   * @param data Input-stream of the to-be-verified data
   * @param signature the signature.
   * @return length of the signature.
   * @throws TokenException If signing the data failed.
   */
  public void verify(Mechanism mechanism, long keyHandle, InputStream data, byte[] signature)
      throws TokenException, IOException {
    verify(mechanism, keyHandle, data, 0, signature);
  }

  /**
   * This method can be used to verify large data.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The signing key to use.
   * @param data Input-stream of the to-be-verified data
   * @param bufferSize size of data sent to HSM in one command. If less than 1,
   *                   default value 1024 will be used.
   * @param signature the signature.
   * @return length of the signature.
   * @throws TokenException If signing the data failed.
   */
  public void verify(Mechanism mechanism, long keyHandle, InputStream data, int bufferSize, byte[] signature)
      throws TokenException, IOException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      // verifyInit
      try {
        session.verifyInit(mechanism, keyHandle);
      } catch (PKCS11Exception e) {
        if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
          login(session);
          session.verifyInit(mechanism, keyHandle);
        } else {
          throw e;
        }
      }

      if (bufferSize < 1) {
        bufferSize = defaultBufferSize;
      }
      byte[] buffer = new byte[bufferSize];
      int readed;

      while ((readed = data.read(buffer)) != -1) {
        if (readed > 0) {
          session.verifyUpdate(copyOfLen(buffer, readed));
        }
      }

      session.verifyFinal(signature);
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Verify-recovers the given data with the key and mechanism.
   *
   * @param mechanism The mechanism to use.
   * @param keyHandle The signing key to use.
   * @param data The data to be verify-recovered.
   * @return The verify-recovered data. Never returns {@code null}.
   * @throws PKCS11Exception If signing the data failed.
   */
  public byte[] verifyRecover(Mechanism mechanism, long keyHandle, byte[] data) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.verifyRecoverSingle(mechanism, keyHandle, data);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.verifyRecoverSingle(mechanism, keyHandle, data);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
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
  public long generateKey(Mechanism mechanism, AttributeVector template) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.generateKey(mechanism, template);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.generateKey(mechanism, template);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
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
  public PKCS11KeyPair generateKeyPair(Mechanism mechanism, KeyPairTemplate template) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.generateKeyPair(mechanism, template);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.generateKeyPair(mechanism, template);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
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
  public byte[] wrapKey(Mechanism mechanism, long wrappingKeyHandle, long keyHandle) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.wrapKey(mechanism, wrappingKeyHandle, keyHandle);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.wrapKey(mechanism, wrappingKeyHandle, keyHandle);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
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
                        AttributeVector keyTemplate) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.unwrapKey(mechanism, unwrappingKeyHandle, wrappedKey, keyTemplate);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.unwrapKey(mechanism, unwrappingKeyHandle, wrappedKey, keyTemplate);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
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
  public long deriveKey(Mechanism mechanism, long baseKeyHandle, AttributeVector template) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.deriveKey(mechanism, baseKeyHandle, template);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.deriveKey(mechanism, baseKeyHandle, template);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
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
  public byte[] generateRandom(int numberOfBytesToGenerate) throws TokenException {
    return generateRandom(numberOfBytesToGenerate, null);
  }

  /**
   * Generates a certain number of random bytes.
   *
   * @param numberOfBytesToGenerate
   *          The number of random bytes to generate.
   * @param extraSeed
   *          The seed bytes to mix in.
   * @return An array of random bytes with length numberOfBytesToGenerate.
   * @exception PKCS11Exception
   *              If generating random bytes failed.
   */
  public byte[] generateRandom(int numberOfBytesToGenerate, byte[] extraSeed) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      if (extraSeed != null && extraSeed.length > 0) {
        session.seedRandom(extraSeed);
      }
      return session.generateRandom(numberOfBytesToGenerate);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        if (extraSeed != null && extraSeed.length > 0) {
          session.seedRandom(extraSeed);
        }
        return session.generateRandom(numberOfBytesToGenerate);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return "User type: " + PKCS11Constants.codeToName(Category.CKU, userType) +
        "\nUser name: " +  (userName == null ? "null" : new String(userName)) +
        "\nMaximal session count: " +  maxSessionCount +
        "\nRead only: " +  readOnly +
        "\nToken: " + token;
  }

  public AttributeVector getAttrValues(long objectHandle, long... attributeTypes) throws TokenException {
    List<Long> typeList = new ArrayList<>(attributeTypes.length);
    for (long attrType : attributeTypes) {
      typeList.add(attrType);
    }
    return getAttrValues(objectHandle, typeList);
  }

  public AttributeVector getAttrValues(long objectHandle, List<Long> attributeTypes) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.getAttrValues(objectHandle, attributeTypes);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.getAttrValues(objectHandle, attributeTypes);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  public AttributeVector getDefaultAttrValues(long objectHandle) throws TokenException {
    ConcurrentBagEntry<Session> session0 = borrowSession();
    Session session = session0.value();
    try {
      return session.getDefaultAttrValues(objectHandle);
    } catch (PKCS11Exception e) {
      if (e.getErrorCode() == CKR_USER_NOT_LOGGED_IN) {
        login(session);
        return session.getDefaultAttrValues(objectHandle);
      } else {
        throw e;
      }
    } finally {
      sessions.requite(session0);
    }
  }

  private ConcurrentBagEntry<Session> borrowSession() throws TokenException {
    return doBorrowSession(0, clock.millis() + timeOutWaitNewSession);
  }

  private ConcurrentBagEntry<Session> doBorrowSession(int retries, long maxTimeMs) throws TokenException {
    ConcurrentBagEntry<Session> session = null;
    synchronized (sessions) {
      if (countSessions.get() < maxSessionCount) {
        try {
          session = sessions.borrow(1, TimeUnit.NANOSECONDS);
        } catch (InterruptedException ex) {
        }

        if (session == null) {
          // create new session
          sessions.add(new ConcurrentBagEntry<>(openSession()));
        }
      }
    }

    if (session == null) {
      long timeOutMs = maxTimeMs - clock.millis();
      try {
        session = sessions.borrow(Math.max(1, timeOutMs), TimeUnit.MILLISECONDS);
      } catch (InterruptedException ex) {
      }
    }

    if (session == null) {
      throw new TokenException("no idle session");
    }

    boolean requiteSession = true;

    try {
      SessionInfo sessionInfo = null;
      try {
        sessionInfo = session.value().getSessionInfo();
      } catch (PKCS11Exception ex) {
        long ckr = ex.getErrorCode();
        StaticLogger.warn("error getSessionInfo: {}", ckrCodeToName(ckr));
      }

      long deviceError = 0;
      if (sessionInfo != null) {
        deviceError = sessionInfo.getDeviceError();
        if (deviceError != 0) {
          StaticLogger.error("device has error {}", deviceError);
        }
      }

      if (deviceError != 0) {
        requiteSession = false;
        sessions.remove(session);
        countSessions.decrementAndGet();
        if (retries < maxSessionCount) {
          ConcurrentBagEntry<Session> session2 = doBorrowSession(retries + 1, maxTimeMs);
          StaticLogger.info("borrowed session after " + (retries + 1) + " tries.");
          return session2;
        } else {
          throw new TokenException("could not borrow session after " + (retries + 1) + " tries.");
        }
      }

      requiteSession = false;
      return session;
    } finally {
      if (requiteSession) {
        sessions.requite(session);
      }
    }
  } // method borrowSession

  private void login(Session session) throws TokenException {
    login(session, userType, userName, pin);
  }

  private void login(Session session, long userType, char[] userName, char[] pin) throws TokenException {
    StaticLogger.info("verify on PKCS11Module with " + (pin == null ? "NULL pin" : "pin"));

    // some driver does not accept null PIN
    char[] tmpPin = (pin == null || isProtectedAuthenticationPath) ? new char[]{} : pin;

    String userText = "user ";
    if (userName != null) {
      userText += new String(userName) + " ";
    }
    userText += "of type " + codeToName(Category.CKU, userType);

    try {
      if (userName == null) {
        session.login(userType, tmpPin);
        StaticLogger.info("login successful as " + userText);
      } else {
        session.loginUser(userType, userName, pin);
        StaticLogger.info("login successful as " + userText);
      }
    } catch (PKCS11Exception ex) {
      if (ex.getErrorCode() == CKR_USER_ALREADY_LOGGED_IN) {
        StaticLogger.info("user already logged in");
      } else {
        StaticLogger.info("login failed as " + userText);
        throw ex;
      }
    }
  } // method singleLogin

  private Session openSession() throws TokenException {
    Session session = token.openSession(!readOnly);
    countSessions.incrementAndGet();
    return session;
  } // method openSession

  private static byte[] copyOfLen(byte[] bytes, int len) {
    return bytes.length == len ? bytes : Arrays.copyOf(bytes, len);
  }
}
