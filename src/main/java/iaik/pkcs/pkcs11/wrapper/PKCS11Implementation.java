// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

import java.io.IOException;

/**
 * This is the default implementation of the PKCS11 interface. It connects to the
 * <code>pkcs11wrapper.dll</code> (or <code>libpkcs11wrapper.so</code>), which is the native part of
 * this library. This file either has to be located in the system path or the wrapper's jar file or
 * the location has to be specified as parameter. If the native library included in the jar file is
 * used, it is copied to the temporary-file directory and loaded from there. The strange and awkward
 * looking initialization was chosen to avoid calling <code>System.loadLibrary(String)</code> from a
 * static initialization block, because this would complicate the use in applets.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class PKCS11Implementation implements PKCS11 {

  /**
   * The PKCS#11 module to connect to. This is the PKCS#11 driver of the token; e.g. pk2priv.dll.
   */
  private final String pkcs11ModulePath;

  /**
   * This method does the initialization of the native library. It is called exactly once for this
   * class.
   *
   */
  public static synchronized native void initializeLibrary();

  /**
   * This method does the finalization of the native library. It is called exactly once for this
   * class. The library uses this method for a clean-up of any resources.
   *
   */
  protected static synchronized native void finalizeLibrary();

  /**
   * Connects to the PKCS#11 driver given. The filename must contain the path, if the driver is not
   * in the system's search path. Tries to load the PKCS#11 wrapper native library from the library
   * path or the class path (jar file). If loaded from the jar file, uses the debug version if
   * wrapperDebugVersion is true.
   *
   * @param pkcs11ModulePath
   *          the PKCS#11 library path
   * @exception IOException
   *              If linking to the given module failed.
   *
   */
  public PKCS11Implementation(String pkcs11ModulePath) throws IOException {
    connect(pkcs11ModulePath);
    this.pkcs11ModulePath = pkcs11ModulePath;
  }

  public String getPkcs11ModulePath() {
    return pkcs11ModulePath;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return The string representation of object
   */
  public String toString() {
    return "Module Name: " + pkcs11ModulePath;
  }

  /**
   * Calls disconnect() to clean up the native part of the wrapper. Once this method is called, this
   * object cannot be used any longer. Any subsequent call to a C_* method will result in a runtime
   * exception.
   *
   * @exception Throwable
   *              If finalization fails.
   */
  public void finalize() throws Throwable {
    disconnect();
    super.finalize();
  }

  /**
   * Connects this object to the specified PKCS#11 library. This method is for internal use only.
   * Declared protected, because incorrect handling may result in errors in the native part.
   *
   * @param pkcs11ModulePath
   *          The PKCS#11 library path.
   * @exception IOException
   *              If connecting the given module failed.
   *
   */
  protected synchronized native void connect(String pkcs11ModulePath) throws IOException;

  /**
   * Disconnects the PKCS#11 library from this object. After calling this method, this object is no
   * longer connected to a native PKCS#11 module and any subsequent calls to C_ methods will fail.
   * This method is for internal use only. Declared protected, because incorrect handling may result
   * in errors in the native part.
   *
   */
  protected synchronized native void disconnect();

  // Implementation of PKCS11 methods delegated to native pkcs11wrapper library

  /*
   * ****************************************************************************
   * General-purpose
   * ****************************************************************************
   */

  /**
   * C_Initialize initializes the Cryptoki library. (General-purpose)
   *
   * @param pInitArgs
   *          if pInitArgs is not NULL it gets cast to CK_C_INITIALIZE_ARGS_PTR and dereferenced
   *          (PKCS#11 param: CK_VOID_PTR pInitArgs)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_Initialize(Object pInitArgs, boolean useUtf8) throws PKCS11Exception;

  /**
   * C_Finalize indicates that an application is done with the Cryptoki library (General-purpose)
   *
   * @param pReserved
   *          is reserved. Should be NULL_PTR (PKCS#11 param: CK_VOID_PTR pReserved)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native void C_Finalize(Object pReserved) throws PKCS11Exception;

  /**
   * C_GetInfo returns general information about Cryptoki. (General-purpose)
   *
   * @return the information. (PKCS#11 param: CK_INFO_PTR pInfo)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native CK_INFO C_GetInfo() throws PKCS11Exception;

  /*
   * *****************************************************************************
   * Slot and token management
   * ****************************************************************************
   */

  /**
   * C_GetSlotList obtains a list of slots in the system. (Slot and token management)
   *
   * @param tokenPresent
   *          if true only Slot IDs with a token are returned (PKCS#11 param: CK_BBOOL tokenPresent)
   * @return a long array of slot IDs and number of Slot IDs (PKCS#11 param: CK_SLOT_ID_PTR
   *         pSlotList, CK_ULONG_PTR pulCount)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native long[] C_GetSlotList(boolean tokenPresent) throws PKCS11Exception;

  /**
   * C_GetSlotInfo obtains information about a particular slot in the system. (Slot and token
   * management)
   *
   * @param slotID
   *          the ID of the slot (PKCS#11 param: CK_SLOT_ID slotID)
   * @return the slot information (PKCS#11 param: CK_SLOT_INFO_PTR pInfo)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native CK_SLOT_INFO C_GetSlotInfo(long slotID) throws PKCS11Exception;

  /**
   * C_GetTokenInfo obtains information about a particular token in the system. (Slot and token
   * management)
   *
   * @param slotID
   *          ID of the token's slot (PKCS#11 param: CK_SLOT_ID slotID)
   * @return the token information (PKCS#11 param: CK_TOKEN_INFO_PTR pInfo)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native CK_TOKEN_INFO C_GetTokenInfo(long slotID) throws PKCS11Exception;

  /**
   * C_GetMechanismList obtains a list of mechanism types supported by a token. (Slot and token
   * management)
   *
   * @param slotID
   *          ID of the token's slot (PKCS#11 param: CK_SLOT_ID slotID)
   * @return a long array of mechanism types and number of mechanism types (PKCS#11 param:
   *         CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native long[] C_GetMechanismList(long slotID) throws PKCS11Exception;

  /**
   * C_GetMechanismInfo obtains information about a particular mechanism possibly supported by a
   * token. (Slot and token management)
   *
   * @param slotID
   *          ID of the token's slot (PKCS#11 param: CK_SLOT_ID slotID)
   * @param type
   *          type of mechanism (PKCS#11 param: CK_MECHANISM_TYPE type)
   * @return the mechanism info (PKCS#11 param: CK_MECHANISM_INFO_PTR pInfo)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native CK_MECHANISM_INFO C_GetMechanismInfo(long slotID, long type) throws PKCS11Exception;

  /**
   * C_InitToken initializes a token. (Slot and token management)
   *
   * @param slotID
   *          ID of the token's slot (PKCS#11 param: CK_SLOT_ID slotID)
   * @param pPin
   *          the SO's initial PIN and the length in bytes of the PIN (PKCS#11 param: CK_CHAR_PTR
   *          pPin, CK_ULONG ulPinLen)
   * @param pLabel
   *          32-byte token label (blank padded) (PKCS#11 param: CK_UTF8CHAR_PTR pLabel)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_InitToken(long slotID, char[] pPin, char[] pLabel, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_InitPIN initializes the normal user's PIN. (Slot and token management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pPin
   *          the normal user's PIN and the length in bytes of the PIN (PKCS#11 param: CK_CHAR_PTR
   *          pPin, CK_ULONG ulPinLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_InitPIN(long hSession, char[] pPin, boolean useUtf8) throws PKCS11Exception;

  /**
   * C_SetPIN modifies the PIN of the user who is logged in. (Slot and token management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pOldPin
   *          the old PIN and the length of the old PIN (PKCS#11 param: CK_CHAR_PTR pOldPin,
   *          CK_ULONG ulOldLen)
   * @param pNewPin
   *          the new PIN and the length of the new PIN (PKCS#11 param: CK_CHAR_PTR pNewPin,
   *          CK_ULONG ulNewLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_SetPIN(long hSession, char[] pOldPin, char[] pNewPin, boolean useUtf8) throws PKCS11Exception;

  /*
   * *****************************************************************************
   * Session management
   * ****************************************************************************
   */

  /**
   * C_OpenSession opens a session between an application and a token. (Session management)
   *
   * @param slotID
   *          the slot's ID (PKCS#11 param: CK_SLOT_ID slotID)
   * @param flags
   *          of CK_SESSION_INFO (PKCS#11 param: CK_FLAGS flags)
   * @param pApplication
   *          passed to callback (PKCS#11 param: CK_VOID_PTR pApplication)
   * @param Notify
   *          the callback function (PKCS#11 param: CK_NOTIFY Notify)
   * @return the session handle (PKCS#11 param: CK_SESSION_HANDLE_PTR phSession)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native long C_OpenSession(long slotID, long flags, Object pApplication,
      CK_NOTIFY Notify) throws PKCS11Exception;

  /**
   * C_CloseSession closes a session between an application and a token. (Session management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_CloseSession(long hSession) throws PKCS11Exception;

  /**
   * C_CloseAllSessions closes all sessions with a token. (Session management)
   *
   * @param slotID
   *          the ID of the token's slot (PKCS#11 param: CK_SLOT_ID slotID)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_CloseAllSessions(long slotID) throws PKCS11Exception;

  /**
   * C_GetSessionInfo obtains information about the session. (Session management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @return the session info (PKCS#11 param: CK_SESSION_INFO_PTR pInfo)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native CK_SESSION_INFO C_GetSessionInfo(long hSession) throws PKCS11Exception;

  /**
   * C_SessionCancel terminates active session based operations (Session management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param flags
   *          indicates which operations should be cancelled (PKCS#11 param: CK_FLAGS)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native void C_SessionCancel(long hSession, long flags) throws PKCS11Exception;

  /**
   * C_GetOperationState obtains the state of the cryptographic operation in a session. (Session
   * management)
   *
   * @param hSession
   *          session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @return the state and the state length (PKCS#11 param: CK_BYTE_PTR pOperationState,
   *         CK_ULONG_PTR pulOperationStateLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_GetOperationState(long hSession) throws PKCS11Exception;

  /**
   * C_SetOperationState restores the state of the cryptographic operation in a session. (Session
   * management)
   *
   * @param hSession
   *          session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pOperationState
   *          the state and the state length (PKCS#11 param: CK_BYTE_PTR pOperationState, CK_ULONG
   *          ulOperationStateLen)
   * @param hEncryptionKey
   *          en/decryption key (PKCS#11 param: CK_OBJECT_HANDLE hEncryptionKey)
   * @param hAuthenticationKey
   *          sign/verify key (PKCS#11 param: CK_OBJECT_HANDLE hAuthenticationKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_SetOperationState(long hSession, byte[] pOperationState,
      long hEncryptionKey, long hAuthenticationKey) throws PKCS11Exception;

  /**
   * C_Login logs a user into a token. (Session management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param userType
   *          the user type (PKCS#11 param: CK_USER_TYPE userType)
   * @param pPin
   *          the user's PIN and the length of the PIN (PKCS#11 param: CK_CHAR_PTR pPin, CK_ULONG
   *          ulPinLen)
   * @param useUtf8
   *          if pin should be changed from ASCII to UTF8 encoding in case of incorrect pin
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_Login(long hSession, long userType, char[] pPin, boolean useUtf8) throws PKCS11Exception;

  /**
   * C_LoginUser logs a user into a token. (Session management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param userType
   *          the user type (PKCS#11 param: CK_USER_TYPE userType)
   * @param pPin
   *          the user's PIN and the length of the PIN (PKCS#11 param: CK_CHAR_PTR pPin, CK_ULONG
   *          ulPinLen)
   * @param pUsername
   *          the username and the length of the username (PKCS#11 param: CK_CHAR_PTR pUsername,
   *          CK_ULONG ulUsernameLen
   * @param useUtf8
   *          if pin should be changed from ASCII to UTF8 encoding in case of incorrect pin
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_LoginUser(long hSession, long userType, char[] pPin, char[] pUsername, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_Logout logs a user out from a token. (Session management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_Logout(long hSession) throws PKCS11Exception;

  /*
   * *****************************************************************************
   * Object management
   * ****************************************************************************
   */

  /**
   * C_CreateObject creates a new object. (Object management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pTemplate
   *          the object's template and number of attributes in template (PKCS#11 param:
   *          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
   * @return the object's handle (PKCS#11 param: CK_OBJECT_HANDLE_PTR phObject)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native long C_CreateObject(long hSession, CK_ATTRIBUTE[] pTemplate, boolean useUtf8) throws PKCS11Exception;

  /**
   * C_CopyObject copies an object, creating a new object for the copy. (Object management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param hObject
   *          the object's handle (PKCS#11 param: CK_OBJECT_HANDLE hObject)
   * @param pTemplate
   *          the template for the new object and number of attributes in template (PKCS#11 param:
   *          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
   * @return the handle of the copy (PKCS#11 param: CK_OBJECT_HANDLE_PTR phNewObject)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native long C_CopyObject(long hSession, long hObject, CK_ATTRIBUTE[] pTemplate, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_DestroyObject destroys an object. (Object management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param hObject
   *          the object's handle (PKCS#11 param: CK_OBJECT_HANDLE hObject)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_DestroyObject(long hSession, long hObject) throws PKCS11Exception;

  /**
   * C_GetObjectSize gets the size of an object in bytes. (Object management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param hObject
   *          the object's handle (PKCS#11 param: CK_OBJECT_HANDLE hObject)
   * @return the size of the object (PKCS#11 param: CK_ULONG_PTR pulSize)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native long C_GetObjectSize(long hSession, long hObject) throws PKCS11Exception;

  /**
   * C_GetAttributeValue obtains the value of one or more object attributes. The template attributes
   * also receive the values. (Object management) note: in PKCS#11 pTemplate and the result template
   * are the same
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param hObject
   *          the object's handle (PKCS#11 param: CK_OBJECT_HANDLE hObject)
   * @param pTemplate
   *          specifies the attributes and number of attributes to get The template attributes also
   *          receive the values. (PKCS#11 param: CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_GetAttributeValue(long hSession, long hObject, CK_ATTRIBUTE[] pTemplate, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_SetAttributeValue modifies the value of one or more object attributes (Object management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param hObject
   *          the object's handle (PKCS#11 param: CK_OBJECT_HANDLE hObject)
   * @param pTemplate
   *          specifies the attributes and values to get; number of attributes in the template
   *          (PKCS#11 param: CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native void C_SetAttributeValue(long hSession, long hObject, CK_ATTRIBUTE[] pTemplate, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_FindObjectsInit initializes a search for token and session objects that match a template.
   * (Object management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pTemplate
   *          the object's attribute values to match and the number of attributes in search template
   *          (PKCS#11 param: CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_FindObjectsInit(long hSession, CK_ATTRIBUTE[] pTemplate, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_FindObjects continues a search for token and session objects that match a template, obtaining
   * additional object handles. (Object management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param ulMaxObjectCount
   *          the max. object handles to get (PKCS#11 param: CK_ULONG ulMaxObjectCount)
   * @return the object's handles and the actual number of objects returned (PKCS#11 param:
   *         CK_ULONG_PTR pulObjectCount)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native long[] C_FindObjects(long hSession, long ulMaxObjectCount) throws PKCS11Exception;

  /**
   * C_FindObjectsFinal finishes a search for token and session objects. (Object management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_FindObjectsFinal(long hSession) throws PKCS11Exception;

  /*
   * *****************************************************************************
   * Encryption and decryption
   * ****************************************************************************
   */

  /**
   * C_EncryptInit initializes an encryption operation. (Encryption and decryption)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the encryption mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hKey
   *          the handle of the encryption key (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_EncryptInit(long hSession, CK_MECHANISM pMechanism, long hKey, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_Encrypt encrypts single-part data. (Encryption and decryption)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pData
   *          the data to get encrypted and the data's length (PKCS#11 param: CK_BYTE_PTR pData,
   *          CK_ULONG ulDataLen)
   * @return the encrypted data and the encrypted data's length (PKCS#11 param: CK_BYTE_PTR
   *         pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native byte[] C_Encrypt(long hSession, byte[] pData) throws PKCS11Exception;

  /**
   * C_EncryptUpdate continues a multiple-part encryption operation. (Encryption and decryption)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pPart
   *          the data part to get encrypted and the data part's length (PKCS#11 param: CK_BYTE_PTR
   *          pPart, CK_ULONG ulPartLen)
   * @return the encrypted data part and the encrypted data part's length (PKCS#11 param:
   *         CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_EncryptUpdate(long hSession, byte[] pPart) throws PKCS11Exception;

  /**
   * C_EncryptFinal finishes a multiple-part encryption operation. (Encryption and decryption)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @return the last encrypted data part and the last data part's length (PKCS#11 param:
   *         CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_EncryptFinal(long hSession) throws PKCS11Exception;

  /**
   * C_MessageEncryptInit initializes an encryption operation for Messages. (Encryption and decryption)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the encryption mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hKey
   *          the handle of the encryption key (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_MessageEncryptInit(long hSession, CK_MECHANISM pMechanism, long hKey, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_EncryptMessage encrypts a Message in a single part.
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   *
   * @param pParameter
   *          the GCM OR CCM Parameters (PKCS#11 param: CK_VOID_PTR pParameter,
   *          CK_ULONG ulParameterLen)
   *          Depending on the mechanism, pParameter can be input or output.
   * @param pAssociatedData
   *          the Associated Data for usage of AEAD Mechanisms and the data's length (PKCS#11 param:
   *          CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
   * @param pPlainText
   *          the Plaintext to get encrypted and the text's length (PKCS#11 param: CK_BYTE_PTR pPlaintext,
   *          CK_ULONG ulPlaintextLen)
   *
   * @return the encrypted text and the encrypted text's length (PKCS#11 param: CK_BYTE_PTR
   *         pCiphertext, CK_ULONG_PTR CiphertextLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native byte[] C_EncryptMessage(long hSession, Object pParameter, byte[] pAssociatedData, byte[] pPlainText,
                                        boolean useUtf8) throws PKCS11Exception;

  /**
   * C_EncryptMessageBegin begins a multiple-part message encryption operation
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   *
   * @param pParameter
   *          the GCM OR CCM Parameters (PKCS#11 param: CK_VOID_PTR pParameter,
   *          CK_ULONG ulParameterLen)
   *          Depending on the mechanism, pParameter can be input or output.
   * @param pAssociatedData
   *          the Associated Data for usage of AEAD Mechanisms and the data's length
   *          (PKCS#11 param: CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
   *
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_EncryptMessageBegin(long hSession, Object pParameter, byte[] pAssociatedData, boolean jUseUtf8)
      throws  PKCS11Exception;

  /**
   * C_EncryptMessageNext continues a multiple-part message encryption operation, processing another
   * message part
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   *
   * @param pParameter
   *          the GCM OR CCM Parameters (PKCS#11 param: CK_VOID_PTR pParameter,
   *          CK_ULONG ulParameterLen)
   *          Depending on the mechanism, pParameter can be input or output.
   *
   * @param pPlainTextPart
   *          the Plaintext to get encrypted and the text's length (PKCS#11 param: CK_BYTE_PTR pPlaintext,
   *          CK_ULONG ulPlaintextLen)
   *
   * @param flags
   *          either 0 for continuing the multipart encryption operation or CKF_END_OF_MESSAGE if this call is the
   *          last part of the operation
   *
   * @return the ciphertext and the ciphertext length (PKCS#11 param: CK_BYTE_PTR
   *         pCiphertext, CK_ULONG_PTR CiphertextLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native byte[] C_EncryptMessageNext(long hSession, Object pParameter, byte[] pPlainTextPart, long flags,
                                            boolean useUtf8) throws PKCS11Exception;

  /**
   * C_MessageEncryptFinal finishes a message-based encryption process
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   *
   * @throws PKCS11Exception in case of error.
   */
  public native void C_MessageEncryptFinal(long hSession) throws PKCS11Exception;

  /**
   * C_DecryptInit initializes a decryption operation. (Encryption and decryption)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the decryption mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hKey
   *          the handle of the decryption key (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_DecryptInit(long hSession, CK_MECHANISM pMechanism, long hKey, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_Decrypt decrypts encrypted data in a single part. (Encryption and decryption)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pEncryptedData
   *          the encrypted data to get decrypted and the encrypted data's length (PKCS#11 param:
   *          CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen)
   * @return the decrypted data and the data's length (PKCS#11 param: CK_BYTE_PTR pData,
   *         CK_ULONG_PTR pulDataLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native byte[] C_Decrypt(long hSession, byte[] pEncryptedData) throws PKCS11Exception;

  /**
   * C_DecryptUpdate continues a multiple-part decryption operation. (Encryption and decryption)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pEncryptedPart
   *          the encrypted data part to get decrypted and the encrypted data part's length (PKCS#11
   *          param: CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen)
   * @return the decrypted data part and the data part's length (PKCS#11 param: CK_BYTE_PTR pPart,
   *         CK_ULONG_PTR pulPartLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_DecryptUpdate(long hSession, byte[] pEncryptedPart) throws PKCS11Exception;

  /**
   * C_DecryptFinal finishes a multiple-part decryption operation. (Encryption and decryption)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @return the last decrypted data part and the last data part's length (PKCS#11 param:
   *         CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_DecryptFinal(long hSession) throws PKCS11Exception;

  /**
   * C_MessageDecryptInit initializes a decryption operation for Messages.
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the encryption mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hKey
   *          the handle of the decryption key (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_MessageDecryptInit(long hSession, CK_MECHANISM pMechanism, long hKey, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_DecryptMessage decrypts a message in a single part
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   *
   * @param pParameter
   *          the GCM OR CCM Parameters (PKCS#11 param: CK_VOID_PTR pParameter,
   *          CK_ULONG ulParameterLen)
   *          Depending on the mechanism, pParameter can be input or output.
   * @param pAssociatedData
   *          the Associated Data for usage of AEAD Mechanisms and the data's length
   *          (PKCS#11 param: CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
   * @param pCipherText
   *          the Plaintext to get encrypted and the text's length (PKCS#11 param:
   *          CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen)
   *
   * @return the plaintext and the its length (PKCS#11 param: CK_BYTE_PTR
   *         pPlaintext, CK_ULONG_PTR PlaintextLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native byte[] C_DecryptMessage(long hSession, Object pParameter, byte[] pAssociatedData, byte[] pCipherText,
                                        boolean useUtf8) throws PKCS11Exception;

  /**
   * C_DecryptMessageBegin begins a multiple-part message decryption operation
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   *
   * @param pParameter
   *          the GCM OR CCM Parameters (PKCS#11 param: CK_VOID_PTR pParameter,
   *          CK_ULONG ulParameterLen)
   *          Depending on the mechanism, pParameter can be input or output.
   * @param pAssociatedData
   *          the Associated Data for usage of AEAD Mechanisms and the data's length (PKCS#11 param:
   *          CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
   *
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_DecryptMessageBegin(long hSession, Object pParameter, byte[] pAssociatedData, boolean useUtf8)
      throws  PKCS11Exception;

  /**
   * C_DecryptMessageNext continues a multiple-part message decryption operation, processing another
   * message part
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   *
   * @param pParameter
   *          the GCM OR CCM Parameters (PKCS#11 param: CK_VOID_PTR pParameter,
   *          CK_ULONG ulParameterLen)
   *          Depending on the mechanism, pParameter can be input or output.
   *
   * @param pCipherTextPart
   *          the Ciphertext to get decrypted and the text's length (PKCS#11 param: CK_BYTE_PTR pCiphertext,
   *          CK_ULONG ulCiphertextLen)
   *
   * @param flags
   *          either 0 for continuing the multipart decryption operation or CKF_END_OF_MESSAGE if this call is the
   *          last part of the operation
   *
   * @return the plaintext and the plaintext length (PKCS#11 param: CK_BYTE_PTR
   *         pPlaintext, CK_ULONG_PTR PlaintextLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native byte[] C_DecryptMessageNext(long hSession, Object pParameter, byte[] pCipherTextPart, long flags,
                                            boolean useUtf8) throws PKCS11Exception;

  /**
   * C_MessageDecryptFinal finishes a message-based Decryption process
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   *
   * @throws PKCS11Exception in case of error.
   */
  public native void C_MessageDecryptFinal(long hSession) throws PKCS11Exception;

  /*
   * *****************************************************************************
   * Message digesting
   * ****************************************************************************
   */

  /**
   * C_DigestInit initializes a message-digesting operation. (Message digesting)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the digesting mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_DigestInit(long hSession, CK_MECHANISM pMechanism, boolean useUtf8) throws PKCS11Exception;

  /**
   * C_Digest digests data in a single part. (Message digesting)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param data
   *          the data to get digested and the data's length (PKCS#11 param: CK_BYTE_PTR pData,
   *          CK_ULONG ulDataLen)
   * @return the message digest and the length of the message digest (PKCS#11 param: CK_BYTE_PTR
   *         pDigest, CK_ULONG_PTR pulDigestLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native byte[] C_Digest(long hSession, byte[] data) throws PKCS11Exception;

  /**
   * C_DigestUpdate continues a multiple-part message-digesting operation. (Message digesting)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pPart
   *          the data to get digested and the data's length (PKCS#11 param: CK_BYTE_PTR pPart,
   *          CK_ULONG ulPartLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native void C_DigestUpdate(long hSession, byte[] pPart) throws PKCS11Exception;

  /**
   * C_DigestKey continues a multipart message-digesting operation, by digesting the value of a
   * secret key as part of the data already digested. (Message digesting)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param hKey
   *          the handle of the secret key to be digested (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_DigestKey(long hSession, long hKey) throws PKCS11Exception;

  /**
   * C_DigestFinal finishes a multiple-part message-digesting operation. (Message digesting)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @return the message digest and the length of the message digest (PKCS#11 param: CK_BYTE_PTR
   *         pDigest, CK_ULONG_PTR pulDigestLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_DigestFinal(long hSession) throws PKCS11Exception;

  /*
   * *****************************************************************************
   * Sign and MAC
   * ****************************************************************************
   */

  /**
   * C_SignInit initializes a signature (private key encryption) operation, where the signature is
   * (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
   * (Sign and MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the signature mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hKey
   *          the handle of the signature key (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_SignInit(long hSession, CK_MECHANISM pMechanism, long hKey, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_Sign signs (encrypts with private key) data in a single part, where the signature is (will
   * be) an appendix to the data, and plaintext cannot be recovered from the signature.
   * (Sign and MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pData
   *          the data to sign and the data's length (PKCS#11 param: CK_BYTE_PTR pData, CK_ULONG
   *          ulDataLen)
   * @return the signature and the signature's length (PKCS#11 param: CK_BYTE_PTR pSignature,
   *         CK_ULONG_PTR pulSignatureLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native byte[] C_Sign(long hSession, byte[] pData) throws PKCS11Exception;

  /**
   * C_SignUpdate continues a multiple-part signature operation, where the signature is (will be) an
   * appendix to the data, and plaintext cannot be recovered from the signature. (Sign and
   * MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pPart
   *          the data part to sign and the data part's length (PKCS#11 param: CK_BYTE_PTR pPart,
   *          CK_ULONG ulPartLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native void C_SignUpdate(long hSession, byte[] pPart) throws PKCS11Exception;

  /**
   * C_SignFinal finishes a multiple-part signature operation, returning the signature. (Sign and
   * MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @return the signature and the signature's length (PKCS#11 param: CK_BYTE_PTR pSignature,
   *         CK_ULONG_PTR pulSignatureLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_SignFinal(long hSession) throws PKCS11Exception;

  /**
   * C_SignRecoverInit initializes a signature operation, where the data can be recovered from the
   * signature. (Sign and MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the signature mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hKey
   *          the handle of the signature key (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_SignRecoverInit(long hSession, CK_MECHANISM pMechanism, long hKey, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_SignRecover signs data in a single operation, where the data can be recovered from the
   * signature. (Sign and MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pData
   *          the data to sign and the data's length (PKCS#11 param: CK_BYTE_PTR pData, CK_ULONG
   *          ulDataLen)
   * @return the signature and the signature's length (PKCS#11 param: CK_BYTE_PTR pSignature,
   *         CK_ULONG_PTR pulSignatureLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native byte[] C_SignRecover(long hSession, byte[] pData) throws PKCS11Exception;

  /**
   * C_MessageSignInit initializes a Message Sign operation
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the signature mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hKey
   *          the handle of the signature key (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   */
  public native void C_MessageSignInit(long hSession, CK_MECHANISM pMechanism, long hKey, boolean useUtf8);

  /**
   *C_SignMessage signs a message in a single part, where the signature is an appendix to the message.
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pParameter
   *          the mechanism parameter (PKCS#11 CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
   * @param pData
   *          the data to sign and the data's length (PKCS#11 param: CK_BYTE_PTR pData, CK_ULONG
   *          ulDataLen)
   * @return the signature and the signature's length (PKCS#11 param: CK_BYTE_PTR pSignature,
   *         CK_ULONG_PTR pulSignatureLen)
   */
  public native byte[] C_SignMessage(long hSession, Object pParameter, byte[] pData, boolean useUtf8);

  /**
   * C_SignMessageBegin begins a multiple-part message signature operation, where the signature is an
   * appendix to the message.
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pParameter
   *          the mechanism parameter (PKCS#11 CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
   */
  public native void C_SignMessageBegin(long hSession, Object pParameter, boolean useUtf8);

  /**
   * C_SignMessageNext continues a multiple-part message signature operation, processing another data
   * part, or finishes a multiple-part message signature operation, returning the signature.
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pParameter
   *          the mechanism parameter (PKCS#11 CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
   * @param pData
   *          the data to sign and the data's length (PKCS#11 param: CK_BYTE_PTR pData, CK_ULONG
   *          ulDataLen)
   * @return the signature and the signature's length (PKCS#11 param: CK_BYTE_PTR pSignature,
   *         CK_ULONG_PTR pulSignatureLen)
   */
  public native byte[] C_SignMessageNext(long hSession, Object pParameter, byte[] pData,
                                         boolean isLastOperation, boolean useUtf8);

  /**
   * C_MessageSignFinal finishes a message-based Sign process.
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   */
  public native void C_MessageSignFinal(long hSession);

  /*
   * *****************************************************************************
   * Verifying signatures and MACs
   * ****************************************************************************
   */

  /**
   * C_VerifyInit initializes a verification operation, where the signature is an appendix to the
   * data, and plaintext cannot be recovered from the signature (e.g. DSA). (Sign and
   * MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the verification mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hKey
   *          the handle of the verification key (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_VerifyInit(long hSession, CK_MECHANISM pMechanism, long hKey, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_Verify verifies a signature in a single-part operation, where the signature is an appendix to
   * the data, and plaintext cannot be recovered from the signature. (Sign and MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pData
   *          the signed data and the signed data's length (PKCS#11 param: CK_BYTE_PTR pData,
   *          CK_ULONG ulDataLen)
   * @param pSignature
   *          the signature to verify and the signature's length (PKCS#11 param: CK_BYTE_PTR
   *          pSignature, CK_ULONG ulSignatureLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native void C_Verify(long hSession, byte[] pData, byte[] pSignature) throws PKCS11Exception;

  /**
   * C_VerifyUpdate continues a multiple-part verification operation, where the signature is an
   * appendix to the data, and plaintext cannot be recovered from the signature. (Sign and
   * MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pPart
   *          the signed data part and the signed data part's length (PKCS#11 param: CK_BYTE_PTR
   *          pPart, CK_ULONG ulPartLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native void C_VerifyUpdate(long hSession, byte[] pPart) throws PKCS11Exception;

  /**
   * C_VerifyFinal finishes a multiple-part verification operation, checking the signature. (Sign
   * and MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pSignature
   *          the signature to verify and the signature's length (PKCS#11 param: CK_BYTE_PTR
   *          pSignature, CK_ULONG ulSignatureLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native void C_VerifyFinal(long hSession, byte[] pSignature) throws PKCS11Exception;

  /**
   * C_VerifyRecoverInit initializes a signature verification operation, where the data is recovered
   * from the signature. (Sign and MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the verification mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hKey
   *          the handle of the verification key (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_VerifyRecoverInit(long hSession, CK_MECHANISM pMechanism, long hKey, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_VerifyRecover verifies a signature in a single-part operation, where the data is recovered
   * from the signature. (Sign and MAC)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pSignature
   *          the signature to verify and the signature's length (PKCS#11 param: CK_BYTE_PTR
   *          pSignature, CK_ULONG ulSignatureLen)
   * @return the recovered data and the recovered data's length (PKCS#11 param: CK_BYTE_PTR pData,
   *         CK_ULONG_PTR pulDataLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native byte[] C_VerifyRecover(long hSession, byte[] pSignature) throws PKCS11Exception;

  /**
   * C_MessageVerifyInit initializes a message-based verification process, preparing a session for one or
   * more verification operations that use the same verification mechanism and verification key.
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the signature mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hKey
   *          the handle of the signature key (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   */
  public native void C_MessageVerifyInit(long hSession, CK_MECHANISM pMechanism, long hKey, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_VerifyMessage verifies a signature on a message in a single part operation.
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pParameter
   *          the mechanism parameter (PKCS#11 param: CK_VOID_PTR pParameter,
   *                 CK_ULONG ulParameterLen)
   * @param pData
   *          the data getting signed (PKCS#11 param: CK_VOID_PTR pData,
   *                CK_ULONG ckDataLen)
   *
   * @param pSignature (PKCS#11 param: CK_VOID_PTR pSignature,
   *                CK_ULONG ckSignatureLen)
   *
   * @throws PKCS11Exception if the Signature is invalid
   *
   */
  public native void C_VerifyMessage(long hSession, Object pParameter, byte[] pData,
                              byte[] pSignature, boolean useUtf8) throws PKCS11Exception;

  /**
   * C_VerifyMessageBegin begins a multiple-part message verification operation
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pParameter
   *          the mechanism parameter (PKCS#11 param: CK_VOID_PTR pParameter,
   *                 CK_ULONG ulParameterLen)
   */
  public native void C_VerifyMessageBegin(long hSession, Object pParameter, boolean useUtf8) throws PKCS11Exception;

  /**
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pParameter
   *          the mechanism parameter (PKCS#11 param: CK_VOID_PTR pParameter,
   *                 CK_ULONG ulParameterLen)
   * @param pData
   *          the data getting signed (PKCS#11 param: CK_VOID_PTR pData,
   *                CK_ULONG ckDataLen)
   * @throws PKCS11Exception if the Signature is invalid
   */
  public native void C_VerifyMessageNext(long hSession, Object pParameter, byte[] pData,
                                  byte[] pSignature, boolean useUtf8) throws PKCS11Exception;

  /**
   * C_MessageSignFinal finishes a message-based Sign process.
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   */
  public native void C_MessageVerifyFinal(long hSession) throws PKCS11Exception;

  /*
   * *****************************************************************************
   * Dual-function cryptographic operations
   * ****************************************************************************
   */

  /**
   * C_DigestEncryptUpdate continues a multiple-part digesting and encryption operation.
   * (Dual-function cryptographic operations)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pPart
   *          the data part to digest and to encrypt and the data's length (PKCS#11 param:
   *          CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
   * @return the digested and encrypted data part and the data part's length (PKCS#11 param:
   *         CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_DigestEncryptUpdate(long hSession, byte[] pPart) throws PKCS11Exception;

  /**
   * C_DecryptDigestUpdate continues a multiple-part decryption and digesting operation.
   * (Dual-function cryptographic operations)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pEncryptedPart
   *          the encrypted data part to decrypt and to digest and encrypted data part's length
   *          (PKCS#11 param: CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen)
   * @return the decrypted and digested data part and the data part's length (PKCS#11 param:
   *         CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_DecryptDigestUpdate(long hSession, byte[] pEncryptedPart) throws PKCS11Exception;

  /**
   * C_SignEncryptUpdate continues a multiple-part Sign and encryption operation. (Dual-function
   * cryptographic operations)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pPart
   *          the data part to sign and to encrypt and the data part's length (PKCS#11 param:
   *          CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
   * @return the signed and encrypted data part and the data part's length (PKCS#11 param:
   *         CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_SignEncryptUpdate(long hSession, byte[] pPart) throws PKCS11Exception;

  /**
   * C_DecryptVerifyUpdate continues a multiple-part decryption and verify operation. (Dual-function
   * cryptographic operations)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pEncryptedPart
   *          the encrypted data part to decrypt and to verify and the data part's length (PKCS#11
   *          param: CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen)
   * @return the decrypted and verified data part and the data part's length (PKCS#11 param:
   *         CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_DecryptVerifyUpdate(long hSession, byte[] pEncryptedPart) throws PKCS11Exception;

  /*
   * *****************************************************************************
   * Key management
   * ****************************************************************************
   */

  /**
   * C_GenerateKey generates a secret key, creating a new key object. (Key management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the key generation mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param pTemplate
   *          the template for the new key and the number of attributes in the template (PKCS#11
   *          param: CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
   * @return the handle of the new key (PKCS#11 param: CK_OBJECT_HANDLE_PTR phKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native long C_GenerateKey(long hSession, CK_MECHANISM pMechanism,
      CK_ATTRIBUTE[] pTemplate, boolean useUtf8) throws PKCS11Exception;

  /**
   * C_GenerateKeyPair generates a public-key/private-key pair, creating new key objects. (Key
   * management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the key generation mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param pPublicKeyTemplate
   *          the template for the new public key and the number of attributes in the template
   *          (PKCS#11 param: CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG
   *          ulPublicKeyAttributeCount)
   * @param pPrivateKeyTemplate
   *          the template for the new private key and the number of attributes in the template
   *          (PKCS#11 param: CK_ATTRIBUTE_PTR pPrivateKeyTemplate CK_ULONG
   *          ulPrivateKeyAttributeCount)
   * @return a long array with exactly two elements and the public key handle as the first element
   *         and the private key handle as the second element (PKCS#11 param: CK_OBJECT_HANDLE_PTR
   *         phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native long[] C_GenerateKeyPair(long hSession, CK_MECHANISM pMechanism,
      CK_ATTRIBUTE[] pPublicKeyTemplate, CK_ATTRIBUTE[] pPrivateKeyTemplate, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_WrapKey wraps (i.e., encrypts) a key. (Key management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the wrapping mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hWrappingKey
   *          the handle of the wrapping key (PKCS#11 param: CK_OBJECT_HANDLE hWrappingKey)
   * @param hKey
   *          the handle of the key to be wrapped (PKCS#11 param: CK_OBJECT_HANDLE hKey)
   * @return the wrapped key and the length of the wrapped key (PKCS#11 param: CK_BYTE_PTR
   *         pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native byte[] C_WrapKey(long hSession, CK_MECHANISM pMechanism,
      long hWrappingKey, long hKey, boolean useUtf8) throws PKCS11Exception;

  /**
   * C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new key object. (Key management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the unwrapping mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hUnwrappingKey
   *          the handle of the unwrapping key (PKCS#11 param: CK_OBJECT_HANDLE hUnwrappingKey)
   * @param pWrappedKey
   *          the wrapped key to unwrap and the wrapped key's length (PKCS#11 param: CK_BYTE_PTR
   *          pWrappedKey, CK_ULONG ulWrappedKeyLen)
   * @param pTemplate
   *          the template for the new key and the number of attributes in the template (PKCS#11
   *          param: CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
   * @return the handle of the unwrapped key (PKCS#11 param: CK_OBJECT_HANDLE_PTR phKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native long C_UnwrapKey(long hSession, CK_MECHANISM pMechanism,
      long hUnwrappingKey, byte[] pWrappedKey, CK_ATTRIBUTE[] pTemplate, boolean useUtf8)
      throws PKCS11Exception;

  /**
   * C_DeriveKey derives a key from a base key, creating a new key object. (Key management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pMechanism
   *          the key derivation mechanism (PKCS#11 param: CK_MECHANISM_PTR pMechanism)
   * @param hBaseKey
   *          the handle of the base key (PKCS#11 param: CK_OBJECT_HANDLE hBaseKey)
   * @param pTemplate
   *          the template for the new key and the number of attributes in the template (PKCS#11
   *          param: CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
   * @return the handle of the derived key (PKCS#11 param: CK_OBJECT_HANDLE_PTR phKey)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native long C_DeriveKey(long hSession, CK_MECHANISM pMechanism, long hBaseKey,
      CK_ATTRIBUTE[] pTemplate, boolean useUtf8) throws PKCS11Exception;

  /*
   * *****************************************************************************
   * Random number generation
   * ****************************************************************************
   */

  /**
   * C_SeedRandom mixes additional seed material into the token's random number generator. (Random
   * number generation)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param pSeed
   *          the seed material and the seed material's length (PKCS#11 param: CK_BYTE_PTR pSeed,
   *          CK_ULONG ulSeedLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native void C_SeedRandom(long hSession, byte[] pSeed) throws PKCS11Exception;

  /**
   * C_GenerateRandom generates random data. (Random number generation)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @param randomData
   *          receives the random data and the length of RandomData is the length of random data to
   *          be generated (PKCS#11 param: CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native void C_GenerateRandom(long hSession, byte[] randomData) throws PKCS11Exception;

  /*
   * *****************************************************************************
   * Parallel function management
   * ****************************************************************************
   */

  /**
   * C_GetFunctionStatus is a legacy function; it obtains an updated status of a function running in
   * parallel with an application. (Parallel function management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_GetFunctionStatus(long hSession) throws PKCS11Exception;

  /**
   * C_CancelFunction is a legacy function; it cancels a function running in parallel. (Parallel
   * function management)
   *
   * @param hSession
   *          the session's handle (PKCS#11 param: CK_SESSION_HANDLE hSession)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   */
  public native void C_CancelFunction(long hSession) throws PKCS11Exception;

  /*
   * *****************************************************************************
   * Functions added in for Cryptoki Version 2.01 or later
   * ****************************************************************************
   */

  /**
   * C_WaitForSlotEvent waits for a slot event (token insertion, removal, etc.) to occur.
   * (General-purpose)
   *
   * @param flags
   *          blocking/nonblocking flag (PKCS#11 param: CK_FLAGS flags)
   * @param pReserved
   *          reserved. Should be null (PKCS#11 param: CK_VOID_PTR pReserved)
   * @return the slot ID where the event occurred (PKCS#11 param: CK_SLOT_ID_PTR pSlot)
   * @exception PKCS11Exception
   *              If function returns other value than CKR_OK.
   *
   */
  public native long C_WaitForSlotEvent(long flags, Object pReserved) throws PKCS11Exception;

  public boolean isDisableBufferPreAllocation() {
    return false;
  }
}
