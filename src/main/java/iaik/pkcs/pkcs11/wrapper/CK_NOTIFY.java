// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * interface CK_NOTIFY.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public interface CK_NOTIFY {

  /**
   * Method CK_NOTIFY
   *
   * @param hSession The handle of the session performing the callback.
   * @param event The type of notification callback.
   * @param pApplication An application-defined value. this is the same value as was passed to <br>
   * {@link PKCS11 #C_OpenSession} to open the session performing the callback.
   *
   * @exception PKCS11Exception in case of error.
   */
  void CK_NOTIFY(long hSession, long event, Object pApplication)
      throws PKCS11Exception;

}
