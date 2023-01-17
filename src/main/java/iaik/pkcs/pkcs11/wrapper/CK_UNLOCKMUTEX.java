// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * interface CK_UNLOCKMUTEX
 * <p>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public interface CK_UNLOCKMUTEX {

  /**
   * Method CK_UNLOCKMUTEX
   *
   * @param pMutex
   *          The mutex (lock) object to unlock.
   * @exception PKCS11Exception
   *              If unlocking the mutex fails.
   */
  void CK_UNLOCKMUTEX(Object pMutex) throws PKCS11Exception;

}
