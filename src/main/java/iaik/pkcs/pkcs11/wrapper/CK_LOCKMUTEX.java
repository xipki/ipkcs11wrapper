// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * interface CK_LOCKMUTEX
 * <p>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public interface CK_LOCKMUTEX {

  /**
   * Method CK_LOCKMUTEX
   *
   * @param pMutex
   *          The mutex (lock) object to lock.
   * @exception PKCS11Exception
   *              If locking the mutex fails.
   */
  void CK_LOCKMUTEX(Object pMutex) throws PKCS11Exception;

}
