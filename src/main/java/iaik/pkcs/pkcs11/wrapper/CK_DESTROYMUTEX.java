// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * interface CK_DESTROYMUTEX.
 * <p>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public interface CK_DESTROYMUTEX {

  /**
   * Method CK_DESTROYMUTEX
   *
   * @param pMutex
   *          The mutex (lock) object.
   * @exception PKCS11Exception
   *              If destroying the mutex fails.
   */
  void CK_DESTROYMUTEX(Object pMutex) throws PKCS11Exception;

}
