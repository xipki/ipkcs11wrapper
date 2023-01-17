// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * interface CK_CREATEMUTEX.
 * <p>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public interface CK_CREATEMUTEX {

  /**
   * Method CK_CREATEMUTEX
   *
   * @return The mutex (lock) object.
   * @exception PKCS11Exception
   *              If creating the mutex fails.
   */
  Object CK_CREATEMUTEX() throws PKCS11Exception;

}
