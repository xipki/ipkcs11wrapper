// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_C_INITIALIZE_ARGS contains the optional arguments for the C_Initialize function.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_C_INITIALIZE_ARGS {&nbsp;&nbsp;
 *   CK_CREATEMUTEX CreateMutex;&nbsp;&nbsp;
 *   CK_DESTROYMUTEX DestroyMutex;&nbsp;&nbsp;
 *   CK_LOCKMUTEX LockMutex;&nbsp;&nbsp;
 *   CK_UNLOCKMUTEX UnlockMutex;&nbsp;&nbsp;
 *   CK_FLAGS flags;&nbsp;&nbsp;
 *   CK_VOID_PTR pReserved;&nbsp;&nbsp;
 * } CK_C_INITIALIZE_ARGS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_C_INITIALIZE_ARGS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_CREATEMUTEX CreateMutex;
   * </PRE>
   */
  public CK_CREATEMUTEX CreateMutex;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_DESTROYMUTEX DestroyMutex;
   * </PRE>
   */
  public CK_DESTROYMUTEX DestroyMutex;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_LOCKMUTEX LockMutex;
   * </PRE>
   */
  public CK_LOCKMUTEX LockMutex;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_UNLOCKMUTEX UnlockMutex;
   * </PRE>
   */
  public CK_UNLOCKMUTEX UnlockMutex;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_FLAGS flags;
   * </PRE>
   */
  public long flags;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_VOID_PTR pReserved;
   * </PRE>
   */
  public Object pReserved;

}
