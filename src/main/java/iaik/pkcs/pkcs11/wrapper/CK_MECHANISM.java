// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_MECHANISM specifies a particular mechanism and any parameters it requires.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 *  typedef struct CK_MECHANISM {
 *    CK_MECHANISM_TYPE  mechanism;
 *    CK_VOID_PTR        pParameter;
 *    CK_ULONG           ulParameterLen;
 *  } CK_MECHANISM;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_MECHANISM {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_MECHANISM_TYPE mechanism;
   * </PRE>
   */
  public long mechanism;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_VOID_PTR pParameter;
   * CK_ULONG ulParameterLen;
   * </PRE>
   */
  public Object pParameter;

}
