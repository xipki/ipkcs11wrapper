// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_SSL3_MASTER_KEY_DERIVE_PARAMS provides the parameters to the CKM_SSL3_MASTER_KEY_DERIVE
 * mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
 *   CK_SSL3_RANDOM_DATA  RandomInfo;
 *   CK_VERSION_PTR       pVersion;
 * } CK_SSL3_MASTER_KEY_DERIVE_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_SSL3_MASTER_KEY_DERIVE_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_SSL3_RANDOM_DATA RandomInfo;
   * </PRE>
   */
  public CK_SSL3_RANDOM_DATA RandomInfo;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_VERSION_PTR pVersion;
   * </PRE>
   */
  public CK_VERSION pVersion;

}
