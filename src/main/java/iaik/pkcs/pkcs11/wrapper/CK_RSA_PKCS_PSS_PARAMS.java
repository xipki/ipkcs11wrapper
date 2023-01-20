// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_RSA_PKCS_PSS_PARAMS provides the parameters to the CKM_RSA_PKCS_OAEP mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_RSA_PKCS_PSS_PARAMS {
 *   CK_MECHANISM_TYPE     hashAlg;
 *   CK_RSA_PKCS_MGF_TYPE  mgf;
 *   CK_ULONG              sLen;
 * } CK_RSA_PKCS_PSS_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 */
public class CK_RSA_PKCS_PSS_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_MECHANISM_TYPE hashAlg;
   * </PRE>
   */
  public long hashAlg;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_RSA_PKCS_MGF_TYPE mgf;
   * </PRE>
   */
  public long mgf;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG sLen;
   * </PRE>
   */
  public long sLen;

}
