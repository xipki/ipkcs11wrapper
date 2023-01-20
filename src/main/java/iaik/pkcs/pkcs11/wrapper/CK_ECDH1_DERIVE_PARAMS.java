// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_ECDH1_DERIVE_PARAMS provides the parameters to the CKM_ECDH1_DERIVE and
 * CKM_ECDH1_COFACTOR_DERIVE mechanisms.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_ECDH1_DERIVE_PARAMS {
 *   CK_EC_KDF_TYPE  kdf;
 *   CK_ULONG        ulSharedDataLen;
 *   CK_BYTE_PTR     pSharedData;
 *   CK_ULONG        ulPublicDataLen;
 *   CK_BYTE_PTR     pPublicData;
 * } CK_ECDH1_DERIVE_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 */
public class CK_ECDH1_DERIVE_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_EC_KDF_TYPE kdf;
   * </PRE>
   */
  public long kdf;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulSharedDataLen;
   * CK_BYTE_PTR pSharedData;
   * </PRE>
   */
  public byte[] pSharedData;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulPublicDataLen;
   * CK_BYTE_PTR pPublicData;
   * </PRE>
   */
  public byte[] pPublicData;

}
