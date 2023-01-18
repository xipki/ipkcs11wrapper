// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 *
 * <B>PKCS#11 structure:</B>
 * <pre>
 * typedef struct CK_X9_42_MQV_DERIVE_PARAMS {
 *   CK_X9_42_DH_KDF_TYPE kdf;
 *   CK_ULONG             ulOtherInfoLen;
 *   CK_BYTE_PTR          pOtherInfo;
 *   CK_ULONG             ulPublicDataLen;
 *   CK_BYTE_PTR          pPublicData;
 *   CK_ULONG             ulPrivateDataLen;
 *   CK_OBJECT_HANDLE     hPrivateData;
 *   CK_ULONG             ulPublicDataLen2;
 *   CK_BYTE_PTR          pPublicData2;
 *   CK_OBJECT_HANDLE     publicKey;
 * } CK_X9_42_MQV_DERIVE_PARAMS;
 * </pre>
 * @author Karl Scheibelhofer (SIC)
 */
public class CK_X9_42_DHMQV_DERIVE_PARAMS {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_X9_42_DH_KDF_TYPE kdf;
   * </PRE>
   *
   * .
   */
  public long kdf;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulOtherInfoLen;
   * CK_BYTE_PTR pOtherInfo;
   * </PRE>
   *
   * .
   */
  public byte[] pOtherInfo;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulPublicDataLen;
   * CK_BYTE_PTR pPublicData;
   * </PRE>
   *
   * .
   */
  public byte[] pPublicData;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulPrivateDataLen;
   * </PRE>
   *
   * .
   */
  public long ulPrivateDataLen;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_OBJECT_HANDLE hPrivateData;
   * </PRE>
   *
   * .
   */
  public long hPrivateData;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_ULONG ulPublicDataLen2;
   * CK_BYTE_PTR pPublicData2;
   * </PRE>
   *
   * .
   */
  public byte[] pPublicData2;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_OBJECT_HANDLE publicKey;
   * </PRE>
   *
   * .
   */
  public long hPublicKey;

}
