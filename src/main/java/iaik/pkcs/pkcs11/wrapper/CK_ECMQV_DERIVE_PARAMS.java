// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_ECMQV_DERIVE_PARAMS provides the parameters to the CKM_ECMQV_DERIVE mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_ECMQV_DERIVE_PARAMS {
 *   CK_EC_KDF_TYPE kdf;
 *   CK_ULONG ulSharedDataLen;
 *   CK_BYTE_PTR pSharedData;
 *   CK_ULONG ulPublicDataLen;
 *   CK_BYTE_PTR pPublicData;
 *   CK_ULONG ulPrivateDataLen;
 *   CK_OBJECT_HANDLE hPrivateData;
 *   CK_ULONG ulPublicDataLen2;
 *   CK_BYTE_PTR pPublicData2;
 *   CK_OBJECT_HANDLE publicKey;
 * } CK_ECMQV_DERIVE_PARAMS;
 * </PRE>
 *
 * @author Stiftung SIC (SIC)
 */
public class CK_ECMQV_DERIVE_PARAMS {

  /**
   * key derivation function used on the shared secret value
   *
   * <PRE>
   * CK_EC_KDF_TYPE kdf;
   * </PRE>
   */
  public long kdf;

  /**
   * some data shared between the two parties
   *
   * <PRE>
   * CK_BYTE_PTR pSharedData;
   * </PRE>
   */
  public byte[] pSharedData;

  /**
   * pointer to other partyâs first EC public key value
   *
   * <PRE>
   * CK_ULONG ulPublicDataLen;
   * CK_BYTE_PTR pPublicData;
   * </PRE>
   */
  public byte[] pPublicData;

  /**
   * the length in bytes of the second EC private key
   *
   * <PRE>
   * CK_ULONG ulPrivateDataLen;
   * </PRE>
   */
  public long ulPrivateDataLen;

  /**
   * key handle for second EC private key value
   *
   * <PRE>
   * CK_OBJECT_HANDLE hPrivateData;
   * </PRE>
   */
  public long hPrivateData;

  /**
   * pointer to other partyâs second EC public key value
   *
   * <PRE>
   * CK_ULONG ulPublicDataLen2;
   * CK_BYTE_PTR pPublicData2;
   * </PRE>
   */
  public byte[] pPublicData2;

  /**
   * Handle to the first partyâs ephemeral public key
   *
   * <PRE>
   * CK_OBJECT_HANDLE publicKey;
   * </PRE>
   */
  public long publicKey;

}
