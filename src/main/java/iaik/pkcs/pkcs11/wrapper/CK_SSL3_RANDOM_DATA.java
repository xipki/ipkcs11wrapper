// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class CK_SSL3_RANDOM_DATA provides information about the random data of a client and a server in
 * an SSL context. This class is used by both the CKM_SSL3_MASTER_KEY_DERIVE and the
 * CKM_SSL3_KEY_AND_MAC_DERIVE mechanisms.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_SSL3_RANDOM_DATA {
 *   CK_BYTE_PTR  pClientRandom;
 *   CK_ULONG     ulClientRandomLen;
 *   CK_BYTE_PTR  pServerRandom;
 *   CK_ULONG     ulServerRandomLen;
 * } CK_SSL3_RANDOM_DATA;
 * </PRE>
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Martin Schläffer (SIC)
 */
public class CK_SSL3_RANDOM_DATA {

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pClientRandom;
   * CK_ULONG ulClientRandomLen;
   * </PRE>
   */
  public byte[] pClientRandom;

  /**
   * <B>PKCS#11:</B>
   *
   * <PRE>
   * CK_BYTE_PTR pServerRandom;
   * CK_ULONG ulServerRandomLen;
   * </PRE>
   */
  public byte[] pServerRandom;

}
