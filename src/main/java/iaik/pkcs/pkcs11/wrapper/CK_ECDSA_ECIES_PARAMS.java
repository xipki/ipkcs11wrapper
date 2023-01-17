// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * The class CK_ECDSA_ECIES_PARAMS provides the parameters to the CKM_ECDSA_ECIES
 * mechanism.
 * <p>
 * <B>PKCS#11 structure:</B>
 *
 * <PRE>
 * typedef struct CK_ECDSA_ECIES_PARAMS // used by CKM_ECDSA_ECIES
 * {
 *     unsigned long int  hashAlg;          // hash algorithm used e.g. CKM_SHA_1
 *     unsigned long int  cryptAlg;         // crypt algorithm used for crypt/decrypt e.g. CKM_AES_ECB
 *     unsigned long int  cryptOpt;         // keysize of crypt algo (0 for CKM_ECDSA_ECIES_XOR)
 *     unsigned long int  macAlg;           // mac algorithm used e.g. CKM_SHA_1_HMAC
 *     unsigned long int  macOpt;           // keysize of mac algo (always 0)
 *     unsigned char     *pSharedSecret1;   // optional shared secret 1 included in hash calculation
 *     unsigned long int  ulSharetSecret1;  // length of shared secret 1
 *     unsigned char     *pSharedSecret2;   // optional shared secret 2 included in mac calculation
 *     unsigned long int  ulSharetSecret2;  // lentgh of shared secret 2
 * }
 * </PRE>
 *
 * @author Otto Touzil (SIC)
 */
public class CK_ECDSA_ECIES_PARAMS {

    public long hashAlg;
    public long cryptAlg;
    public long cryptOpt;
    public long macAlg;
    public long macOpt;

    /**
     * optional shared secret 1 included in hash calculation.
     *
     * <B>PKCS#11:</B>
     *
     * <PRE>
     *  unsigned char     *pSharedSecret1;   // optional shared secret 1 included in hash calculation
     *  unsigned long int  ulSharetSecret1;  // length of shared secret 1
     * </PRE>
     *
     */
    public byte[] pSharedSecret1;

    /**
     * optional shared secret 2 included in hash calculation.
     *
     * <B>PKCS#11:</B>
     *
     * <PRE>
     *  unsigned char     *pSharedSecret2;   // optional shared secret 1 included in hash calculation
     *  unsigned long int  ulSharetSecret2;  // length of shared secret 1
     * </PRE>
     *
     */
    public byte[] pSharedSecret2;

}
