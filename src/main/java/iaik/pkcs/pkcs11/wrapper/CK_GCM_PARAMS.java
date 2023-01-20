// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * class
 * <B>PKCS#11 structure:</B>
 * <PRE>
 * typedef struct CK_GCM_PARAMS {
 *   CK_BYTE_PTR   pIv;
 *   CK_ULONG      ulIvLen;
 *   CK_BYTE_PTR   pAAD;
 *   CK_ULONG      ulAADLen;
 *   CK_ULONG      ulTagBits;
 * } CK_GCM_PARAMS;
 * </PRE>
 *
 * @author Otto Touzil (SIC)
 */
public class CK_GCM_PARAMS {

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_ULONG ulIvLen;
     * CK_BYTE_PTR pIv;
     * </PRE>
     */

    public byte[] pIv;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_ULONG ulADDLen;
     * CK_BYTE_PTR pAAD;
     * </PRE>
     */

    public byte[] pAAD;
    public long ulTagBits;

}
