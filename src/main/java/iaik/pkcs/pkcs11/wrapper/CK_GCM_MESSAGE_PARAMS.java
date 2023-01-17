// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.

package iaik.pkcs.pkcs11.wrapper;

/**
 * <B>PKCS#11 structure:</B>
 * <PRE>
 * typedef struct CK_GCM_MESSAGE_PARAMS {
 * CK_BYTE_PTR       pIv;
 * CK_ULONG          ulIvLen;
 * CK_ULONG          ulIvFixedBits;
 * CK_GENERATOR_FUNCTION ivGenerator;
 * CK_BYTE_PTR       pTag;
 * CK_ULONG          ulTagBits;
 * } CK_GCM_MESSAGE_PARAMS;
 * </PRE>
 *
 * @author Patrick Schuster (SIC)
 */
public class CK_GCM_MESSAGE_PARAMS {

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_BYTE_PTR pIv;
     * CK_ULONG ulIvLen;
     * </PRE>
     */

    public byte[] pIv;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_ULONG ulIvFixedBits;
     * </PRE>
     */
    public long ulIvFixedBits;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_GENERATOR_FUNCTION ivGenerator;
     * </PRE>
     */
    public long ivGenerator;

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     * CK_BYTE_PTR pTag;
     * CK_ULONG ulTagBits;
     * </PRE>
     */
    public byte[] pTag;

}
