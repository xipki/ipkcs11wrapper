// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from this
//    software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.xipki.pkcs11.parameters;

import iaik.pkcs.pkcs11.wrapper.CK_GCM_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the AES-GCM en/decryption.
 *
 * @author Otto Touzil
 * @author Lijun Liao (xipki)
 */
public class GcmParameters implements Parameters {

    private byte[] iv;
    private byte[] aad;
    private int tagBits;

    /**
     * Create a new GCMParameters object with the given attributes.
     *
     * @param iv       Initialization vector
     * @param aad      additional authentication data. This data is authenticated but not encrypted.
     * @param tagBits length of authentication tag (output following ciphertext) in bits. (0 - 128)
     *                  depending on the algorithm implementation within the hsm, ulTagBits may be any
     *                  one of the following five values: 128, 120, 112, 104, or 96, may be 64 or 32;
     */
    public GcmParameters(byte[] iv, byte[] aad, int tagBits) {
        this.iv = Functions.requireNonNull("iv", iv);
        this.tagBits = Functions.requireRange("tagBits", tagBits, 0, 128);
        this.aad = aad;
    }

  /**
     * Get this parameters object as an object of the CK_GCM_PARAMS class.
     *
     * @return This object as a CK_GCM_PARAMS object.
     */
    public CK_GCM_PARAMS getPKCS11ParamsObject() {
        CK_GCM_PARAMS params = new CK_GCM_PARAMS();
        params.pIv = iv;
        params.pAAD = aad;
        params.ulTagBits = tagBits;

        return params;
    }

    /**
     * Returns the string representation of this object. Do not parse data from this string, it is for
     * debugging only.
     *
     * @return A string representation of this object.
     */
    public String toString() {
        return "Class: " + getClass().getName() + "\n   IV: " + Functions.toHex(iv) +
            "\n  AAD: " + (aad == null ? " " : Functions.toHex(aad)) + "\n   TagBits: " + tagBits;
    }

}

