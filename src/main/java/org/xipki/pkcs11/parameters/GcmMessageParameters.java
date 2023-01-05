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

import iaik.pkcs.pkcs11.wrapper.CK_GCM_MESSAGE_PARAMS;
import org.xipki.pkcs11.Functions;

/**
 * This class encapsulates parameters for the AES-GCM en/decryption.
 *
 * @author Otto Touzil
 * @version 1.0
 */
public class GcmMessageParameters implements Parameters, MessageParameters {

    private byte[] iv;
    private long ivFixedBits;
    private long ivGenerator;
    private byte[] tag;

    /**
     * Create a new GCMParameters object with the given attributes.
     *
     * @param iv Initialization vector
     * @param ivFixedBits number of bits of the original IV to preserve when generating an <br>
     *                      new IV. These bits are counted from the Most significant bits (to the right).
     * @param ivGenerator Function used to generate a new IV. Each IV must be unique for a given session.
     * @param tag ocation of the authentication tag which is returned on MessageEncrypt, and provided on MessageDecrypt.
     */
    public GcmMessageParameters(byte[] iv, long ivFixedBits, long ivGenerator, byte[] tag) {
        init(iv, ivFixedBits, ivGenerator, tag);
    }

    private void init(byte[] iv, long ivFixedBits, long ivGenerator, byte[] tag) {
        this.iv = Functions.requireNonNull("pIV", iv);
        this.ivFixedBits = ivFixedBits;
        this.ivGenerator = ivGenerator;
        this.tag = tag;
    }

    /**
     * Get this parameters object as an object of the CK_ECDH1_DERIVE_PARAMS class.
     *
     * @return This object as a CK_ECDH1_DERIVE_PARAMS object.
     * @postconditions (result != null)
     */
    public Object getPKCS11ParamsObject() {
        CK_GCM_MESSAGE_PARAMS params = new CK_GCM_MESSAGE_PARAMS();
        params.pIv = iv;
        params.ulIvFixedBits = ivFixedBits;
        params.ivGenerator = ivGenerator;
        params.pTag = tag;

        return params;
    }

    /**
     * Read the parameters from the PKCS11Object and overwrite the values into this object.
     *
     * @param obj Object to read the parameters from
     */
    public void setValuesFromPKCS11Object(Object obj) {
        CK_GCM_MESSAGE_PARAMS params = (CK_GCM_MESSAGE_PARAMS) obj;
        init(params.pIv, params.ulIvFixedBits, params.ivGenerator, params.pTag);
    }

    /**
     * Returns the string representation of this object. Do not parse data from this string, it is for
     * debugging only.
     *
     * @return A string representation of this object.
     */
    public String toString() {
        return "Class: " + getClass().getName() + "\n  IV: " + Functions.toHex(iv) +
            "\n  Tag: " + Functions.toHex(tag) + "\n  ivGenerator: " + ivGenerator + "\n  IVFixedBits: " + ivFixedBits;
    }

}

