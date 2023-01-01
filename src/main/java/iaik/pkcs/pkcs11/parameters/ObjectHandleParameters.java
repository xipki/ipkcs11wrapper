// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
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
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
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

package iaik.pkcs.pkcs11.parameters;

/**
 * This class encapsulates parameters for Mechanisms.CONCATENATE_BASE_AND_KEY.
 *
 * @author Karl Scheibelhofer
 * @version 1.0
 */
public class ObjectHandleParameters implements Parameters {

  /**
   * The PKCS#11 object.
   */
  protected long objectHandle;

  /**
   * Create a new ObjectHandleParameters object using the given object.
   *
   * @param object
   *          The PKCS#11 object whose handle to use.
   */
  public ObjectHandleParameters(long object) {
    this.objectHandle = object;
  }

  /**
   * Get this parameters object as a Long object, which is the handle of the
   * underlying object.
   *
   * @return This object as a Long object.
   */
  @Override
  public Long getPKCS11ParamsObject() {
    return objectHandle;
  }

  /**
   * Get the PKCS#11 object.
   *
   * @return The PKCS#11 object.
   */
  public long getObjectHandle() {
    return objectHandle;
  }

  /**
   * Set the PKCS#11 object.
   *
   * @param objectHandle
   *          The PKCS#11 object.
   */
  public void setObjectHandle(long objectHandle) {
    this.objectHandle = objectHandle;
  }

  /**
   * Returns the string representation of this object. Do not parse data from
   * this string, it is for debugging only.
   *
   * @return A string representation of this object.
   */
  @Override
  public String toString() {
    return "  The PKCS11Object: " + objectHandle;
  }

  /**
   * Compares all member variables of this object with the other object.
   * Returns only true, if all are equal in both objects.
   *
   * @param otherObject
   *          The other object to compare to.
   * @return True, if other is an instance of this class and all member
   *         variables of both objects are equal. False, otherwise.
   */
  @Override
  public boolean equals(Object otherObject) {
    if (this == otherObject) return true;
    else if (!(otherObject instanceof ObjectHandleParameters)) return false;

    ObjectHandleParameters other = (ObjectHandleParameters) otherObject;
    return objectHandle == other.objectHandle;
  }

  /**
   * The overriding of this method should ensure that the objects of this
   * class work correctly in a hashtable.
   *
   * @return The hash code of this object.
   */
  @Override
  public int hashCode() {
    return Long.hashCode(objectHandle);
  }

}
