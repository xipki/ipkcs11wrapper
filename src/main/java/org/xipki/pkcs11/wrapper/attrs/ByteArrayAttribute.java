// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Constants;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Objects of this class represent a byte-array attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class ByteArrayAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_VALUE.
   */
  public ByteArrayAttribute(long type) {
    super(type);
  }

  /**
   * Set the byte-array value of this attribute. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The byte-array value to set. May be null.
   * @return a reference to this object.
   */
  public ByteArrayAttribute byteArrayValue(byte[] value) {
    ckAttribute.pValue = value;
    present = true;
    return this;
  }

  /**
   * Set the big integer value whose unsigned byte-array representation is
   * the content of this attribute. Null, is also valid. A call to this
   * method sets the present flag to true.
   *
   * @param value
   *          The byte-array value to set. May be null.
   * @return a reference to this object.
   */
  public ByteArrayAttribute bigIntValue(BigInteger value) {
    return byteArrayValue(value == null ? null : Functions.asUnsignedByteArray(value));
  }

  /**
   * Get the byte-array value of this attribute. Null, is also possible.
   *
   * @return The byte-array value of this attribute or null.
   */
  @Override
  public byte[] getValue() {
    return (byte[]) ckAttribute.pValue;
  }

  public BigInteger getBigIntValue() {
    return isNullValue() ? null : new BigInteger(1, (byte[]) ckAttribute.pValue);
  }

  public BigInteger getSignedBigIntValue() {
    return isNullValue() ? null : new BigInteger((byte[]) ckAttribute.pValue);
  }

  /**
   * Get a string representation of the value of this attribute.
   *
   * @return A string representation of the value of this attribute.
   */
  @Override
  protected String getValueString() {
    if (isNullValue()) {
      return "<NULL_PTR>";
    }

    byte[] value = (byte[]) ckAttribute.pValue;
    String text = "byte[" + value.length + "]\n" + Functions.toString("    ", value);
    if (type() != PKCS11Constants.CKA_EC_PARAMS) {
      return text;
    }

    try {
      String[] curveNames = Functions.getCurveNames(value);
      String curveOid = Functions.decodeOid(value);
      return text + "(" + curveOid + ", " + Arrays.toString(curveNames) + ")";
    } catch (Exception e) {
      return text;
    }
  }

}
