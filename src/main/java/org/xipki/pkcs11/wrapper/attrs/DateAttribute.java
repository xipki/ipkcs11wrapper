// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import iaik.pkcs.pkcs11.wrapper.CK_DATE;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

/**
 * Objects of this class represent a date attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Karl Scheibelhofer (SIC)
 * @author Lijun Liao (xipki)
 */
public class DateAttribute extends Attribute {

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   *
   * @param type
   *          The PKCS#11 type of this attribute; e.g. CKA_START_DATE.
   */
  public DateAttribute(long type) {
    super(type);
  }

  /**
   * Set the date value of this attribute. Null, is also valid.
   * A call to this method sets the present flag to true.
   *
   * @param value
   *          The date value to set. May be null.
   * @return a reference to this object.
   */
  public DateAttribute dateValue(Instant value) {
    if (value == null) {
      ckAttribute.pValue = null;
    } else {
      //poor memory/performance behavior, consider alternatives
      ZonedDateTime utcTime = ZonedDateTime.ofInstant(value, ZoneOffset.UTC);
      int year = utcTime.getYear();
      int month = utcTime.getMonthValue();
      int day = utcTime.getDayOfMonth();

      CK_DATE ckDate = new CK_DATE();
      ckAttribute.pValue = ckDate;

      ckDate.year  = Integer.toString(year).toCharArray();
      ckDate.month = (month < 10 ? "0" + month: Integer.toString(month)).toCharArray();
      ckDate.day   = (  day < 10 ? "0" +   day: Integer.toString(day)).toCharArray();
    }
    present = true;
    return this;
  }

  /**
   * Get the date value of this attribute. Null, is also possible.
   *
   * @return The date value of this attribute or null.
   */
  @Override
  public Instant getValue() {
    if (isNullValue()) {
      return null;
    }

    CK_DATE ckDate = (CK_DATE) ckAttribute.pValue;
    int year  = Integer.parseInt(new String(ckDate.year));
    int month = Integer.parseInt(new String(ckDate.month));
    int day   = Integer.parseInt(new String(ckDate.day));
    return ZonedDateTime.of(year, month, day, 0, 0, 0, 0, ZoneOffset.UTC).toInstant();
  }

  @Override
  protected String getValueString() {
    if (isNullValue()) {
      return "<NULL_PTR>";
    } else {
      CK_DATE ckDate = (CK_DATE) ckAttribute.pValue;
      return new String(ckDate.year) + "." + new String(ckDate.month) + "." + new String(ckDate.day);
    }
  }

}
