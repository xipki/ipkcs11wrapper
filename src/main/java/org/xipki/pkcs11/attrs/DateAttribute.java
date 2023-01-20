// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// License IAIK PKCS#11 Wrapper License.
//
// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.attrs;

import iaik.pkcs.pkcs11.wrapper.CK_DATE;

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

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
   */
  public DateAttribute dateValue(Date value) {
    if (value == null) {
      ckAttribute.pValue = null;
    } else {
      //poor memory/performance behavior, consider alternatives
      Calendar calendar = new GregorianCalendar();
      calendar.setTime(value);
      int year = calendar.get(Calendar.YEAR);
      // month counting starts with zero
      int month = calendar.get(Calendar.MONTH) + 1;
      int day = calendar.get(Calendar.DAY_OF_MONTH);

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
  public Date getValue() {
    if (isNullValue()) {
      return null;
    }

    CK_DATE ckDate = (CK_DATE) ckAttribute.pValue;
    int year  = Integer.parseInt(new String(ckDate.year));
    int month = Integer.parseInt(new String(ckDate.month));
    int day   = Integer.parseInt(new String(ckDate.day));
    // poor performance, consider alternatives
    Calendar calendar = new GregorianCalendar();
    // calendar starts months with 0
    calendar.set(year, Calendar.JANUARY + (month - 1), day);
    return calendar.getTime();
  }

}
