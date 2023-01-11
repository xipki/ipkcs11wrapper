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

package org.xipki.pkcs11.attrs;

import iaik.pkcs.pkcs11.wrapper.CK_DATE;

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

/**
 * Objects of this class represent a date attribute of a PKCS#11 object
 * as specified by PKCS#11.
 *
 * @author Karl Scheibelhofer
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

      ckDate.year = Integer.toString(year).toCharArray();
      ckDate.month = (month < 10 ? "0" + month: Integer.toString(month)).toCharArray();
      ckDate.day = (day < 10 ? "0" + day: Integer.toString(day)).toCharArray();
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
    if (ckAttribute.pValue == null) return null;

    CK_DATE ckDate = (CK_DATE) ckAttribute.pValue;
    int year = Integer.parseInt(new String(ckDate.year));
    int month = Integer.parseInt(new String(ckDate.month));
    int day = Integer.parseInt(new String(ckDate.day));
    // poor performance, consider alternatives
    Calendar calendar = new GregorianCalendar();
    // calendar starts months with 0
    calendar.set(year, Calendar.JANUARY + (month - 1), day);
    return calendar.getTime();
  }

}
