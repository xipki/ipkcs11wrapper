// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * Logger.
 *
 * @author Lijun Liao
 */
public interface Logger {

    void info(String msg);

    void warn(String msg);

    void error(String msg);

}
