// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

/**
 * Logger.
 *
 * @author Lijun Liao
 */
public interface Logger {

    void info(String format, Object... arguments);

    void warn(String format, Object... arguments);

    void error(String format, Object... arguments);

    void debug(String format, Object... arguments);

    boolean isDebugEnabled();

    boolean isInfoEnabled();

    boolean isWarnEnabled();

}
