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

package demo.pkcs.pkcs11.wrapper.basics;

import demo.pkcs.pkcs11.wrapper.TestBase;
import org.junit.Test;
import org.xipki.pkcs11.*;

import static org.xipki.pkcs11.PKCS11Constants.CKF_TOKEN_INITIALIZED;
import static org.xipki.pkcs11.PKCS11Constants.ckmCodeToName;

/**
 * This demo program lists information about a library, the available slots, the
 * available tokens and the objects on them. It takes the name of the module and
 * the absolute path to the shared library of the IAIK PKCS#11 Wrapper and
 * prompts the user PIN. If the user PIN is not available, the program will list
 * only public objects but no private objects; i.e. as defined in PKCS#11 for
 * public read-only sessions.
 */
public class GetInfo extends TestBase {

  @Test
  public void main() throws PKCS11Exception {
    PKCS11Module pkcs11Module = getModule();
    ModuleInfo moduleInfo = pkcs11Module.getInfo();
    LOG.info("##################################################");
    LOG.info("{}", moduleInfo);
    LOG.info("##################################################");
    LOG.info("getting list of all slots");
    Slot[] slots = pkcs11Module.getSlotList(false);

    for (Slot slot : slots) {
      LOG.info("___________________________________________________");
      SlotInfo slotInfo = slot.getSlotInfo();
      LOG.info("Slot with ID: {}", slot.getSlotID());
      LOG.info("--------------------------------------------------");
      LOG.info("{}", slotInfo);
      LOG.info("___________________________________________________");
    }

    LOG.info("##################################################");
    LOG.info("getting list of all tokens");
    Slot[] slotsWithToken = pkcs11Module.getSlotList(true);
    Token[] tokens = new Token[slotsWithToken.length];

    for (int i = 0; i < slotsWithToken.length; i++) {
      LOG.info("___________________________________________________");
      tokens[i] = slotsWithToken[i].getToken();
      TokenInfo tokenInfo = tokens[i].getTokenInfo();
      LOG.info("Token in slot with ID: {}", tokens[i].getSlot().getSlotID());
      LOG.info("--------------------------------------------------");
      LOG.info("{}", tokenInfo);

      LOG.info("supported Mechanisms:");
      long[] supportedMechanisms = tokens[i].getMechanismList();
      for (long supportedMechanism : supportedMechanisms) {
        LOG.info("--------------------------------------------------");
        LOG.info("Mechanism Name: {}", ckmCodeToName(supportedMechanism));
        MechanismInfo mechanismInfo = tokens[i].getMechanismInfo(supportedMechanism);
        LOG.info("{}", mechanismInfo);
        LOG.info("--------------------------------------------------");
      }
      LOG.info("___________________________________________________");
    }

    LOG.info("##################################################");
    LOG.info("listing objects on tokens");
    for (Token token : tokens) {
      LOG.info("___________________________________________________");
      TokenInfo tokenInfo = token.getTokenInfo();
      LOG.info("listing objects for token: {}", tokenInfo);
      if (!tokenInfo.hasFlagBit(CKF_TOKEN_INITIALIZED)) {
        LOG.info("token not initialized yet");
        continue;
      }

      Session session = openReadOnlySession(token);
      try {
        main0(session);
      } finally {
        session.closeSession();
      }
    }
  }

  private void main0(Session session) throws PKCS11Exception {
    SessionInfo sessionInfo = session.getSessionInfo();
    LOG.info("using session: {}", sessionInfo);

    int limit = 0, counter = 0;

    session.findObjectsInit(null);
    long[] objects = session.findObjects(1);
    if (0 < objects.length) {
      counter++;
    }

    while (objects.length > 0 && (0 == limit || counter < limit)) {
      long object = objects[0];
      LOG.info("--------------------------------------------------");
      LOG.info("Object with handle: {}", object);
      LOG.info("--------------------------------------------------");
      objects = session.findObjects(1);
      counter++;
    }
    session.findObjectsFinal();

    LOG.info("___________________________________________________");
    LOG.info("found {} objects on this token", counter);
    LOG.info("___________________________________________________");
  }
}
