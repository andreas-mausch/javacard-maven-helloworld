package helloworld.integration;

import com.licel.jcardsim.smartcardio.CardSimulator;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Reference implementation of the phone side of the secure channel (plain
 * JCE - the same primitives are available on Android). Implements the protocol
 * described in {@link helloworld.SecureChannelApplet} for both cipher suites:
 *
 * <ul>
 * <li>0x01: AES-256-GCM, AAD = header || iv.</li>
 * <li>0x02: AES-256-CBC (ISO9797-M2 padding) + HMAC-SHA-256
 * Encrypt-then-MAC over {@code aad || iv || ct}, truncated to 16
 * bytes and verified before decryption.</li>
 * </ul>
 *
 * <p>The suite is fixed at card install time; INIT echoes it back and this
 * client refuses to continue on a mismatch.
 *
 * <p>Not part of the applet; used by integration tests and as a template for
 * the mobile app.
 */
public class SecureChannelClient {

  public static final int CLA = 0x80;
  public static final int INS_INIT = 0x10;
  public static final int INS_EXCHANGE = 0x12;
  public static final int INS_SECRET_PING = 0xB0;

  public static final byte SUITE_GCM = 0x01;
  public static final byte SUITE_CBC_HMAC = 0x02;

  private static final int NONCE_LEN = 16;
  private static final int TAG_LEN = 16;
  private static final int TOKEN_PT_LEN = 16;

  private static final byte[] CONF_PT = new byte[TOKEN_PT_LEN];

  private final CardSimulator simulator;
  private final byte suite;
  private final int ivLen;
  private final int tokenCtLen;
  private final SecureRandom random = new SecureRandom();

  private final byte[] cardAid;
  private byte[] qCard;
  private byte[] nCard;
  private byte[] nPeer;
  private byte[] qPeer;
  private SecretKeySpec confKey;
  private SecretKeySpec msgKey;
  private byte[] confMacKey;
  private byte[] macKey;
  private byte[] rxPrefix;
  private byte[] txPrefix;
  private final byte[] rxSeq = new byte[8];
  private boolean established;

  public SecureChannelClient(CardSimulator simulator, byte[] appletAid,
      byte suite) {
    this.simulator = simulator;
    this.cardAid = appletAid;
    this.suite = suite;
    this.ivLen = suite == SUITE_GCM ? 12 : 16;
    this.tokenCtLen = suite == SUITE_GCM ? TOKEN_PT_LEN : 32;
  }

  /** Runs INIT + EXCHANGE and verifies the card's confirmation token. */
  public void handshake() throws Exception {
    ResponseAPDU init = transmit(new CommandAPDU(CLA, INS_INIT, 0, 0, 255));
    expectSw(init, 0x9000);
    byte[] body = startExchange(init.getData());
    ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_EXCHANGE, 0, 0, body));
    finishExchange(resp);
  }

  /**
   * Phase 1 of an exchange against the given INIT response data
   * (Q_card || N_card || suite): checks the echoed suite, derives the session
   * keys and returns the EXCHANGE command body. Split from {@link
   * #finishExchange} so tests can interleave other APDUs.
   */
  public byte[] startExchange(byte[] initData) throws Exception {
    if (initData.length != 65 + NONCE_LEN + 1) {
      throw new AssertionError(
          "unexpected INIT response length " + initData.length);
    }
    qCard = java.util.Arrays.copyOfRange(initData, 0, 65);
    nCard = java.util.Arrays.copyOfRange(initData, 65, 65 + NONCE_LEN);
    byte cardSuite = initData[65 + NONCE_LEN];
    if (cardSuite != suite) {
      throw new AssertionError("card runs suite " + cardSuite
          + " but client was built for " + suite);
    }

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair own = kpg.generateKeyPair();
    qPeer = rawPublic((ECPublicKey) own.getPublic());

    nPeer = new byte[NONCE_LEN];
    random.nextBytes(nPeer);

    byte[] z = ecdh(own.getPrivate(), qCard);
    byte[] prk = hmacFull(concat(nCard, nPeer), z);
    if (suite == SUITE_GCM) {
      confKey = new SecretKeySpec(firstBlock(prk, "SCv1-conf", 16), "AES");
      msgKey = new SecretKeySpec(firstBlock(prk, "SCv1-msg", 32), "AES");
    } else {
      confKey = new SecretKeySpec(firstBlock(prk, "SCv2-conf", 16), "AES");
      confMacKey = firstBlock(prk, "SCv2-confmac", 32);
      msgKey = new SecretKeySpec(firstBlock(prk, "SCv2-msg", 32), "AES");
      macKey = firstBlock(prk, "SCv2-mac", 32);
    }
    established = false;

    // Confirmation token bound to the transcript, direction byte 0x00.
    byte[] aad = concat(qCard, qPeer, nCard, nPeer, new byte[]{suite, 0x00});
    byte[] iv = randomIv();
    byte[] sealed = seal(confKey, confMacKey, aad, iv, CONF_PT);
    return concat(qPeer, nPeer, iv, sealed);
  }

  /**
   * Phase 2: verifies the card's confirmation token and activates the
   * session.
   */
  public void finishExchange(ResponseAPDU resp) throws Exception {
    expectSw(resp, 0x9000);
    byte[] out = resp.getData();
    if (out.length != ivLen + tokenCtLen + TAG_LEN) {
      throw new AssertionError(
          "unexpected EXCHANGE response length " + out.length);
    }
    // Verify card confirmation token (direction byte 0x01).
    byte[] aadCard = concat(qCard, qPeer, nCard, nPeer, new byte[]{suite, 0x01});
    byte[] iv = java.util.Arrays.copyOfRange(out, 0, ivLen);
    byte[] opened = open(confKey, confMacKey, aadCard, iv,
        java.util.Arrays.copyOfRange(out, ivLen, out.length));
    if (!java.util.Arrays.equals(opened, CONF_PT)) {
      throw new AssertionError("card confirmation token mismatch");
    }

    rxPrefix = java.util.Arrays.copyOfRange(nPeer, 0, 4);
    txPrefix = java.util.Arrays.copyOfRange(nCard, 0, 4);
    java.util.Arrays.fill(rxSeq, (byte) 0);
    established = true;
  }

  /**
   * Builds a protected command APDU for the given instruction: increments
   * the sequence number, so call once per command.
   */
  public CommandAPDU protect(int ins, byte[] plaintext) throws Exception {
    if (!established) {
      throw new IllegalStateException("session not established");
    }
    increment(rxSeq);
    byte[] iv = ivFor(rxPrefix, rxSeq);
    int ctLen = suite == SUITE_GCM ? plaintext.length : padLen(plaintext.length);
    byte[] header = new byte[]{(byte) CLA, (byte) ins, 0, 0, (byte) (ivLen + ctLen + TAG_LEN)};
    // GCM binds the iv through the AAD; CBC binds it inside the MAC input.
    byte[] aad = suite == SUITE_GCM ? concat(header, iv) : header;
    byte[] sealed = seal(msgKey, macKey, aad, iv, plaintext);
    return new CommandAPDU(CLA, ins, 0, 0, concat(iv, sealed));
  }

  /** Decrypts and authenticates the response of a protected command. */
  public byte[] open(int ins, ResponseAPDU response) throws Exception {
    byte[] data = response.getData();
    if (data.length < ivLen + TAG_LEN) {
      throw new AssertionError("response too short");
    }
    byte[] iv = java.util.Arrays.copyOfRange(data, 0, ivLen);
    if (!java.util.Arrays.equals(
        java.util.Arrays.copyOfRange(iv, 0, 4), txPrefix)) {
      throw new AssertionError("response IV carries wrong session prefix");
    }
    // The card binds responses as INS || iv (GCM AAD) or INS (CBC, the iv is
    // inside the MAC input).
    byte[] body = java.util.Arrays.copyOfRange(data, ivLen, data.length);
    byte[] aad = suite == SUITE_GCM
        ? concat(new byte[]{(byte) ins}, iv)
        : new byte[]{(byte) ins};
    return open(msgKey, macKey, aad, iv, body);
  }

  public ResponseAPDU transmit(CommandAPDU apdu) {
    return simulator.transmitCommand(apdu);
  }

  public boolean isEstablished() {
    return established;
  }

  public byte getSuite() {
    return suite;
  }

  /** Convenience: select this client's applet. */
  public void select() {
    expectSw(transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, cardAid)),
        0x9000);
  }

  // --- seal/open dispatch (mirror of the card's seal()/openMsg()) ----------

  /** Returns ct || tag(16) for the active suite (iv is the caller's job). */
  private byte[] seal(SecretKeySpec encKey, byte[] macKeyBytes, byte[] aad,
      byte[] iv, byte[] plaintext) throws Exception {
    if (suite == SUITE_GCM) {
      return gcmEncrypt(encKey, iv, aad, plaintext);
    }
    byte[] ct = cbcEncrypt(encKey, iv, padM2(plaintext));
    return concat(ct, hmac(macKeyBytes, concat(aad, iv, ct)));
  }

  /** Input is ct || tag(16); returns the plaintext (padding stripped). */
  private byte[] open(SecretKeySpec encKey, byte[] macKeyBytes, byte[] aad,
      byte[] iv, byte[] ctAndTag) throws Exception {
    if (suite == SUITE_GCM) {
      return gcmDecrypt(encKey, iv, aad, ctAndTag);
    }
    byte[] ct = java.util.Arrays.copyOfRange(ctAndTag, 0,
        ctAndTag.length - TAG_LEN);
    byte[] wireMac = java.util.Arrays.copyOfRange(ctAndTag,
        ctAndTag.length - TAG_LEN, ctAndTag.length);
    // Encrypt-then-MAC: verify before decrypting.
    byte[] computed = hmac(macKeyBytes, concat(aad, iv, ct));
    if (!java.util.Arrays.equals(computed, wireMac)) {
      throw new AssertionError("CBC-HMAC tag mismatch");
    }
    return unpadM2(cbcDecrypt(encKey, iv, ct));
  }

  // --- suite 2 helpers ------------------------------------------------------

  /** ISO9797 padding method 2: 0x80 followed by zeros to the block size. */
  static byte[] padM2(byte[] pt) {
    byte[] out = java.util.Arrays.copyOf(pt, padLen(pt.length));
    out[pt.length] = (byte) 0x80;
    return out;
  }

  /** Padded length under M2 (always adds at least one byte). */
  static int padLen(int n) {
    return n + 16 - (n % 16);
  }

  static byte[] unpadM2(byte[] padded) {
    int i = padded.length - 1;
    while (i >= 0 && padded[i] == 0) {
      i--;
    }
    if (i < 0 || padded[i] != (byte) 0x80) {
      throw new AssertionError("invalid ISO9797-M2 padding");
    }
    return java.util.Arrays.copyOf(padded, i);
  }

  // --- crypto helpers ---------------------------------------------------------

  private static byte[] ecdh(PrivateKey priv, byte[] peerRaw) throws Exception {
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    ka.init(priv);
    ka.doPhase(parsePublic(peerRaw), true);
    return ka.generateSecret();
  }

  private static ECPublicKey parsePublic(byte[] raw) throws Exception {
    if (raw.length != 65 || raw[0] != 0x04) {
      throw new IllegalArgumentException("expected uncompressed EC point");
    }
    AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
    params.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec curve = params.getParameterSpec(ECParameterSpec.class);
    BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(raw, 1, 33));
    BigInteger y = new BigInteger(1, java.util.Arrays.copyOfRange(raw, 33, 65));
    return (ECPublicKey) KeyFactory.getInstance("EC")
        .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), curve));
  }

  private static byte[] rawPublic(ECPublicKey pub) {
    byte[] out = new byte[65];
    out[0] = 0x04;
    fixed32(pub.getW().getAffineX(), out, 1);
    fixed32(pub.getW().getAffineY(), out, 33);
    return out;
  }

  private static void fixed32(BigInteger v, byte[] out, int off) {
    byte[] b = v.toByteArray();
    if (b.length == 33 && b[0] == 0) {
      System.arraycopy(b, 1, out, off, 32);
    } else if (b.length == 32) {
      System.arraycopy(b, 0, out, off, 32);
    } else {
      System.arraycopy(b, 0, out, off + 32 - b.length, b.length);
    }
  }

  /** HMAC-SHA-256, result truncated to TAG_LEN bytes. */
  private static byte[] hmac(byte[] key, byte[] msg) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    return java.util.Arrays.copyOf(mac.doFinal(msg), TAG_LEN);
  }

  /** HKDF-Extract: PRK = HMAC-SHA-256(key = salt, msg = ikm), full 32 B. */
  private static byte[] hmacFull(byte[] key, byte[] msg) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    return mac.doFinal(msg);
  }

  /** HKDF-Expand single block: HMAC-SHA-256(key = prk, info || 0x01). */
  private static byte[] firstBlock(byte[] prk, String label, int outLen)
      throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(prk, "HmacSHA256"));
    mac.update(label.getBytes("ASCII"));
    mac.update((byte) 0x01);
    return java.util.Arrays.copyOf(mac.doFinal(), outLen);
  }

  private static byte[] cbcEncrypt(SecretKeySpec key, byte[] iv, byte[] padded)
      throws Exception {
    Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
    return c.doFinal(padded);
  }

  private static byte[] cbcDecrypt(SecretKeySpec key, byte[] iv, byte[] ct)
      throws Exception {
    Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
    c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
    return c.doFinal(ct);
  }

  private static byte[] gcmEncrypt(SecretKeySpec key, byte[] iv, byte[] aad,
      byte[] plaintext) throws Exception {
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
    c.updateAAD(aad);
    return c.doFinal(plaintext); // ct || tag
  }

  private static byte[] gcmDecrypt(SecretKeySpec key, byte[] iv, byte[] aad,
      byte[] ctAndTag) throws Exception {
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
    c.updateAAD(aad);
    return c.doFinal(ctAndTag);
  }

  private byte[] randomIv() {
    byte[] iv = new byte[ivLen];
    random.nextBytes(iv);
    return iv;
  }

  /** iv = prefix || seq, zero-padded to 16 bytes for CBC. */
  private byte[] ivFor(byte[] prefix, byte[] seq) {
    byte[] iv = new byte[ivLen];
    System.arraycopy(prefix, 0, iv, 0, 4);
    System.arraycopy(seq, 0, iv, 4, 8);
    return iv;
  }

  private static void increment(byte[] counter) {
    for (int i = counter.length - 1; i >= 0; i--) {
      int v = counter[i] & 0xFF;
      if (v < 0xFF) {
        counter[i]++;
        return;
      }
      counter[i] = 0;
    }
  }

  private static byte[] concat(byte[]... parts) {
    int len = 0;
    for (byte[] p : parts) {
      len += p.length;
    }
    byte[] out = new byte[len];
    int off = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, off, p.length);
      off += p.length;
    }
    return out;
  }

  private static void expectSw(ResponseAPDU resp, int sw) {
    if (resp.getSW() != sw) {
      throw new AssertionError(
          "expected SW " + Integer.toHexString(sw) + " but got "
              + Integer.toHexString(resp.getSW()));
    }
  }
}
