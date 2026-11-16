package helloworld.integration;

import com.licel.jcardsim.smartcardio.CardSimulator;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Reference implementation of the phone side of the secure channel (plain
 * JCE - the same primitives are available on Android). Implements the protocol
 * described in {@link helloworld.SecureChannelApplet}.
 *
 * <p>Not part of the applet; used by integration tests and as a template for
 * the mobile app.
 */
public class SecureChannelClient {

  public static final int CLA = 0x80;
  public static final int INS_INIT = 0x10;
  public static final int INS_EXCHANGE = 0x12;
  public static final int INS_SECRET_PING = 0xB0;

  private static final int NONCE_LEN = 16;
  private static final int IV_LEN = 12;
  private static final int TAG_LEN = 16;
  private static final int TOKEN_PT_LEN = 16;

  private static final byte[] LABEL_CONF = "SCv1-conf".getBytes();
  private static final byte[] LABEL_MSG = "SCv1-msg".getBytes();
  private static final byte[] CONF_PT = new byte[TOKEN_PT_LEN];

  private final CardSimulator simulator;
  private final SecureRandom random = new SecureRandom();

  private byte[] cardAid;
  private byte[] qCard;
  private byte[] nCard;
  private byte[] nPeer;
  private byte[] qPeer;
  private SecretKeySpec confKey;
  private SecretKeySpec msgKey;
  private byte[] rxPrefix;
  private byte[] txPrefix;
  private final byte[] rxSeq = new byte[8];
  private boolean established;

  public SecureChannelClient(CardSimulator simulator, byte[] appletAid) {
    this.simulator = simulator;
    this.cardAid = appletAid;
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
   * (Q_card || N_card): derives the session keys and returns the EXCHANGE
   * command body. Split from {@link #finishExchange} so tests can interleave
   * other APDUs.
   */
  public byte[] startExchange(byte[] initData) throws Exception {
    if (initData.length != 65 + NONCE_LEN) {
      throw new AssertionError("unexpected INIT response length " + initData.length);
    }
    qCard = java.util.Arrays.copyOfRange(initData, 0, 65);
    nCard = java.util.Arrays.copyOfRange(initData, 65, 65 + NONCE_LEN);

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair own = kpg.generateKeyPair();
    qPeer = rawPublic((ECPublicKey) own.getPublic());

    nPeer = new byte[NONCE_LEN];
    random.nextBytes(nPeer);

    byte[] z = ecdh(own.getPrivate(), qCard);

    byte[] salt = concat(nCard, nPeer);
    byte[] prk = hmac(salt, z);
    confKey = new SecretKeySpec(firstBlock(prk, LABEL_CONF, 16), "AES");
    msgKey = new SecretKeySpec(firstBlock(prk, LABEL_MSG, 32), "AES");
    established = false;

    // Confirmation token bound to the transcript, direction byte 0x00.
    byte[] aad = aad(qCard, qPeer, nCard, nPeer, (byte) 0x00);
    byte[] iv = randomIv();
    byte[] ctAndTag = gcmEncrypt(confKey, iv, aad, CONF_PT);
    return concat(qPeer, nPeer, iv, ctAndTag);
  }

  /** Phase 2: verifies the card's confirmation token and activates the session. */
  public void finishExchange(ResponseAPDU resp) throws Exception {
    expectSw(resp, 0x9000);
    byte[] out = resp.getData();
    if (out.length != IV_LEN + TOKEN_PT_LEN + TAG_LEN) {
      throw new AssertionError("unexpected EXCHANGE response length " + out.length);
    }
    // Verify card confirmation token (direction byte 0x01).
    byte[] aadCard = aad(qCard, qPeer, nCard, nPeer, (byte) 0x01);
    byte[] cardIv = java.util.Arrays.copyOfRange(out, 0, IV_LEN);
    byte[] opened = gcmDecrypt(confKey, cardIv, aadCard,
        java.util.Arrays.copyOfRange(out, IV_LEN, out.length));
    if (!java.util.Arrays.equals(opened, CONF_PT)) {
      throw new AssertionError("card confirmation token mismatch");
    }

    rxPrefix = java.util.Arrays.copyOfRange(nPeer, 0, 4);
    txPrefix = java.util.Arrays.copyOfRange(nCard, 0, 4);
    java.util.Arrays.fill(rxSeq, (byte) 0);
    established = true;
  }

  /**
   * Builds a protected command APDU for the given instruction: increments the
   * sequence number, so call once per command.
   */
  public CommandAPDU protect(int ins, byte[] plaintext) throws Exception {
    increment(rxSeq);
    byte[] iv = concat(rxPrefix, rxSeq);
    int lc = IV_LEN + plaintext.length + TAG_LEN;
    byte[] aad = aad((byte) CLA, (byte) ins, (byte) 0, (byte) 0, (byte) lc, iv);
    byte[] ctAndTag = gcmEncrypt(msgKey, iv, aad, plaintext);
    return new CommandAPDU(CLA, ins, 0, 0, concat(iv, ctAndTag));
  }

  /** Decrypts and authenticates the response of a protected command. */
  public byte[] open(int ins, ResponseAPDU response) throws Exception {
    byte[] data = response.getData();
    if (data.length < IV_LEN + TAG_LEN) {
      throw new AssertionError("response too short");
    }
    byte[] iv = java.util.Arrays.copyOfRange(data, 0, IV_LEN);
    if (!java.util.Arrays.equals(java.util.Arrays.copyOfRange(iv, 0, 4), txPrefix)) {
      throw new AssertionError("response IV carries wrong session prefix");
    }
    byte[] aad = aad((byte) ins, iv);
    return gcmDecrypt(msgKey, iv, aad,
        java.util.Arrays.copyOfRange(data, IV_LEN, data.length));
  }

  public ResponseAPDU transmit(CommandAPDU apdu) {
    return simulator.transmitCommand(apdu);
  }

  public boolean isEstablished() {
    return established;
  }

  /** Convenience: select this client's applet. */
  public void select() {
    expectSw(transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, cardAid)), 0x9000);
  }

  // --- crypto helpers (mirror the card, see protocol docs) -----------------

  private static byte[] ecdh(java.security.PrivateKey priv, byte[] peerRaw)
      throws Exception {
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
      // left-pad shorter values
      System.arraycopy(b, 0, out, off + 32 - b.length, b.length);
    }
  }

  /** HKDF-Extract: PRK = HMAC-SHA-256(key = salt, msg = ikm). */
  private static byte[] hmac(byte[] key, byte[] msg) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    return mac.doFinal(msg);
  }

  /** HKDF-Expand single block: HMAC-SHA-256(key = prk, info || 0x01). */
  private static byte[] firstBlock(byte[] prk, byte[] label, int outLen)
      throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(prk, "HmacSHA256"));
    mac.update(label);
    mac.update((byte) 0x01);
    return java.util.Arrays.copyOf(mac.doFinal(), outLen);
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
    byte[] iv = new byte[IV_LEN];
    random.nextBytes(iv);
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

  private static byte[] aad(Object... parts) {
    int len = 0;
    for (Object p : parts) {
      len += p instanceof Byte ? 1 : ((byte[]) p).length;
    }
    byte[] out = new byte[len];
    int off = 0;
    for (Object p : parts) {
      if (p instanceof Byte) {
        out[off++] = (Byte) p;
      } else {
        byte[] b = (byte[]) p;
        System.arraycopy(b, 0, out, off, b.length);
        off += b.length;
      }
    }
    return out;
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
