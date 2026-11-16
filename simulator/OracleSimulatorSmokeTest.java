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
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

/**
 * End-to-end smoke test for SecureChannelApplet against a real card reader,
 * typically the Oracle Java Card simulator inside the docker-javacard image.
 * Runs the same scenario against both cipher-suite instances:
 * ...0507 = suite 0x01 (AES-256-GCM), ...0508 = suite 0x02
 * (AES-256-CBC + HMAC-SHA-256 Encrypt-then-MAC).
 *
 * <p>Compile and run with any JDK 11+ (javax.smartcardio and JCE are part of
 * the JDK - no BouncyCastle needed, the ISO9797-M2 padding is done by hand).
 * See simulator/run.sh. Exits non-zero on failure.
 */
public class OracleSimulatorSmokeTest {

  static final int SW_OK = 0x9000;
  static final int SW_SECURE = 0x6982;
  static final byte INS_PING = (byte) 0xB0;

  static CardChannel channel;
  static int passed = 0;
  static int failed = 0;

  static final byte[] AID_HELLO = {1, 2, 3, 4, 5, 6};
  static final byte[] AID_GCM = {1, 2, 3, 4, 5, 7};
  static final byte[] AID_CBC = {1, 2, 3, 4, 5, 8};

  public static void main(String[] args) throws Exception {
    Card card = firstTerminal().connect("*");
    channel = card.getBasicChannel();
    System.out.println("Connected, ATR=" + bytesToHex(card.getATR().getBytes()));

    // 1. Hello applet still reachable.
    check("select HelloWorld", select(AID_HELLO), SW_OK);
    ResponseAPDU hello = transmit(new CommandAPDU(0x80, 0x00, 0, 0));
    check("GET HELLO SW", hello.getSW(), SW_OK);
    check("GET HELLO data", new String(hello.getData()), "Hello");

    // 2. Full scenario per suite.
    runScenario(AID_GCM, (byte) 0x01, "AES-256-GCM");
    runScenario(AID_CBC, (byte) 0x02, "AES-256-CBC+HMAC-SHA-256");

    System.out.println("---");
    System.out.println("passed=" + passed + " failed=" + failed);
    if (failed > 0) {
      System.exit(1);
    }
  }

  static void runScenario(byte[] aid, byte suite, String label)
      throws Exception {
    System.out.println("=== suite 0x" + Integer.toHexString(suite & 0xFF)
        + " (" + label + ") ===");
    int sw = select(aid);
    if (sw != SW_OK) {
      // Real cards may only carry one of the two suite instances (a suite
      // the card cannot run fails its install probe by design).
      System.out.println("SKIP: instance " + bytesToHex(aid)
          + " not present (select SW=" + hex(sw) + ")");
      return;
    }

    Sc c = new Sc(suite);

    // Protected command before handshake must be rejected.
    check("ping before handshake rejected",
        transmit(new CommandAPDU(0x80, 0xB0, 0, 0, new byte[28 + 20])).getSW(),
        SW_SECURE);

    c.handshake();
    System.out.println("PASS: handshake (ECDH P-256 + HKDF + key confirmation"
        + ", suite echoed 0x" + Integer.toHexString(suite & 0xFF) + ")");
    passed++;

    for (int i = 0; i < 3; i++) {
      byte[] msg = ("smoke-" + i).getBytes();
      ResponseAPDU resp = transmit(c.protect(INS_PING, msg));
      check("ping " + i + " SW", resp.getSW(), SW_OK);
      check("ping " + i + " echo", new String(c.open(INS_PING, resp)),
          new String(msg));
    }

    // Replay rejected.
    CommandAPDU one = c.protect(INS_PING, "replay-me".getBytes());
    check("original accepted", transmit(one).getSW(), SW_OK);
    check("replay rejected", transmit(one).getSW(), SW_SECURE);

    // Tamper rejected + session wiped, re-handshake recovers.
    CommandAPDU two = c.protect(INS_PING, "tamper-me".getBytes());
    byte[] raw = two.getBytes();
    raw[raw.length - 3] ^= 0x01;
    check("tampered rejected", transmit(new CommandAPDU(raw)).getSW(),
        SW_SECURE);
    check("session wiped", transmit(two).getSW(), SW_SECURE);
    c.handshake();
    check("recovered after re-handshake",
        transmit(c.protect(INS_PING, "back".getBytes())).getSW(), SW_OK);

    // Deselect wipes the session.
    select(AID_HELLO);
    select(aid);
    check("session wiped on deselect", transmit(two).getSW(), SW_SECURE);
  }

  // --- protocol client (mirrors helloworld.SecureChannelApplet) -------------

  static final class Sc {
    static final SecureRandom RANDOM = new SecureRandom();

    final byte suite;
    final int ivLen;
    final int tokenCtLen;
    SecretKeySpec confKey;
    SecretKeySpec msgKey;
    byte[] confMacKey;
    byte[] macKey;
    byte[] rxPrefix;
    byte[] txPrefix;
    byte[] rxSeq = new byte[8];

    Sc(byte suite) {
      this.suite = suite;
      this.ivLen = suite == 0x01 ? 12 : 16;
      this.tokenCtLen = suite == 0x01 ? 16 : 32;
    }

    void handshake() throws Exception {
      ResponseAPDU init = transmit(new CommandAPDU(0x80, 0x10, 0, 0, 255));
      expect(init.getSW() == SW_OK, "INIT SW, got " + hex(init.getSW()));
      byte[] data = init.getData();
      expect(data.length == 82, "INIT length " + data.length);
      byte[] qCard = Arrays.copyOfRange(data, 0, 65);
      byte[] nCard = Arrays.copyOfRange(data, 65, 81);
      expect(data[81] == suite,
          "INIT echoed suite " + (data[81] & 0xFF) + ", expected " + suite);

      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(new ECGenParameterSpec("secp256r1"));
      KeyPair own = kpg.generateKeyPair();
      byte[] qPeer = rawPublic((ECPublicKey) own.getPublic());
      byte[] nPeer = new byte[16];
      RANDOM.nextBytes(nPeer);

      KeyAgreement ka = KeyAgreement.getInstance("ECDH");
      ka.init(own.getPrivate());
      ka.doPhase(parsePublic(qCard), true);
      byte[] z = ka.generateSecret();

      byte[] prk = hmacFull(concat(nCard, nPeer), z);
      String v = suite == 0x01 ? "SCv1-" : "SCv2-";
      confKey = new SecretKeySpec(
          Arrays.copyOf(expand(prk, v + "conf"), 16), "AES");
      msgKey = new SecretKeySpec(expand(prk, v + "msg"), "AES");
      if (suite != 0x01) {
        confMacKey = expand(prk, v + "confmac");
        macKey = expand(prk, v + "mac");
      }

      byte[] aad = concat(qCard, qPeer, nCard, nPeer,
          new byte[] {suite, 0x00});
      byte[] iv = randomIv();
      byte[] body = concat(qPeer, nPeer, iv,
          seal(confKey, confMacKey, aad, iv, new byte[16]));
      ResponseAPDU resp = transmit(new CommandAPDU(0x80, 0x12, 0, 0, body));
      expect(resp.getSW() == SW_OK, "EXCHANGE SW, got " + hex(resp.getSW()));
      byte[] out = resp.getData();
      expect(out.length == ivLen + tokenCtLen + 16,
          "EXCHANGE length " + out.length);
      byte[] aadCard = concat(qCard, qPeer, nCard, nPeer,
          new byte[] {suite, 0x01});
      byte[] opened = openTok(confKey, confMacKey, aadCard,
          Arrays.copyOfRange(out, 0, ivLen),
          Arrays.copyOfRange(out, ivLen, out.length));
      expect(Arrays.equals(opened, new byte[16]), "card confirmation token");

      rxPrefix = Arrays.copyOfRange(nPeer, 0, 4);
      txPrefix = Arrays.copyOfRange(nCard, 0, 4);
      rxSeq = new byte[8];
    }

    CommandAPDU protect(int ins, byte[] plaintext) throws Exception {
      inc(rxSeq);
      byte[] iv = new byte[ivLen];
      System.arraycopy(rxPrefix, 0, iv, 0, 4);
      System.arraycopy(rxSeq, 0, iv, 4, 8);
      int ctLen = suite == 0x01 ? plaintext.length : padLen(plaintext.length);
      byte[] header = new byte[] {
          (byte) 0x80, (byte) ins, 0, 0, (byte) (ivLen + ctLen + 16)};
      byte[] aad = suite == 0x01 ? concat(header, iv) : header;
      return new CommandAPDU(0x80, ins, 0, 0,
          concat(iv, seal(msgKey, macKey, aad, iv, plaintext)));
    }

    byte[] open(int ins, ResponseAPDU resp) throws Exception {
      byte[] data = resp.getData();
      byte[] iv = Arrays.copyOfRange(data, 0, ivLen);
      expect(Arrays.equals(Arrays.copyOfRange(iv, 0, 4), txPrefix),
          "response IV prefix");
      byte[] aad = suite == 0x01
          ? concat(new byte[] {(byte) ins}, iv)
          : new byte[] {(byte) ins};
      return openTok(msgKey, macKey, aad, iv,
          Arrays.copyOfRange(data, ivLen, data.length));
    }

    /** Returns ct || tag(16) for the active suite. */
    byte[] seal(SecretKeySpec enc, byte[] mKey, byte[] aad, byte[] iv,
        byte[] pt) throws Exception {
      if (suite == 0x01) {
        return gcm(Cipher.ENCRYPT_MODE, enc, iv, aad, pt);
      }
      byte[] ct = cbc(Cipher.ENCRYPT_MODE, enc, iv, padM2(pt));
      return concat(ct, Arrays.copyOf(
          hmacFull(mKey, concat(aad, iv, ct)), 16));
    }

    /** Input is ct || tag(16); MAC is verified BEFORE decrypting. */
    byte[] openTok(SecretKeySpec enc, byte[] mKey, byte[] aad, byte[] iv,
        byte[] ctAndTag) throws Exception {
      if (suite == 0x01) {
        return gcm(Cipher.DECRYPT_MODE, enc, iv, aad, ctAndTag);
      }
      byte[] ct = Arrays.copyOfRange(ctAndTag, 0, ctAndTag.length - 16);
      byte[] wireMac = Arrays.copyOfRange(ctAndTag, ctAndTag.length - 16,
          ctAndTag.length);
      byte[] computed = Arrays.copyOf(
          hmacFull(mKey, concat(aad, iv, ct)), 16);
      expect(Arrays.equals(computed, wireMac), "CBC-HMAC tag mismatch");
      return unpadM2(cbc(Cipher.DECRYPT_MODE, enc, iv, ct));
    }

    byte[] randomIv() {
      byte[] iv = new byte[ivLen];
      RANDOM.nextBytes(iv);
      return iv;
    }
  }

  // --- ISO9797-M2 padding (JDK JCE has no such padding) ----------------------

  static int padLen(int n) {
    return n + 16 - (n % 16);
  }

  static byte[] padM2(byte[] pt) {
    byte[] out = Arrays.copyOf(pt, padLen(pt.length));
    out[pt.length] = (byte) 0x80;
    return out;
  }

  static byte[] unpadM2(byte[] padded) {
    int i = padded.length - 1;
    while (i >= 0 && padded[i] == 0) {
      i--;
    }
    expect(i >= 0 && padded[i] == (byte) 0x80, "invalid M2 padding");
    return Arrays.copyOf(padded, i);
  }

  // --- helpers --------------------------------------------------------------

  static CardTerminal firstTerminal() throws Exception {
    List<CardTerminal> list = TerminalFactory.getDefault().terminals().list();
    for (CardTerminal t : list) {
      if (t.isCardPresent()) {
        return t;
      }
    }
    throw new IllegalStateException("no card present; readers: " + list);
  }

  static int select(byte[] aid) throws Exception {
    return transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid)).getSW();
  }

  static ResponseAPDU transmit(CommandAPDU apdu) throws Exception {
    return channel.transmit(apdu);
  }

  static byte[] hmacFull(byte[] key, byte[] msg) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    return mac.doFinal(msg);
  }

  static byte[] expand(byte[] prk, String label) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(prk, "HmacSHA256"));
    mac.update(label.getBytes("ASCII"));
    mac.update((byte) 0x01);
    return mac.doFinal();
  }

  static byte[] gcm(int mode, SecretKeySpec key, byte[] iv, byte[] aad,
      byte[] in) throws Exception {
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(mode, key, new GCMParameterSpec(128, iv));
    c.updateAAD(aad);
    return c.doFinal(in);
  }

  static byte[] cbc(int mode, SecretKeySpec key, byte[] iv, byte[] in)
      throws Exception {
    Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
    c.init(mode, key, new IvParameterSpec(iv));
    return c.doFinal(in);
  }

  static ECPublicKey parsePublic(byte[] raw) throws Exception {
    AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
    params.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec curve = params.getParameterSpec(ECParameterSpec.class);
    return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(
        new ECPublicKeySpec(new ECPoint(
            new BigInteger(1, Arrays.copyOfRange(raw, 1, 33)),
            new BigInteger(1, Arrays.copyOfRange(raw, 33, 65))), curve));
  }

  static byte[] rawPublic(ECPublicKey pub) {
    byte[] out = new byte[65];
    out[0] = 0x04;
    fix32(pub.getW().getAffineX(), out, 1);
    fix32(pub.getW().getAffineY(), out, 33);
    return out;
  }

  static void fix32(BigInteger v, byte[] out, int off) {
    byte[] b = v.toByteArray();
    int src = 0;
    int dst = off + 32 - Math.min(b.length, 32);
    if (b.length > 32) {
      src = b.length - 32;
    }
    System.arraycopy(b, src, out, dst, Math.min(b.length, 32));
  }

  static void inc(byte[] c) {
    for (int i = c.length - 1; i >= 0; i--) {
      int v = c[i] & 0xFF;
      if (v < 0xFF) {
        c[i]++;
        return;
      }
      c[i] = 0;
    }
  }

  static byte[] concat(byte[]... parts) {
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

  static void check(String name, Object actual, Object expected) {
    if (actual.equals(expected)) {
      System.out.println("PASS: " + name);
      passed++;
    } else {
      System.out.println("FAIL: " + name + " expected=" + expected
          + " actual=" + actual);
      failed++;
    }
  }

  static void expect(boolean cond, String what) {
    if (!cond) {
      throw new AssertionError(what);
    }
  }

  static String hex(int v) {
    return Integer.toHexString(v);
  }

  static String bytesToHex(byte[] b) {
    StringBuilder sb = new StringBuilder();
    for (byte x : b) {
      sb.append(String.format("%02x", x));
    }
    return sb.toString();
  }
}
