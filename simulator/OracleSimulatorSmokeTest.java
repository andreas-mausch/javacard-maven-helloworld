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
 *
 * <p>Compile and run with any JDK 11+ (javax.smartcardio is part of the JDK).
 * See simulator/run.sh. Exits non-zero on failure.
 */
public class OracleSimulatorSmokeTest {

  static final int SW_OK = 0x9000;
  static final int SW_SECURE = 0x6982;
  static final byte CLA = (byte) 0x80;
  static final byte INS_PING = (byte) 0xB0;

  static CardChannel channel;
  static final SecureRandom RANDOM = new SecureRandom();
  static int passed = 0;
  static int failed = 0;

  // Session state
  static SecretKeySpec confKey;
  static SecretKeySpec msgKey;
  static byte[] rxPrefix;
  static byte[] txPrefix;
  static byte[] rxSeq = new byte[8];

  public static void main(String[] args) throws Exception {
    Card card = firstTerminal().connect("*");
    channel = card.getBasicChannel();
    System.out.println("Connected, ATR="
        + bytesToHex(card.getATR().getBytes()));

    // 1. Hello applet still reachable.
    check("select HelloWorld", select(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06}), SW_OK);
    ResponseAPDU hello = transmit(new CommandAPDU(0x80, 0x00, 0, 0));
    check("GET HELLO SW", hello.getSW(), SW_OK);
    check("GET HELLO data", new String(hello.getData()), "Hello");

    // 2. Secure applet: protected command before handshake must be rejected.
    check("select SecureChannel", select(new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x07}), SW_OK);
    ResponseAPDU early = transmit(new CommandAPDU(0x80, 0xB0, 0, 0,
        new byte[28]));
    check("ping before handshake rejected", early.getSW(), SW_SECURE);


    // 3. Full handshake.
    handshake();
    System.out.println("PASS: handshake (ECDH P-256 + HKDF + key confirmation)");
    passed++;

    // 4. Protected round trips.
    for (int i = 0; i < 3; i++) {
      byte[] msg = ("smoke-" + i).getBytes();
      ResponseAPDU resp = transmit(protect(INS_PING, msg));
      check("ping " + i + " SW", resp.getSW(), SW_OK);
      check("ping " + i + " echo",
          new String(open(INS_PING, resp)), new String(msg));
    }

    // 5. Replay rejected.
    CommandAPDU one = protect(INS_PING, "replay-me".getBytes());
    check("original accepted", transmit(one).getSW(), SW_OK);
    check("replay rejected", transmit(one).getSW(), SW_SECURE);

    // 6. Tamper rejected + session wiped, re-handshake recovers.
    CommandAPDU two = protect(INS_PING, "tamper-me".getBytes());
    byte[] raw = two.getBytes();
    raw[raw.length - 3] ^= 0x01;
    check("tampered rejected", transmit(new CommandAPDU(raw)).getSW(),
        SW_SECURE);
    check("session wiped", transmit(two).getSW(), SW_SECURE);
    handshake();
    check("recovered after re-handshake",
        transmit(protect(INS_PING, "back".getBytes())).getSW(), SW_OK);

    // 7. Deselect wipes the session.
    select(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    select(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x07});
    check("session wiped on deselect", transmit(two).getSW(), SW_SECURE);

    System.out.println("---");
    System.out.println("passed=" + passed + " failed=" + failed);
    if (failed > 0) {
      System.exit(1);
    }
  }

  // --- protocol (mirrors helloworld.SecureChannelApplet) -------------------

  static void handshake() throws Exception {
    ResponseAPDU init = transmit(new CommandAPDU(0x80, 0x10, 0, 0, 255));
    expect(init.getSW() == SW_OK, "INIT SW, got " + hex(init.getSW()));
    byte[] data = init.getData();
    expect(data.length == 81, "INIT length " + data.length);
    byte[] qCard = Arrays.copyOfRange(data, 0, 65);
    byte[] nCard = Arrays.copyOfRange(data, 65, 81);

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

    byte[] prk = hmac(concat(nCard, nPeer), z);
    confKey = new SecretKeySpec(Arrays.copyOf(
        expand(prk, "SCv1-conf".getBytes()), 16), "AES");
    msgKey = new SecretKeySpec(expand(prk, "SCv1-msg".getBytes()), "AES");

    byte[] aad = concat(qCard, qPeer, nCard, nPeer, new byte[] {0});
    byte[] iv = new byte[12];
    RANDOM.nextBytes(iv);
    byte[] body = concat(qPeer, nPeer, iv,
        gcm(Cipher.ENCRYPT_MODE, confKey, iv, aad, new byte[16]));
    ResponseAPDU resp = transmit(new CommandAPDU(0x80, 0x12, 0, 0, body));
    expect(resp.getSW() == SW_OK, "EXCHANGE SW, got " + hex(resp.getSW()));
    byte[] out = resp.getData();
    expect(out.length == 44, "EXCHANGE length " + out.length);
    byte[] aadCard = concat(qCard, qPeer, nCard, nPeer, new byte[] {1});
    byte[] opened = gcm(Cipher.DECRYPT_MODE, confKey,
        Arrays.copyOfRange(out, 0, 12), aadCard,
        Arrays.copyOfRange(out, 12, out.length));
    expect(Arrays.equals(opened, new byte[16]), "card confirmation token");

    rxPrefix = Arrays.copyOfRange(nPeer, 0, 4);
    txPrefix = Arrays.copyOfRange(nCard, 0, 4);
    rxSeq = new byte[8];
  }

  static CommandAPDU protect(int ins, byte[] plaintext) throws Exception {
    inc(rxSeq);
    byte[] iv = concat(rxPrefix, rxSeq);
    int lc = 12 + plaintext.length + 16;
    byte[] aad = new byte[] {CLA, (byte) ins, 0, 0, (byte) lc};
    aad = concat(aad, iv);
    return new CommandAPDU(0x80, ins, 0, 0,
        concat(iv, gcm(Cipher.ENCRYPT_MODE, msgKey, iv, aad, plaintext)));
  }

  static byte[] open(int ins, ResponseAPDU resp) throws Exception {
    byte[] data = resp.getData();
    byte[] iv = Arrays.copyOfRange(data, 0, 12);
    expect(Arrays.equals(Arrays.copyOfRange(iv, 0, 4), txPrefix),
        "response IV prefix");
    byte[] aad = concat(new byte[] {(byte) ins}, iv);
    return gcm(Cipher.DECRYPT_MODE, msgKey, iv, aad,
        Arrays.copyOfRange(data, 12, data.length));
  }

  // --- helpers --------------------------------------------------------------

  static CardTerminal firstTerminal() throws Exception {
    List<CardTerminal> list =
        TerminalFactory.getDefault().terminals().list();
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

  static byte[] hmac(byte[] key, byte[] msg) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    return mac.doFinal(msg);
  }

  static byte[] expand(byte[] prk, byte[] label) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(prk, "HmacSHA256"));
    mac.update(label);
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
