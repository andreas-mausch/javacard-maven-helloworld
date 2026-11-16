package helloworld;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

/**
 * Applet with an ECDH + HKDF-SHA256 authenticated secure channel.
 *
 * <h2>Cipher suites (fixed at install time, no negotiation, no fallback)</h2>
 *
 * The GP INSTALL private data must be exactly one byte choosing the suite:
 * {@code 01} = AES-256-GCM ({@link javacardx.crypto.AEADCipher}), {@code 02} =
 * AES-256-CBC (ISO9797-M2 padding) + HMAC-SHA-256 Encrypt-then-MAC. Anything
 * else fails the install ({@code 0x9E01} missing parameter, {@code 0x9E02}
 * unknown value) and a card that cannot run the chosen suite fails with
 * {@code 0x9F00 | bitmask} (see probe(), README has the table). Example:
 * {@code gp --create ...0507 --applet ...0507 --params 02}.
 *
 * <h2>Protocol (version 1)</h2>
 *
 * <pre>
 * CLA = 0x80
 *
 * INIT (INS 0x10, no data) -&gt;
 *   out: Q_card (65B uncompressed EC point, secp256r1) || N_card (16B nonce)
 *        || suite (1B echo so the host derives matching keys)
 *   Regenerates the ephemeral ECDH key pair and wipes any active session.
 *
 * EXCHANGE (INS 0x12) -&gt;
 *   in:  Q_peer (65B) || N_peer (16B) || iv_c (12/16B) || conf_token ct
 *        (16/32B) || tag (16B)
 *   out: iv_s || conf_token_s ct || tag (16B)
 *   (12/16B and 16/32B for suites 01/02; the tag is always 16B)
 *
 *   Z       = ECDH(d_card, Q_peer)                       (32B, plain X coord)
 *   salt    = N_card || N_peer
 *   PRK     = HKDF-Extract(salt, Z)                      (HMAC-SHA-256)
 *   K_conf  = HKDF-Expand(PRK, "SCvN-conf" || 0x01)[0..16)
 *   K_msg   = HKDF-Expand(PRK, "SCvN-msg"  || 0x01)[0..32)
 *   plus, for suite 02 only, MAC keys K_confmac ("SCv2-confmac") and
 *   K_mac ("SCv2-mac"), each 32B; N = 1/2 per suite.
 *   conf_token = seal under K_conf (and K_confmac for suite 02) of 16 zero
 *        bytes, bound to the transcript
 *   transcript = Q_card || Q_peer || N_card || N_peer || suite || dir
 *        (dir = 0x00 client-&gt;card, 0x01 card-&gt;client)
 *   The card checks the token (key confirmation) and answers with its own
 *   token. On success a session is active.
 *
 * PROTECTED COMMAND (e.g. INS 0xB0 SECRET_PING) -&gt;
 *   in:  iv (12/16B = N_card[0..4) || seq(8B, big endian, strictly increasing)
 *        [|| 4 zero bytes for CBC]) || ciphertext || tag/mac (16B)
 *   out: iv (12/16B = N_peer[0..4) || resp_seq(8B) [|| zeros]) || ct || 16B
 *   Suite 01 (GCM): aad (request)  = CLA || INS || P1 || P2 || Lc || iv,
 *                   aad (response) = INS || iv.
 *   Suite 02 (CBC-HMAC, Encrypt-then-MAC, tag = HMAC truncated to 16B):
 *                   mac input (request)  = CLA..Lc || iv || ct,
 *                   mac input (response) = INS || iv || ct;
 *                   verified BEFORE decrypting, so a bad MAC never decrypts
 *                   and the padding is unreachable for an attacker.
 *   Only accepted while a session is active, otherwise 0x6982.
 *   Any integrity failure wipes the session (re-handshake required).
 * </pre>
 *
 * <h2>Security notes</h2>
 *
 * <ul>
 * <li>Forward secrecy: yes (ephemeral on both sides).</li>
 * <li>Mutual key confirmation: yes (tokens bound to the full transcript,
 * including the suite byte, so tokens cannot cross suites).</li>
 * <li>Replay protection: strictly increasing, direction-bound sequence
 * numbers; the iv is bound via the GCM AAD (suite 01) or inside the MAC
 * input (suite 02).</li>
 * <li>Suite 02 is a fallback for cards without AEADCipher support; it is a
 * standard Encrypt-then-MAC construction (never MAC-then-pad!), but GCM is
 * the preferred suite where available.</li>
 * <li><b>Authentication against an active network attacker: NO.</b> Both
 * ECDH keys are ephemeral, so a MITM can run two handshakes. For
 * production, pin a card attestation key or add a static signed
 * handshake. See README.</li>
 * </ul>
 */
public class SecureChannelApplet extends Applet {

  // --- Instruction set ---------------------------------------------------

  private static final byte SC_CLA = (byte) 0x80;
  private static final byte INS_INIT = (byte) 0x10;
  private static final byte INS_EXCHANGE = (byte) 0x12;
  private static final byte INS_SECRET_PING = (byte) 0xB0;

  // --- Fixed sizes -------------------------------------------------------

  private static final short EC_POINT_LEN = 65;
  private static final short NONCE_LEN = 16;
  private static final short GCM_IV_LEN = 12;
  private static final short CBC_IV_LEN = 16;
  private static final short TAG_LEN = 16;
  private static final short SEQ_LEN = 8;
  private static final short PREFIX_LEN = 4;
  private static final short HKDF_OUT_LEN = 32;
  private static final short SHA256_BLOCK_LEN = 64;
  private static final short TOKEN_PT_LEN = 16;
  /** Token ciphertext under CBC: 16B plaintext + one ISO9797-M2 pad block. */
  private static final short CBC_TOKEN_CT_LEN = 32;
  // transcript = Q_card || Q_peer || N_card || N_peer || suite || direction
  private static final short TRANSRIPT_LEN = EC_POINT_LEN * 2 + NONCE_LEN * 2 + 2;

  // --- Cipher suites (chosen by the GP INSTALL parameter, no fallback) ----
  //
  // 0x01: AES-256-GCM (AEADCipher.ALG_AES_GCM), AAD = header || iv.
  // 0x02: AES-256-CBC (ISO9797-M2 padding) + HMAC-SHA-256 Encrypt-then-MAC,
  // MAC input = header || iv || ct, tag truncated to 16 bytes and
  // verified before decryption. Payload layout iv || ct || mac is
  // identical, so callers do not care.
  //
  // The suite is FIXED at instance creation: an instance never negotiates or
  // downgrades. The suite byte is part of the handshake transcript, so keys,
  // tokens and AAD are suite-bound and instances cannot be confused.

  /** Install parameter: AES-256-GCM. */
  private static final byte SUITE_GCM = (byte) 0x01;
  /** Install parameter: AES-256-CBC + HMAC-SHA-256 (Encrypt-then-MAC). */
  private static final byte SUITE_CBC_HMAC = (byte) 0x02;

  /** No (or malformed) suite byte in the GP INSTALL data. */
  private static final short SW_SUITE_PARAM_MISSING = (short) 0x9E01;
  /** Suite byte present but not one of the known suites. */
  private static final short SW_SUITE_PARAM_INVALID = (short) 0x9E02;

  // --- HKDF info labels (RFC 5869) ---------------------------------------

  private static final byte[] LABEL_CONF = {
      'S', 'C', 'v', '1', '-', 'c', 'o', 'n', 'f'};
  private static final byte[] LABEL_MSG = {
      'S', 'C', 'v', '1', '-', 'm', 's', 'g'};
  private static final byte[] L2_LABEL_CONF = {
      'S', 'C', 'v', '2', '-', 'c', 'o', 'n', 'f'};
  private static final byte[] L2_LABEL_CONF_MAC = {
      'S', 'C', 'v', '2', '-', 'c', 'o', 'n', 'f', 'm', 'a', 'c'};
  private static final byte[] L2_LABEL_MSG = {
      'S', 'C', 'v', '2', '-', 'm', 's', 'g'};
  private static final byte[] L2_LABEL_MAC = {
      'S', 'C', 'v', '2', '-', 'm', 'a', 'c'};

  /** Known plaintext of the confirmation tokens (all zeros, length 16). */
  private static final byte[] CONF_PT = new byte[TOKEN_PT_LEN];

  // --- Install-time capability self test ------------------------------------
  // install() probes every primitive the CHOSEN suite needs so that a card
  // lacking one fails the GP INSTALL with a vendor SW of the form
  // 0x9F00 | bitmask (see bits below) instead of a generic error from deep
  // inside the constructor. Note: probe() runs before register(), so nothing
  // is registered on failure; see README for the SW table.

  /** Vendor SW base for a failed capability self test. */
  private static final short SW_MISSING_ALGORITHMS = (short) 0x9F00;

  // Missing-primitive bitmask (combine freely; multiple bits may be set).
  // Bits 0x20/0x40 refer to the cipher of the suite chosen via the install
  // parameter (GCM or CBC+HMAC).
  private static final short MISS_SHA256 = 0x0001; // MessageDigest
  private static final short MISS_RANDOM = 0x0002; // RandomData
  private static final short MISS_EC_FP_256 = 0x0004; // EC FP-256 keypair
  private static final short MISS_ECDH_PLAIN = 0x0008; // ALG_EC_SVDP_DH_PLAIN
  private static final short MISS_AES_TRANSIENT = 0x0010; // AES *_TRANSIENT_DESELECT
  private static final short MISS_CIPHER = 0x0020; // suite cipher unavailable
  private static final short MISS_KAT = 0x0040; // suite cipher functional test broken

  // Throwaway inputs for the cipher known-answer smoke tests.
  private static final byte[] KAT_KEY = {
      (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
      (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
      (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10, (byte) 0x11,
      (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
      (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B, (byte) 0x1C, (byte) 0x1D,
      (byte) 0x1E, (byte) 0x1F
  };
  private static final byte[] KAT_PT = {
      'S', 'C', 'v', '1', 'k', 'a', 't', '!', 0, 0, 0, 0, 0, 0, 0, 0
  };
  private static final byte[] KAT_AAD = {'S', 'C', 'v', '1', 'k', 'a', 't'};

  /** Layout of the 96-byte GCM probe workspace. */
  private static final short KAT_IV = 0; // 12
  private static final short KAT_CT = 12; // 16
  private static final short KAT_TAG = 28; // 16
  private static final short KAT_PT_OFF = 44; // 16
  private static final short KAT_AAD_OFF = 64; // 7
  private static final short KAT_OUT = 76; // 16

  private static final byte[] KAT_MAC_KEY = {
      (byte) 0xF0, (byte) 0xF1, (byte) 0xF2, (byte) 0xF3, (byte) 0xF4, (byte) 0xF5,
      (byte) 0xF6, (byte) 0xF7, (byte) 0xF8, (byte) 0xF9, (byte) 0xFA, (byte) 0xFB,
      (byte) 0xFC, (byte) 0xFD, (byte) 0xFE, (byte) 0xFF, (byte) 0xE0, (byte) 0xE1,
      (byte) 0xE2, (byte) 0xE3, (byte) 0xE4, (byte) 0xE5, (byte) 0xE6, (byte) 0xE7,
      (byte) 0xE8, (byte) 0xE9, (byte) 0xEA, (byte) 0xEB, (byte) 0xEC, (byte) 0xED,
      (byte) 0xEE, (byte) 0xEF
  };
  private static final byte[] KAT_CBC_IV = {
      'i', 'v', '4', 'c', 'b', 'c', 'k', 'a', 't', 0, 0, 0, 0, 0, 0, 0
  };

  /**
   * Layout of the 256-byte CBC-HMAC probe workspace (wire at the far end so
   * it never overlaps the HMAC pad||msg region).
   */
  private static final short KAT2_WIRE = 160; // seal writes iv||ct||mac (64)
  private static final short KAT2_PT = 0; // open writes the plaintext back here

  // --- NIST P-256 (secp256r1) domain parameters --------------------------

  private static final byte[] EC_P = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
  };
  private static final byte[] EC_A = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
  };
  private static final byte[] EC_B = {
      (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
      (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
      (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
      (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B
  };
  private static final byte[] EC_G = {
      (byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42,
      (byte) 0x47, (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40,
      (byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33,
      (byte) 0xA0, (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2,
      (byte) 0x96, (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F,
      (byte) 0x9B, (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E,
      (byte) 0x16, (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E,
      (byte) 0xCE, (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51,
      (byte) 0xF5
  };
  private static final byte[] EC_R = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
      (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51
  };

  // --- Crypto objects (created once, reused) ------------------------------

  private ECPrivateKey ecdhPriv;
  private ECPublicKey ecdhPub;
  private ECPublicKey peerPub;
  private KeyPair ecdhKeyPair;
  private KeyAgreement ecdh;
  /** Suite 1 only. */
  private AEADCipher gcm;
  /** Suite 2 only. */
  private Cipher cbc;
  private MessageDigest sha256;
  private RandomData random;

  /** Session message key (AES-256, GCM or CBC), transient. */
  private AESKey msgKey;
  /** Handshake confirmation key (AES-128, GCM or CBC), transient. */
  private AESKey confKey;
  /** Suite 2 payload MAC key (raw bytes - HMACKey is not portable), transient. */
  private byte[] macKey;
  /** Suite 2 confirmation-token MAC key, transient. */
  private byte[] confMacKey;

  // --- State ---------------------------------------------------------------

  /** Ephemeral card nonce; transient, cleared on deselect. */
  private byte[] nCard;
  private byte[] salt; // transient 32: N_card || N_peer (handshake only)
  private byte[] zBuf; // transient 32: ECDH shared secret (handshake only)
  private byte[] prk; // transient 32: HKDF pseudo-random key (handshake only)
  private byte[] tmp; // transient 32: HKDF block output scratch (secrets!)
  private byte[] rxPrefix; // transient 4: N_peer[0..4)
  private byte[] txPrefix; // transient 4: N_card[0..4)
  private byte[] lastRxSeq; // transient 8
  private byte[] txSeq; // transient 8
  private byte[] decBuf; // transient: plaintext scratch + HMAC pad||msg workspace
  private byte[] hmacInner; // transient 32: inner HMAC digest (secret!)

  /** Transcript scratch (public data only, not transient). */
  private byte[] transcript;
  /** Small scratch for HKDF block inputs and random IVs (public). */
  private byte[] scratch;

  private boolean sessionActive;

  /** Cipher suite fixed at install time; see SUITE_* constants. */
  private final byte suite;
  private final short ivLen;
  private final short tokenCtLen;

  // ------------------------------------------------------------------------

  /**
   * The GP install parameter (one byte) selects the cipher suite
   * ({@code 01} = GCM, {@code 02} = CBC+HMAC) and there is no default: an
   * instance can never silently fall back to another algorithm. Fails with
   * SW_MISSING_ALGORITHMS | bitmask if the card lacks a primitive of the
   * chosen suite, so a broken deployment never registers a half-usable
   * applet. Example: {@code gp --create ... --params 02}.
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    byte suite = parseSuiteParam(bArray, bOffset);
    short missing = probe(suite);
    if (missing != 0) {
      ISOException.throwIt((short) (SW_MISSING_ALGORITHMS | missing));
    }
    new SecureChannelApplet(suite).register(bArray, (short) (bOffset + 1),
        bArray[bOffset]);
  }

  /**
   * GP INSTALL data layout at bOffset: {@code [len][instance AID]
   * [len][card capabilities][len][applet private data]}. The private data
   * must be exactly one suite byte.
   */
  private static byte parseSuiteParam(byte[] bArray, short bOffset) {
    short i = (short) (bOffset + 1 + (bArray[bOffset] & 0xFF)); // caps length
    i += (short) (1 + (bArray[i] & 0xFF)); // private data length
    short dataLen = (short) (bArray[i] & 0xFF);
    if (dataLen != 1) {
      ISOException.throwIt(SW_SUITE_PARAM_MISSING);
    }
    byte suite = bArray[(short) (i + 1)];
    if (suite != SUITE_GCM && suite != SUITE_CBC_HMAC) {
      ISOException.throwIt(SW_SUITE_PARAM_INVALID);
    }
    return suite;
  }

  /**
   * Checks that all primitives shared by the suites are available and that
   * the cipher of the chosen suite works (round trip + tamper rejection via
   * the same open code path used at runtime). Availability probes only throw
   * CryptoException(NO_SUCH_ALGORITHM), which is cheap and side-effect free;
   * classic Java Card has no garbage collector, so probe() intentionally
   * leaks only a handful of small key/cipher objects and one transient
   * buffer — the price of failing install early with a good SW.
   *
   * @return bitmask of missing primitives, 0 if the card can run the suite
   */
  private static short probe(byte suite) {
    short missing = 0;

    try {
      MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    } catch (CryptoException e) {
      missing |= MISS_SHA256;
    }
    try {
      RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    } catch (CryptoException e) {
      missing |= MISS_RANDOM;
    }
    try {
      KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
          KeyBuilder.LENGTH_EC_FP_256, false);
      KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,
          KeyBuilder.LENGTH_EC_FP_256, false);
    } catch (CryptoException e) {
      missing |= MISS_EC_FP_256;
    }
    try {
      KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    } catch (CryptoException e) {
      missing |= MISS_ECDH_PLAIN;
    }
    try {
      KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
          KeyBuilder.LENGTH_AES_256, false);
      KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
          KeyBuilder.LENGTH_AES_128, false);
    } catch (CryptoException e) {
      missing |= MISS_AES_TRANSIENT;
    }

    if (suite == SUITE_GCM) {
      AEADCipher cipher = null;
      try {
        cipher = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
      } catch (CryptoException e) {
        missing |= MISS_CIPHER;
      }
      if (cipher != null && !probeGcm(cipher)) {
        missing |= MISS_KAT;
      }
    } else { // SUITE_CBC_HMAC
      MessageDigest md = null;
      try {
        md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
      } catch (CryptoException e) {
        missing |= MISS_SHA256;
      }
      Cipher cbc = null;
      try {
        cbc = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
      } catch (CryptoException e) {
        missing |= MISS_CIPHER;
      }
      if (md != null && cbc != null && !probeCbcHmac(md, cbc)) {
        missing |= MISS_KAT;
      }
    }
    return missing;
  }

  /**
   * GCM smoke test on a throwaway key: seal a known plaintext, open it back
   * (must match), then flip one ciphertext byte and open again — the tag
   * check must reject it. Detects runtimes that advertise ALG_AES_GCM but
   * implement it inconsistently (our gcmOpen()/openGcm() portability dance
   * included, this is the exact path the session will take).
   */
  private static boolean probeGcm(AEADCipher cipher) {
    byte[] ws = JCSystem.makeTransientByteArray((short) 96,
        JCSystem.CLEAR_ON_RESET);
    try {
      AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
          KeyBuilder.LENGTH_AES_256, false);
      key.setKey(KAT_KEY, (short) 0);
      Util.arrayCopyNonAtomic(KAT_PT, (short) 0, ws, KAT_PT_OFF, TOKEN_PT_LEN);
      Util.arrayCopyNonAtomic(KAT_AAD, (short) 0, ws, KAT_AAD_OFF,
          (short) KAT_AAD.length);

      cipher.init(key, Cipher.MODE_ENCRYPT, ws, KAT_IV, GCM_IV_LEN);
      cipher.updateAAD(ws, KAT_AAD_OFF, (short) KAT_AAD.length);
      cipher.doFinal(ws, KAT_PT_OFF, TOKEN_PT_LEN, ws, KAT_CT);
      cipher.retrieveTag(ws, KAT_TAG, TAG_LEN);

      // Open must return the known plaintext.
      boolean ok = openGcm(cipher, key, ws, KAT_AAD_OFF,
          (short) KAT_AAD.length, ws, KAT_IV, KAT_CT, TOKEN_PT_LEN, ws,
          KAT_OUT)
          && Util.arrayCompare(ws, KAT_OUT, KAT_PT, (short) 0, TOKEN_PT_LEN) == 0;

      // A flipped ciphertext byte must be rejected by the tag check.
      ws[KAT_CT] ^= 1;
      boolean rejected = !openGcm(cipher, key, ws, KAT_AAD_OFF,
          (short) KAT_AAD.length, ws, KAT_IV, KAT_CT, TOKEN_PT_LEN, ws,
          KAT_OUT);

      key.clearKey();
      return ok && rejected;
    } catch (CryptoException e) {
      return false;
    }
  }

  /**
   * CBC+HMAC smoke test: seal a known plaintext with the same
   * sealCbcHmac()/openCbcHmac() code path the session uses, require the
   * plaintext back, and require a flipped IV byte to be rejected by the
   * MAC (the tag is checked before decryption, so nothing decrypts on a
   * failed MAC). Detects runtimes that advertise CBC-M2 but implement it
   * inconsistently.
   */
  private static boolean probeCbcHmac(MessageDigest md, Cipher cbc) {
    byte[] ws = JCSystem.makeTransientByteArray((short) 256,
        JCSystem.CLEAR_ON_RESET);
    try {
      AESKey encKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
          KeyBuilder.LENGTH_AES_256, false);
      encKey.setKey(KAT_KEY, (short) 0);

      short wireLen = sealCbcHmac(md, cbc, encKey, KAT_MAC_KEY, ws,
          KAT_AAD, (short) 0, (short) KAT_AAD.length, KAT_CBC_IV, (short) 0,
          KAT_PT, (short) 0, TOKEN_PT_LEN, ws, KAT2_WIRE);
      boolean shaped = wireLen == (short) (CBC_IV_LEN + CBC_TOKEN_CT_LEN
          + TAG_LEN);

      short ptLen = openCbcHmac(md, cbc, encKey, KAT_MAC_KEY, ws,
          KAT_AAD, (short) 0, (short) KAT_AAD.length, ws, KAT2_WIRE,
          (short) (KAT2_WIRE + CBC_IV_LEN), CBC_TOKEN_CT_LEN, ws, KAT2_PT);
      boolean ok = shaped && ptLen == TOKEN_PT_LEN
          && Util.arrayCompare(ws, KAT2_PT, KAT_PT, (short) 0, TOKEN_PT_LEN) == 0;

      // A flipped iv byte must be rejected by the MAC check.
      ws[KAT2_WIRE] ^= 1;
      boolean rejected = openCbcHmac(md, cbc, encKey, KAT_MAC_KEY, ws,
          KAT_AAD, (short) 0, (short) KAT_AAD.length, ws, KAT2_WIRE,
          (short) (KAT2_WIRE + CBC_IV_LEN), CBC_TOKEN_CT_LEN, ws, KAT2_PT) < 0;

      encKey.clearKey();
      return ok && rejected;
    } catch (CryptoException e) {
      return false;
    }
  }

  private SecureChannelApplet(byte suite) {
    this.suite = suite;
    this.ivLen = (short) (suite == SUITE_GCM ? GCM_IV_LEN : CBC_IV_LEN);
    this.tokenCtLen = (short) (suite == SUITE_GCM
        ? TOKEN_PT_LEN
        : CBC_TOKEN_CT_LEN);
    ecdhPriv = (ECPrivateKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    ecdhPub = (ECPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    peerPub = (ECPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    setDomain(ecdhPriv);
    setDomain(ecdhPub);
    setDomain(peerPub);
    ecdhKeyPair = new KeyPair(ecdhPub, ecdhPriv);
    ecdhKeyPair.genKeyPair();

    ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    if (suite == SUITE_GCM) {
      gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
    } else {
      cbc = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
    }
    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

    msgKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
        KeyBuilder.LENGTH_AES_256, false);
    confKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
        KeyBuilder.LENGTH_AES_128, false);
    if (suite == SUITE_CBC_HMAC) {
      macKey = JCSystem.makeTransientByteArray(HKDF_OUT_LEN,
          JCSystem.CLEAR_ON_DESELECT);
      confMacKey = JCSystem.makeTransientByteArray(HKDF_OUT_LEN,
          JCSystem.CLEAR_ON_DESELECT);
    }

    nCard = JCSystem.makeTransientByteArray(NONCE_LEN,
        JCSystem.CLEAR_ON_DESELECT);
    salt = JCSystem.makeTransientByteArray(HKDF_OUT_LEN,
        JCSystem.CLEAR_ON_DESELECT);
    zBuf = JCSystem.makeTransientByteArray(HKDF_OUT_LEN,
        JCSystem.CLEAR_ON_DESELECT);
    prk = JCSystem.makeTransientByteArray(HKDF_OUT_LEN,
        JCSystem.CLEAR_ON_DESELECT);
    tmp = JCSystem.makeTransientByteArray(HKDF_OUT_LEN,
        JCSystem.CLEAR_ON_DESELECT);
    rxPrefix = JCSystem.makeTransientByteArray(PREFIX_LEN,
        JCSystem.CLEAR_ON_DESELECT);
    txPrefix = JCSystem.makeTransientByteArray(PREFIX_LEN,
        JCSystem.CLEAR_ON_DESELECT);
    lastRxSeq = JCSystem.makeTransientByteArray(SEQ_LEN,
        JCSystem.CLEAR_ON_DESELECT);
    txSeq = JCSystem.makeTransientByteArray(SEQ_LEN, JCSystem.CLEAR_ON_DESELECT);
    // decBuf doubles as pad||staged-MAC-input workspace for suite 2; 384 B
    // covers the largest payload a short APDU can carry (64 pad + 244 mac
    // input + 32 MAC tail). Suite 1 keeps the lean 256.
    decBuf = JCSystem.makeTransientByteArray(
        suite == SUITE_GCM ? (short) 256 : (short) 384,
        JCSystem.CLEAR_ON_DESELECT);
    hmacInner = JCSystem.makeTransientByteArray(HKDF_OUT_LEN,
        JCSystem.CLEAR_ON_DESELECT);

    transcript = new byte[TRANSRIPT_LEN];
    scratch = new byte[EC_POINT_LEN + 1];

    random.nextBytes(nCard, (short) 0, NONCE_LEN);
    sessionActive = false;
  }

  private void setDomain(ECKey key) {
    key.setFieldFP(EC_P, (short) 0, (short) EC_P.length);
    key.setA(EC_A, (short) 0, (short) EC_A.length);
    key.setB(EC_B, (short) 0, (short) EC_B.length);
    key.setG(EC_G, (short) 0, (short) EC_G.length);
    key.setR(EC_R, (short) 0, (short) EC_R.length);
    key.setK((short) 1);
  }

  // ------------------------------------------------------------------------

  public void process(APDU apdu) {
    if (selectingApplet()) {
      return;
    }

    byte[] buffer = apdu.getBuffer();
    if (buffer[ISO7816.OFFSET_CLA] != SC_CLA) {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    byte ins = buffer[ISO7816.OFFSET_INS];
    if (ins == INS_INIT) {
      initChannel(apdu);
    } else if (ins == INS_EXCHANGE) {
      exchange(apdu);
    } else if (ins == INS_SECRET_PING) {
      secretPing(apdu);
    } else {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }

  public void deselect() {
    wipeSession();
  }

  // --- INIT ---------------------------------------------------------------

  /** Fresh ephemeral key pair + fresh card nonce; invalidates old session. */
  private void initChannel(APDU apdu) {
    wipeSession();
    ecdhKeyPair.genKeyPair();
    // Re-bind after genKeyPair (objects are reused in place, but keys are new).
    random.nextBytes(nCard, (short) 0, NONCE_LEN);

    byte[] buffer = apdu.getBuffer();
    short len = ecdhPub.getW(buffer, (short) 0);
    Util.arrayCopyNonAtomic(nCard, (short) 0, buffer, len, NONCE_LEN);
    // Echo the suite byte so the host derives matching keys.
    buffer[(short) (len + NONCE_LEN)] = suite;
    apdu.setOutgoingAndSend((short) 0, (short) (len + NONCE_LEN + 1));
  }

  // --- EXCHANGE -----------------------------------------------------------

  private void exchange(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short lc = apdu.setIncomingAndReceive();
    short cdata = ISO7816.OFFSET_CDATA;

    short expectedLc = (short) (EC_POINT_LEN + NONCE_LEN + ivLen + tokenCtLen
        + TAG_LEN);
    if (lc != expectedLc || buffer[cdata] != 0x04) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    try {
      peerPub.setW(buffer, cdata, EC_POINT_LEN);
    } catch (CryptoException e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Z = ECDH(d_card, Q_peer)
    ecdh.init(ecdhPriv);
    short zLen = ecdh.generateSecret(buffer, cdata, EC_POINT_LEN, zBuf,
        (short) 0);
    if (zLen != HKDF_OUT_LEN) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // salt = N_card || N_peer
    Util.arrayCopyNonAtomic(nCard, (short) 0, salt, (short) 0, NONCE_LEN);
    Util.arrayCopyNonAtomic(buffer, (short) (cdata + EC_POINT_LEN), salt,
        NONCE_LEN, NONCE_LEN);

    hkdfExtract(zLen);

    // Derive the suite's keys: token enc + token mac, payload enc + payload
    // mac (the *mac labels only exist for suite 2).
    if (suite == SUITE_GCM) {
      hkdfExpand(LABEL_CONF, (short) 0, tmp);
      confKey.setKey(tmp, (short) 0);
      Util.arrayFillNonAtomic(tmp, (short) 0, HKDF_OUT_LEN, (byte) 0);
      hkdfExpand(LABEL_MSG, (short) 0, tmp);
      msgKey.setKey(tmp, (short) 0);
    } else {
      hkdfExpand(L2_LABEL_CONF, (short) 0, tmp);
      confKey.setKey(tmp, (short) 0);
      Util.arrayFillNonAtomic(tmp, (short) 0, HKDF_OUT_LEN, (byte) 0);
      hkdfExpand(L2_LABEL_CONF_MAC, (short) 0, confMacKey);
      hkdfExpand(L2_LABEL_MSG, (short) 0, tmp);
      msgKey.setKey(tmp, (short) 0);
      hkdfExpand(L2_LABEL_MAC, (short) 0, macKey);
    }
    Util.arrayFillNonAtomic(tmp, (short) 0, HKDF_OUT_LEN, (byte) 0);
    Util.arrayFillNonAtomic(prk, (short) 0, HKDF_OUT_LEN, (byte) 0);
    // Scrub HMAC key-schedule scratch (derived from salt/PRK).
    Util.arrayFillNonAtomic(hmacInner, (short) 0, HKDF_OUT_LEN, (byte) 0);

    // transcript = Q_card || Q_peer || N_card || N_peer || suite || dir
    short off = (short) 0;
    ecdhPub.getW(transcript, off);
    off += EC_POINT_LEN;
    Util.arrayCopyNonAtomic(buffer, cdata, transcript, off, EC_POINT_LEN);
    off += EC_POINT_LEN;
    Util.arrayCopyNonAtomic(nCard, (short) 0, transcript, off, NONCE_LEN);
    off += NONCE_LEN;
    Util.arrayCopyNonAtomic(buffer, (short) (cdata + EC_POINT_LEN), transcript,
        off, NONCE_LEN);
    off += NONCE_LEN;
    transcript[off] = suite;
    transcript[(short) (off + 1)] = 0x00; // direction: client -> card

    short ivOff = (short) (cdata + EC_POINT_LEN + NONCE_LEN);
    short ctOff = (short) (ivOff + ivLen);

    // Verify the client confirmation token bound to the suite.
    if (openMsg(confKey, confMacKey, transcript, (short) 0, TRANSRIPT_LEN,
        buffer, ivOff, ctOff, tokenCtLen) != TOKEN_PT_LEN
        || Util.arrayCompare(decBuf, (short) 0, CONF_PT, (short) 0,
            TOKEN_PT_LEN) != 0) {
      wipeSession();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // Session established: derive IV prefixes and reset counters.
    Util.arrayCopyNonAtomic(buffer, (short) (cdata + EC_POINT_LEN), rxPrefix,
        (short) 0, PREFIX_LEN);
    Util.arrayCopyNonAtomic(nCard, (short) 0, txPrefix, (short) 0, PREFIX_LEN);
    Util.arrayFillNonAtomic(lastRxSeq, (short) 0, SEQ_LEN, (byte) 0);
    Util.arrayFillNonAtomic(txSeq, (short) 0, SEQ_LEN, (byte) 0);
    sessionActive = true;

    // Build card confirmation token (direction byte 0x01).
    transcript[TRANSRIPT_LEN - 1] = 0x01;
    random.nextBytes(scratch, (short) 0, ivLen);
    short sent = seal(confKey, confMacKey, transcript, (short) 0,
        TRANSRIPT_LEN, scratch, (short) 0, CONF_PT, (short) 0, TOKEN_PT_LEN,
        buffer, (short) 0);
    apdu.setOutgoingAndSend((short) 0, sent);
  }

  // --- Protected command ---------------------------------------------------

  /**
   * Demo for a protected command: echoes the decrypted plaintext back,
   * encrypted again under the session key. Use requireSession(),
   * the AAD/IV scheme and the seal/open helpers the same way for your own
   * instructions.
   */
  private void secretPing(APDU apdu) {
    requireSession();

    byte[] buffer = apdu.getBuffer();
    short lc = apdu.setIncomingAndReceive();
    if (lc < (short) (ivLen + TAG_LEN)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short ivOff = ISO7816.OFFSET_CDATA;

    // IV must carry this session's prefix and a strictly increasing seq.
    if (Util.arrayCompare(buffer, ivOff, rxPrefix, (short) 0, PREFIX_LEN) != 0
        || Util.arrayCompare(buffer, (short) (ivOff + PREFIX_LEN), lastRxSeq,
            (short) 0, SEQ_LEN) <= 0) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // Payload = iv || ct || tag/mac. Suite 1 binds the iv via the GCM AAD
    // (header || iv); suite 2 via the MAC input (header || iv || ct) - both
    // contiguous in the APDU buffer because the iv starts at OFFSET_CDATA.
    short ctLen = (short) (lc - ivLen - TAG_LEN);
    short aadLen = (suite == SUITE_GCM)
        ? (short) (ISO7816.OFFSET_CDATA + GCM_IV_LEN)
        : ISO7816.OFFSET_CDATA;
    short ptLen = openMsg(msgKey, macKey, buffer, (short) 0, aadLen, buffer,
        ivOff, (short) (ivOff + ivLen), ctLen);
    if (ptLen <= 0) {
      wipeSession();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    Util.arrayCopyNonAtomic(buffer, (short) (ivOff + PREFIX_LEN), lastRxSeq,
        (short) 0, SEQ_LEN);

    // Response: aad = INS || iv_resp (suite 1) or INS (suite 2), iv_resp =
    // N_peer[0..4) || txSeq++ (|| 4 zero bytes to fill the 16B CBC iv).
    increment(txSeq, (short) 0);
    scratch[0] = buffer[ISO7816.OFFSET_INS];
    Util.arrayCopyNonAtomic(txPrefix, (short) 0, scratch, (short) 1,
        PREFIX_LEN);
    Util.arrayCopyNonAtomic(txSeq, (short) 0, scratch, (short) 5, SEQ_LEN);
    if (suite != SUITE_GCM) {
      Util.arrayFillNonAtomic(scratch, (short) (1 + PREFIX_LEN + SEQ_LEN),
          (short) (CBC_IV_LEN - PREFIX_LEN - SEQ_LEN), (byte) 0);
    }

    short respAadLen = (suite == SUITE_GCM) ? (short) (1 + GCM_IV_LEN) : 1;
    try {
      short sent = seal(msgKey, macKey, scratch, (short) 0, respAadLen,
          scratch, (short) 1, decBuf, (short) 0, ptLen, buffer, (short) 0);
      apdu.setOutgoingAndSend((short) 0, sent);
    } catch (CryptoException e) {
      wipeSession();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      return; // not reached
    }
  }

  // --- Helpers -------------------------------------------------------------

  private void requireSession() {
    if (!sessionActive) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  /**
   * GCM "open": decrypt + authenticate a payload laid out as iv || ct || tag
   * (iv at ivOff, ct at ctOff, tag right after ct, all within `in`); the
   * plaintext ends up in decBuf[0..ctLen).
   *
   * Runtime portability: Java Card runtimes disagree on the AEADCipher
   * decrypt contract —
   * - spec / Oracle (v26 sim, real cards): doFinal(ciphertextOnly) returns
   * the plaintext (n -> n), then verifyTag(wireTag) returns a boolean;
   * - jcardsim (JCE/BC style): doFinal(ciphertext || tag) verifies the tag
   * internally and throws CryptoException on mismatch.
   * We try the spec form first and retry once with the BC form only if it
   * threw. This cannot weaken integrity on spec-compliant cards: their
   * doFinal is n -> n, so the BC retry sees ct || tag as plain ciphertext,
   * returns dlen = ctLen + TAG_LEN != ctLen and is rejected. A successful
   * retry therefore implies a runtime that verifies the tag internally —
   * only jcardsim (test infra). Empirically verified on both runtimes
   * (2026-11-16).
   */
  private boolean gcmOpen(AESKey key, byte[] aadBuf, short aadOff,
      short aadLen, byte[] in, short ivOff, short ctOff, short ctLen) {
    return openGcm(gcm, key, aadBuf, aadOff, aadLen, in, ivOff, ctOff, ctLen,
        decBuf, (short) 0);
  }

  /**
   * Static core of {@link #gcmOpen} so the install-time probe can run the
   * exact same code path. Plaintext lands in out[outOff..outOff+ctLen);
   * that region must not overlap iv/ct/tag in `in`.
   */
  /**
   * Seal pt as iv || ct || tag into out[outOff..], iv taken from
   * ivBuf[ivOff..ivOff+GCM_IV_LEN). Returns the total written length. ivBuf
   * must not overlap out (callers keep the iv in scratch).
   */
  private static short sealGcm(AEADCipher cipher, AESKey key, byte[] aadBuf,
      short aadOff, short aadLen, byte[] ivBuf, short ivOff, byte[] pt,
      short ptOff, short ptLen, byte[] out, short outOff) {
    cipher.init(key, Cipher.MODE_ENCRYPT, ivBuf, ivOff, GCM_IV_LEN);
    cipher.updateAAD(aadBuf, aadOff, aadLen);
    cipher.doFinal(pt, ptOff, ptLen, out, (short) (outOff + GCM_IV_LEN));
    // jcardsim's ENCRYPT doFinal appends the tag right there; retrieveTag
    // then overwrites the identical region on every runtime.
    cipher.retrieveTag(out, (short) (outOff + GCM_IV_LEN + ptLen), TAG_LEN);
    Util.arrayCopyNonAtomic(ivBuf, ivOff, out, outOff, GCM_IV_LEN);
    return (short) (GCM_IV_LEN + ptLen + TAG_LEN);
  }

  /**
   * Seal pt as iv || ct || mac for suite 2: AES-256-CBC with ISO9797-M2
   * padding, Encrypt-then-MAC over {@code aad || iv || ct} (the iv is bound
   * explicitly because, unlike GCM, CBC does not authenticate it), HMAC-SHA-
   * 256 truncated to TAG_LEN. ivBuf must not overlap out.
   *
   * <p>{@code ws} doubles as pad||staged-MAC-input workspace plus a 32-byte
   * tail slot used for the inner digest and the MAC output; must satisfy
   * 64 + aadLen + 16 + ctLen(padded) + 32 bytes, checked at runtime.
   */
  private static short sealCbcHmac(MessageDigest md, Cipher cbc,
      AESKey encKey, byte[] macKey, byte[] ws, byte[] aadBuf, short aadOff,
      short aadLen, byte[] ivBuf, short ivOff, byte[] pt, short ptOff,
      short ptLen, byte[] out, short outOff) {
    Util.arrayCopyNonAtomic(ivBuf, ivOff, out, outOff, CBC_IV_LEN);
    cbc.init(encKey, Cipher.MODE_ENCRYPT, ivBuf, ivOff, CBC_IV_LEN);
    short ctLen = cbc.doFinal(pt, ptOff, ptLen, out,
        (short) (outOff + CBC_IV_LEN));
    short macLen = (short) (aadLen + CBC_IV_LEN + ctLen);
    short macOff = (short) (ws.length - HKDF_OUT_LEN);
    if ((short) (SHA256_BLOCK_LEN + macLen + HKDF_OUT_LEN) > ws.length) {
      CryptoException.throwIt(CryptoException.ILLEGAL_USE); // callers wipe
    }
    // Stage aad || iv || ct at ws[64..); iv || ct are contiguous in `out`.
    Util.arrayCopyNonAtomic(aadBuf, aadOff, ws, SHA256_BLOCK_LEN, aadLen);
    Util.arrayCopyNonAtomic(out, outOff, ws,
        (short) (SHA256_BLOCK_LEN + aadLen), (short) (CBC_IV_LEN + ctLen));
    hmacFromWorkspace(md, ws, ws, macOff, macKey, (short) 0, HKDF_OUT_LEN,
        macLen, ws, macOff);
    Util.arrayCopyNonAtomic(ws, macOff, out,
        (short) (outOff + CBC_IV_LEN + ctLen), TAG_LEN);
    return (short) (CBC_IV_LEN + ctLen + TAG_LEN);
  }

  /**
   * Open a suite-2 payload iv || ct || mac (iv at ivOff, ct at
   * ctOff == ivOff + CBC_IV_LEN, mac right after ct, all within `in`). The
   * MAC is checked BEFORE decrypting (constant-time via arrayCompare), so a
   * failed MAC never decrypts and never leaks padding behaviour.
   *
   * @return plaintext length (M2 padding stripped) in out[outOff..], or -1
   *         if the MAC does not validate or padding is broken
   */
  private static short openCbcHmac(MessageDigest md, Cipher cbc,
      AESKey encKey, byte[] macKey, byte[] ws, byte[] aadBuf, short aadOff,
      short aadLen, byte[] in, short ivOff, short ctOff, short ctLen,
      byte[] out, short outOff) {
    short macLen = (short) (aadLen + CBC_IV_LEN + ctLen);
    short macOff = (short) (ws.length - HKDF_OUT_LEN);
    if ((short) (SHA256_BLOCK_LEN + macLen + HKDF_OUT_LEN) > ws.length
        || ctOff != (short) (ivOff + CBC_IV_LEN)) {
      return -1;
    }
    // Stage aad || iv || ct at ws[64..); iv || ct are contiguous in `in`.
    Util.arrayCopyNonAtomic(aadBuf, aadOff, ws, SHA256_BLOCK_LEN, aadLen);
    Util.arrayCopyNonAtomic(in, ivOff, ws,
        (short) (SHA256_BLOCK_LEN + aadLen), (short) (CBC_IV_LEN + ctLen));
    hmacFromWorkspace(md, ws, ws, macOff, macKey, (short) 0, HKDF_OUT_LEN,
        macLen, ws, macOff);
    if (Util.arrayCompare(ws, macOff, in, (short) (ctOff + ctLen), TAG_LEN) != 0) {
      return -1;
    }
    cbc.init(encKey, Cipher.MODE_DECRYPT, in, ivOff, CBC_IV_LEN);
    try {
      return cbc.doFinal(in, ctOff, ctLen, out, outOff);
    } catch (CryptoException paddingBroken) {
      // Valid MAC but malformed M2 padding - reject anyway.
      return -1;
    }
  }

  /**
   * Suite-aware seal: writes iv || ct || tag/mac into out[outOff..] and
   * returns the total length. macKeyBuf is only used by suite 2.
   */
  private short seal(AESKey encKey, byte[] macKeyBuf, byte[] aadBuf,
      short aadOff, short aadLen, byte[] ivBuf, short ivOff, byte[] pt,
      short ptOff, short ptLen, byte[] out, short outOff) {
    if (suite == SUITE_GCM) {
      return sealGcm(gcm, encKey, aadBuf, aadOff, aadLen, ivBuf, ivOff, pt,
          ptOff, ptLen, out, outOff);
    }
    return sealCbcHmac(sha256, cbc, encKey, macKeyBuf, decBuf, aadBuf, aadOff,
        aadLen, ivBuf, ivOff, pt, ptOff, ptLen, out, outOff);
  }

  /**
   * Suite-aware open of iv || ct || tag/mac from `in`; plaintext lands in
   * decBuf[0..).
   *
   * @return plaintext length, or -1 on authentication failure (suite 1
   *         reports ctLen on success)
   */
  private short openMsg(AESKey encKey, byte[] macKeyBuf, byte[] aadBuf,
      short aadOff, short aadLen, byte[] in, short ivOff, short ctOff,
      short ctLen) {
    if (suite == SUITE_GCM) {
      return gcmOpen(encKey, aadBuf, aadOff, aadLen, in, ivOff, ctOff, ctLen)
          ? ctLen
          : (short) -1;
    }
    return openCbcHmac(sha256, cbc, encKey, macKeyBuf, decBuf, aadBuf, aadOff,
        aadLen, in, ivOff, ctOff, ctLen, decBuf, (short) 0);
  }

  private static boolean openGcm(AEADCipher cipher, AESKey key,
      byte[] aadBuf, short aadOff, short aadLen, byte[] in, short ivOff,
      short ctOff, short ctLen, byte[] out, short outOff) {
    short tagOff = (short) (ctOff + ctLen);
    try {
      // Spec form: doFinal(ct) -> pt, then verifyTag(wire tag).
      cipher.init(key, Cipher.MODE_DECRYPT, in, ivOff, GCM_IV_LEN);
      cipher.updateAAD(aadBuf, aadOff, aadLen);
      short dlen = cipher.doFinal(in, ctOff, ctLen, out, outOff);
      return dlen == ctLen
          && cipher.verifyTag(in, tagOff, TAG_LEN, TAG_LEN);
    } catch (CryptoException specMismatch) {
      try {
        // jcardsim/BC form: doFinal(ct || tag), tag verified internally.
        cipher.init(key, Cipher.MODE_DECRYPT, in, ivOff, GCM_IV_LEN);
        cipher.updateAAD(aadBuf, aadOff, aadLen);
        short dlen = cipher.doFinal(in, ctOff, (short) (ctLen + TAG_LEN), out,
            outOff);
        return dlen == ctLen;
      } catch (CryptoException bcMismatch) {
        return false;
      }
    }
  }

  /** HKDF-Extract: PRK = HMAC-SHA256(key = salt, msg = Z). */
  private void hkdfExtract(short zLen) {
    hmacSha256(salt, (short) 0, (short) salt.length,
        zBuf, (short) 0, zLen, prk, (short) 0);
    Util.arrayFillNonAtomic(salt, (short) 0, (short) salt.length, (byte) 0);
    Util.arrayFillNonAtomic(zBuf, (short) 0, (short) zBuf.length, (byte) 0);
  }

  /**
   * HKDF-Expand single output block: T(1) = HMAC-SHA256(key = PRK,
   * info || 0x01). All derived keys here are &lt;= 32 bytes, so the
   * multi-block loop of RFC 5869 section 2.3 is not needed.
   */
  private void hkdfExpand(byte[] label, short labelOff, byte[] out) {
    Util.arrayCopyNonAtomic(label, labelOff, scratch, (short) 0,
        (short) label.length);
    scratch[(short) label.length] = (byte) 0x01;
    hmacSha256(prk, (short) 0, HKDF_OUT_LEN, scratch, (short) 0,
        (short) (label.length + 1), out, (short) 0);
  }

  /**
   * HMAC-SHA-256 (RFC 2104) built directly on MessageDigest(ALG_SHA_256).
   *
   * <p>Java Card's {@code HMACKey} length semantics are not portable: the
   * Oracle simulator reads {@code buildKey}'s length argument as bits, while
   * jcardsim reads the same {@code LENGTH_HMAC_*} constant as bytes, so
   * {@code setKey} throws {@code ILLEGAL_VALUE} on one runtime and works on
   * the other. Doing the standard HMAC construction here relies only on the
   * SHA-256 digest, which behaves identically everywhere.
   *
   * <p>HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m)) where K' is K
   * zero-padded (or hashed if longer) to the 64-byte block size.
   */
  private void hmacSha256(byte[] key, short keyOff, short keyLen, byte[] msg,
      short msgOff, short msgLen, byte[] out, short outOff) {
    hmacSha256(sha256, decBuf, hmacInner, key, keyOff, keyLen, msg, msgOff,
        msgLen, out, outOff);
  }

  /**
   * Static HMAC-SHA-256 core (RFC 2104) over a contiguous message. {@code ws}
   * is the pad||message workspace (at least 64 + msgLen bytes) and
   * {@code inner} a 32-byte scratch; the caller supplies both so the same
   * routine serves HKDF (during handshake) and the CBC-HMAC suite.
   */
  private static void hmacSha256(MessageDigest md, byte[] ws, byte[] inner,
      byte[] key, short keyOff, short keyLen, byte[] msg, short msgOff,
      short msgLen, byte[] out, short outOff) {
    Util.arrayCopyNonAtomic(msg, msgOff, ws, SHA256_BLOCK_LEN, msgLen);
    hmacFromWorkspace(md, ws, inner, (short) 0, key, keyOff, keyLen, msgLen,
        out, outOff);
  }

  /**
   * HMAC-SHA-256 over a message already staged at ws[64..64+msgLen); ws must
   * be at least 64 + msgLen bytes. Keys in this protocol are always <= the
   * hash block size, so per RFC 2104 the padded key K' is the key
   * zero-extended to 64 bytes. Single-shot digests are used (instead of
   * update() + doFinal()) because multi-part MessageDigest behaviour is not
   * uniform across runtimes.
   */
  private static void hmacFromWorkspace(MessageDigest md, byte[] ws,
      byte[] innerBuf, short innerOff, byte[] key, short keyOff,
      short keyLen, short msgLen, byte[] out, short outOff) {
    // inner = H((K' ^ ipad) || msg)
    fillPadBlock(ws, key, keyOff, keyLen, (byte) 0x36);
    md.doFinal(ws, (short) 0, (short) (SHA256_BLOCK_LEN + msgLen), innerBuf,
        innerOff);
    // out = H((K' ^ opad) || inner)
    fillPadBlock(ws, key, keyOff, keyLen, (byte) 0x5c);
    Util.arrayCopyNonAtomic(innerBuf, innerOff, ws, SHA256_BLOCK_LEN,
        HKDF_OUT_LEN);
    md.doFinal(ws, (short) 0, (short) (SHA256_BLOCK_LEN + HKDF_OUT_LEN), out,
        outOff);
  }

  /** Writes key zero-padded to 64 bytes XOR pad into dst[0..64). */
  private static void fillPadBlock(byte[] dst, byte[] key, short keyOff,
      short keyLen, byte pad) {
    short i;
    for (i = (short) 0; i < keyLen; i++) {
      dst[i] = (byte) (key[(short) (keyOff + i)] ^ pad);
    }
    for (; i < SHA256_BLOCK_LEN; i++) {
      dst[i] = pad;
    }
  }

  private void increment(byte[] counter, short off) {
    for (byte i = (byte) (SEQ_LEN - 1); i >= 0; i--) {
      short pos = (short) (off + i);
      short v = (short) (counter[pos] & 0x00FF);
      if (v < 0xFF) {
        counter[pos] = (byte) (v + 1);
        break;
      }
      counter[pos] = (byte) 0;
    }
  }

  private void wipeSession() {
    sessionActive = false;
    Util.arrayFillNonAtomic(rxPrefix, (short) 0, PREFIX_LEN, (byte) 0);
    Util.arrayFillNonAtomic(txPrefix, (short) 0, PREFIX_LEN, (byte) 0);
    Util.arrayFillNonAtomic(lastRxSeq, (short) 0, SEQ_LEN, (byte) 0);
    Util.arrayFillNonAtomic(txSeq, (short) 0, SEQ_LEN, (byte) 0);
    Util.arrayFillNonAtomic(prk, (short) 0, HKDF_OUT_LEN, (byte) 0);
    Util.arrayFillNonAtomic(zBuf, (short) 0, HKDF_OUT_LEN, (byte) 0);
    Util.arrayFillNonAtomic(salt, (short) 0, HKDF_OUT_LEN, (byte) 0);
    Util.arrayFillNonAtomic(tmp, (short) 0, HKDF_OUT_LEN, (byte) 0);
    Util.arrayFillNonAtomic(hmacInner, (short) 0, HKDF_OUT_LEN, (byte) 0);
    if (macKey != null) {
      Util.arrayFillNonAtomic(macKey, (short) 0, HKDF_OUT_LEN, (byte) 0);
      Util.arrayFillNonAtomic(confMacKey, (short) 0, HKDF_OUT_LEN, (byte) 0);
    }
    Util.arrayFillNonAtomic(decBuf, (short) 0, (short) decBuf.length, (byte) 0);
    try {
      msgKey.clearKey();
      confKey.clearKey();
    } catch (CryptoException e) {
      // key was never set - nothing to clear
    }
  }
}
