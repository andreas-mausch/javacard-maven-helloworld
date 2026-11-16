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
 * Applet with an ECDH + HKDF-SHA256 + AES-256-GCM secure channel.
 *
 * <h2>Protocol (version 1)</h2>
 *
 * <pre>
 * CLA = 0x80
 *
 * INIT (INS 0x10, no data) -&gt;
 *   out: Q_card (65B uncompressed EC point, secp256r1) || N_card (16B nonce)
 *   Regenerates the ephemeral ECDH key pair and wipes any active session.
 *
 * EXCHANGE (INS 0x12) -&gt;
 *   in:  Q_peer (65B) || N_peer (16B) || iv_c (12B) || conf_token (16B ct)
 *        || conf_tag (16B)
 *   out: iv_s (12B) || conf_token_s (16B ct) || conf_tag_s (16B)
 *
 *   Z       = ECDH(d_card, Q_peer)                       (32B, plain X coord)
 *   salt    = N_card || N_peer
 *   PRK     = HKDF-Extract(salt, Z)                      (HMAC-SHA-256)
 *   K_conf  = HKDF-Expand(PRK, "SCv1-conf" || 0x01)[0..16)
 *   K_msg   = HKDF-Expand(PRK, "SCv1-msg"  || 0x01)[0..32)
 *   conf_token = AES-GCM(K_conf, iv_c, pt = 16 zero bytes,
 *                        aad = Q_card || Q_peer || N_card || N_peer || 0x00)
 *   The card checks the token (key confirmation) and answers with its own
 *   token bound to direction byte 0x01. On success a session is active.
 *
 * PROTECTED COMMAND (e.g. INS 0xB0 SECRET_PING) -&gt;
 *   in:  iv (12B = N_card[0..4) || seq(8B, big endian, strictly increasing))
 *        || ciphertext || tag (16B)
 *   out: iv (12B = N_peer[0..4) || resp_seq(8B)) || ciphertext || tag (16B)
 *   aad (request)  = CLA || INS || P1 || P2 || Lc || iv   (17B)
 *   aad (response) = INS || iv                             (13B)
 *   Only accepted while a session is active, otherwise 0x6982.
 *   Any integrity failure wipes the session (re-handshake required).
 * </pre>
 *
 * <h2>Security notes</h2>
 *
 * <ul>
 * <li>Forward secrecy: yes (ephemeral on both sides).</li>
 * <li>Mutual key confirmation: yes (tokens bound to the full transcript).</li>
 * <li>Replay protection: strictly increasing, direction-bound sequence
 * numbers authenticated via the IV inside the AAD.</li>
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
  private static final short IV_LEN = 12;
  private static final short TAG_LEN = 16;
  private static final short SEQ_LEN = 8;
  private static final short PREFIX_LEN = 4;
  private static final short HKDF_OUT_LEN = 32;
  private static final short SHA256_BLOCK_LEN = 64;
  private static final short EXCHANGE_LC = EC_POINT_LEN + NONCE_LEN + IV_LEN
      + HKDF_OUT_LEN / 2 + TAG_LEN; // = 125
  private static final short TOKEN_PT_LEN = 16;
  private static final short TRANSRIPT_LEN = EC_POINT_LEN * 2 + NONCE_LEN * 2 + 1;

  // --- HKDF info labels (RFC 5869) ---------------------------------------

  private static final byte[] LABEL_CONF = {
      'S', 'C', 'v', '1', '-', 'c', 'o', 'n', 'f'};
  private static final byte[] LABEL_MSG = {
      'S', 'C', 'v', '1', '-', 'm', 's', 'g'};

  /** Known plaintext of the confirmation tokens (all zeros, length 16). */
  private static final byte[] CONF_PT = new byte[TOKEN_PT_LEN];

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
  private AEADCipher gcm;
  private MessageDigest sha256;
  private RandomData random;

  /** Session message key (AES-256), transient. */
  private AESKey msgKey;
  /** Handshake confirmation key (AES-128), transient. */
  private AESKey confKey;

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

  // ------------------------------------------------------------------------

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new SecureChannelApplet().register(bArray, (short) (bOffset + 1),
        bArray[bOffset]);
  }

  private SecureChannelApplet() {
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
    gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

    msgKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
        KeyBuilder.LENGTH_AES_256, false);
    confKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
        KeyBuilder.LENGTH_AES_128, false);

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
    decBuf = JCSystem.makeTransientByteArray((short) 256,
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
    apdu.setOutgoingAndSend((short) 0, (short) (len + NONCE_LEN));
  }

  // --- EXCHANGE -----------------------------------------------------------

  private void exchange(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short lc = apdu.setIncomingAndReceive();
    short cdata = ISO7816.OFFSET_CDATA;

    if (lc != EXCHANGE_LC || buffer[cdata] != 0x04) {
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

    // K_conf -> confKey, K_msg -> msgKey
    hkdfExpand(LABEL_CONF, (short) 0, tmp);
    confKey.setKey(tmp, (short) 0);
    Util.arrayFillNonAtomic(tmp, (short) 0, HKDF_OUT_LEN, (byte) 0);
    hkdfExpand(LABEL_MSG, (short) 0, tmp);
    msgKey.setKey(tmp, (short) 0);
    Util.arrayFillNonAtomic(tmp, (short) 0, HKDF_OUT_LEN, (byte) 0);
    Util.arrayFillNonAtomic(prk, (short) 0, HKDF_OUT_LEN, (byte) 0);
    // Scrub HMAC key-schedule scratch (derived from salt/PRK).
    Util.arrayFillNonAtomic(hmacInner, (short) 0, HKDF_OUT_LEN, (byte) 0);

    // transcript = Q_card || Q_peer || N_card || N_peer
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
    transcript[off] = 0x00; // direction: client -> card

    short ivOff = (short) (cdata + EC_POINT_LEN + NONCE_LEN);
    short ctOff = (short) (ivOff + IV_LEN);

    // Verify the client confirmation token (see gcmOpen() for why decrypting
    // needs a runtime-portability dance).
    if (!gcmOpen(confKey, transcript, (short) 0, TRANSRIPT_LEN, buffer, ivOff,
        ctOff, TOKEN_PT_LEN)
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
    random.nextBytes(scratch, (short) 0, IV_LEN);
    gcm.init(confKey, Cipher.MODE_ENCRYPT, scratch, (short) 0, IV_LEN);
    gcm.updateAAD(transcript, (short) 0, TRANSRIPT_LEN);
    gcm.doFinal(CONF_PT, (short) 0, TOKEN_PT_LEN, buffer, IV_LEN);
    gcm.retrieveTag(buffer, (short) (IV_LEN + TOKEN_PT_LEN), TAG_LEN);
    Util.arrayCopyNonAtomic(scratch, (short) 0, buffer, (short) 0, IV_LEN);
    apdu.setOutgoingAndSend((short) 0, (short) (IV_LEN + TOKEN_PT_LEN + TAG_LEN));
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
    if (lc < IV_LEN + TAG_LEN) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    short ivOff = ISO7816.OFFSET_CDATA;

    // IV must carry this session's prefix and a strictly increasing seq.
    if (Util.arrayCompare(buffer, ivOff, rxPrefix, (short) 0, PREFIX_LEN) != 0
        || Util.arrayCompare(buffer, (short) (ivOff + PREFIX_LEN), lastRxSeq,
            (short) 0, SEQ_LEN) <= 0) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // Payload = iv (12B) || ct || tag (16B). aad = header (CLA..Lc, 5B) || iv,
    // which is contiguous here because the iv starts at OFFSET_CDATA.
    short ctLen = (short) (lc - IV_LEN - TAG_LEN);
    short aadLen = (short) (ISO7816.OFFSET_CDATA + IV_LEN);
    if (!gcmOpen(msgKey, buffer, (short) 0, aadLen, buffer, ivOff,
        (short) (ivOff + IV_LEN), ctLen)) {
      wipeSession();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    Util.arrayCopyNonAtomic(buffer, (short) (ivOff + PREFIX_LEN), lastRxSeq,
        (short) 0, SEQ_LEN);

    // Response: aad = INS || iv_resp, iv_resp = N_peer[0..4) || txSeq++
    increment(txSeq, (short) 0);
    scratch[0] = buffer[ISO7816.OFFSET_INS];
    Util.arrayCopyNonAtomic(txPrefix, (short) 0, scratch, (short) 1, PREFIX_LEN);
    Util.arrayCopyNonAtomic(txSeq, (short) 0, scratch, (short) 5, SEQ_LEN);

    try {
      gcm.init(msgKey, Cipher.MODE_ENCRYPT, scratch, (short) 1, IV_LEN);
      gcm.updateAAD(scratch, (short) 0, (short) (1 + IV_LEN));
      gcm.doFinal(decBuf, (short) 0, ctLen, buffer, IV_LEN);
      gcm.retrieveTag(buffer, (short) (IV_LEN + ctLen), TAG_LEN);
    } catch (CryptoException e) {
      wipeSession();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      return; // not reached
    }
    Util.arrayCopyNonAtomic(scratch, (short) 1, buffer, (short) 0, IV_LEN);
    apdu.setOutgoingAndSend((short) 0, (short) (IV_LEN + ctLen + TAG_LEN));
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
    short tagOff = (short) (ctOff + ctLen);
    try {
      // Spec form: doFinal(ct) -> pt, then verifyTag(wire tag).
      gcm.init(key, Cipher.MODE_DECRYPT, in, ivOff, IV_LEN);
      gcm.updateAAD(aadBuf, aadOff, aadLen);
      short dlen = gcm.doFinal(in, ctOff, ctLen, decBuf, (short) 0);
      return dlen == ctLen && gcm.verifyTag(in, tagOff, TAG_LEN, TAG_LEN);
    } catch (CryptoException specMismatch) {
      try {
        // jcardsim/BC form: doFinal(ct || tag), tag verified internally.
        gcm.init(key, Cipher.MODE_DECRYPT, in, ivOff, IV_LEN);
        gcm.updateAAD(aadBuf, aadOff, aadLen);
        short dlen = gcm.doFinal(in, ctOff, (short) (ctLen + TAG_LEN), decBuf,
            (short) 0);
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
    // Keys in this protocol (HKDF salt and PRK) are always <= hash block
    // size, so per RFC 2104 the padded key K' is just the key zero-extended
    // to 64 bytes. A single-shot digest over a combined buffer is used
    // (instead of update() + doFinal()) because multi-part MessageDigest
    // behaviour is not uniform across runtimes.
    //
    // inner = H((K' ^ ipad) || msg)
    // out = H((K' ^ opad) || inner)
    //
    // decBuf (256B, unused while HKDF runs) is the pad||message workspace.
    fillPadBlock(decBuf, key, keyOff, keyLen, (byte) 0x36);
    Util.arrayCopyNonAtomic(msg, msgOff, decBuf, SHA256_BLOCK_LEN, msgLen);
    sha256.doFinal(decBuf, (short) 0, (short) (SHA256_BLOCK_LEN + msgLen),
        hmacInner, (short) 0);
    fillPadBlock(decBuf, key, keyOff, keyLen, (byte) 0x5c);
    Util.arrayCopyNonAtomic(hmacInner, (short) 0, decBuf, SHA256_BLOCK_LEN,
        HKDF_OUT_LEN);
    sha256.doFinal(decBuf, (short) 0,
        (short) (SHA256_BLOCK_LEN + HKDF_OUT_LEN), out, outOff);
  }

  /** Writes key zero-padded to 64 bytes XOR pad into dst[0..64). */
  private void fillPadBlock(byte[] dst, byte[] key, short keyOff,
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
    Util.arrayFillNonAtomic(decBuf, (short) 0, (short) decBuf.length, (byte) 0);
    try {
      msgKey.clearKey();
      confKey.clearKey();
    } catch (CryptoException e) {
      // key was never set - nothing to clear
    }
  }
}
