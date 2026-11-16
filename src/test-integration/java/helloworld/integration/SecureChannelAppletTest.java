package helloworld.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import helloworld.HelloWorldApplet;
import helloworld.SecureChannelApplet;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SecureChannelAppletTest {

  // Applet instance AIDs, injected by javacard-parent / pom.xml.
  private static final String HELLO_AID_HEX = System.getProperty("javacard.applet.id.nocolons");
  private static final String SECURE_AID_HEX = System.getProperty("javacard.secure.applet.id.nocolons");

  private static final int SW_OK = 0x9000;
  private static final int SW_SECURITY_NOT_SATISFIED = 0x6982;

  private static final byte SUITE_GCM = SecureChannelClient.SUITE_GCM;
  private static final byte SUITE_CBC_HMAC = SecureChannelClient.SUITE_CBC_HMAC;

  private static CardSimulator simulator;
  private static byte[] secureAidBytes;
  private static byte[] secureCbcAidBytes;

  private SecureChannelClient client;

  @BeforeAll
  static void beforeAll() throws IOException {
    simulator = new CardSimulator();
    secureAidBytes = Hex.decode(SECURE_AID_HEX);
    secureCbcAidBytes = variantAid(secureAidBytes, (byte) 1);

    install(HELLO_AID_HEX, HelloWorldApplet.class, null);
    install(secureAidBytes, SecureChannelApplet.class, SUITE_GCM);
    install(secureCbcAidBytes, SecureChannelApplet.class, SUITE_CBC_HMAC);
  }

  /**
   * Installs with a full GP INSTALL data block: {@code [aidLen][aid]
   * [capsLen][caps][dataLen][suite]}. A null suite installs without private
   * data (used for HelloWorld, which ignores it).
   */
  private static void install(byte[] aidBytes,
      Class<? extends javacard.framework.Applet> appletClass, Byte suite) {
    AID aid = AIDUtil.create(aidBytes);
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      bos.write(aidBytes.length);
      bos.write(aidBytes);
      bos.write(0x01); // card capabilities: one byte
      bos.write(0x00);
      bos.write(suite == null ? 0x00 : 0x01);
      if (suite != null) {
        bos.write(suite);
      }
      simulator.installApplet(aid, appletClass, bos.toByteArray(), (short) 0,
          (byte) bos.size());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static void install(String aidHex,
      Class<? extends javacard.framework.Applet> appletClass, Byte suite) {
    install(Hex.decode(aidHex), appletClass, suite);
  }

  private static byte[] variantAid(byte[] base, byte delta) {
    byte[] b = base.clone();
    b[b.length - 1] = (byte) (b[b.length - 1] + delta);
    return b;
  }

  private SecureChannelClient clientFor(byte[] aid, byte suite) {
    SecureChannelClient c = new SecureChannelClient(simulator, aid, suite);
    c.select();
    return c;
  }

  @BeforeEach
  void beforeEach() {
    simulator.reset();
    client = clientFor(secureAidBytes, SUITE_GCM);
  }

  // --- core scenarios, run for BOTH cipher suites ---------------------------

  @Test
  public void testHandshakeAndSecretPingGcm() throws Exception {
    runHandshakeAndPing(clientFor(secureAidBytes, SUITE_GCM));
  }

  @Test
  public void testHandshakeAndSecretPingCbcHmac() throws Exception {
    runHandshakeAndPing(clientFor(secureCbcAidBytes, SUITE_CBC_HMAC));
  }

  private void runHandshakeAndPing(SecureChannelClient c) throws Exception {
    c.handshake();
    for (int i = 0; i < 5; i++) {
      byte[] message = ("msg-" + i).getBytes();
      CommandAPDU cmd = c.protect(SecureChannelClient.INS_SECRET_PING, message);
      ResponseAPDU resp = c.transmit(cmd);
      assertThat(resp.getSW()).isEqualTo(SW_OK);
      assertThat(c.open(SecureChannelClient.INS_SECRET_PING, resp))
          .isEqualTo(message);
    }
  }

  @Test
  public void testTamperedCommandWipesSessionGcm() throws Exception {
    runTamperWipes(clientFor(secureAidBytes, SUITE_GCM));
  }

  @Test
  public void testTamperedCommandWipesSessionCbcHmac() throws Exception {
    runTamperWipes(clientFor(secureCbcAidBytes, SUITE_CBC_HMAC));
  }

  private void runTamperWipes(SecureChannelClient c) throws Exception {
    c.handshake();
    CommandAPDU cmd = c.protect(SecureChannelClient.INS_SECRET_PING,
        "original".getBytes());
    byte[] tampered = cmd.getBytes().clone();
    tampered[tampered.length - 3] ^= 0x01; // flip one ciphertext byte
    assertThat(c.transmit(new CommandAPDU(tampered)).getSW())
        .isEqualTo(SW_SECURITY_NOT_SATISFIED);

    // Session must be dead: even the untouched command is rejected now.
    assertThat(c.transmit(cmd).getSW()).isEqualTo(SW_SECURITY_NOT_SATISFIED);

    c.handshake();
    CommandAPDU fresh = c.protect(SecureChannelClient.INS_SECRET_PING,
        "again".getBytes());
    assertThat(c.transmit(fresh).getSW()).isEqualTo(SW_OK);
  }

  @Test
  public void testReplayRejectedGcm() throws Exception {
    runReplayRejected(clientFor(secureAidBytes, SUITE_GCM));
  }

  @Test
  public void testReplayRejectedCbcHmac() throws Exception {
    runReplayRejected(clientFor(secureCbcAidBytes, SUITE_CBC_HMAC));
  }

  private void runReplayRejected(SecureChannelClient c) throws Exception {
    c.handshake();
    CommandAPDU cmd = c.protect(SecureChannelClient.INS_SECRET_PING,
        "once".getBytes());
    assertThat(c.transmit(cmd).getSW()).isEqualTo(SW_OK);
    assertThat(c.transmit(cmd).getSW()).isEqualTo(SW_SECURITY_NOT_SATISFIED);
  }

  // --- suite selection & install-parameter enforcement ----------------------

  @Test
  public void testInitEchoesMatchingSuiteByte() throws Exception {
    ResponseAPDU gcmInit = client.transmit(
        new CommandAPDU(0x80, 0x10, 0, 0, 255));
    assertThat(gcmInit.getSW()).isEqualTo(SW_OK);
    assertThat(gcmInit.getData()[gcmInit.getData().length - 1])
        .isEqualTo(SUITE_GCM);

    SecureChannelClient cbc = clientFor(secureCbcAidBytes, SUITE_CBC_HMAC);
    ResponseAPDU cbcInit = cbc.transmit(
        new CommandAPDU(0x80, 0x10, 0, 0, 255));
    assertThat(cbcInit.getData()[cbcInit.getData().length - 1])
        .isEqualTo(SUITE_CBC_HMAC);
  }

  @Test
  public void testClientRefusesSuiteMismatch() throws Exception {
    // A CBC client pointed at the GCM instance must abort during handshake
    // (INIT echoes suite 01, the client expected 02).
    SecureChannelClient mismatch = clientFor(secureAidBytes, SUITE_CBC_HMAC);
    assertThatThrownBy(mismatch::handshake).isInstanceOf(AssertionError.class);
  }

  @Test
  public void testInstallRejectsMissingSuiteParam() {
    byte[] aid = variantAid(secureAidBytes, (byte) 7);
    assertThatThrownBy(() -> install(aid, SecureChannelApplet.class, null))
        .isInstanceOf(Throwable.class);
  }

  @Test
  public void testInstallRejectsUnknownSuite() {
    byte[] aid = variantAid(secureAidBytes, (byte) 8);
    assertThatThrownBy(() -> install(aid, SecureChannelApplet.class, (byte) 0x03))
        .isInstanceOf(Throwable.class);
  }

  // --- runtime behaviours that only exist on one instance -------------------

  @Test
  public void testProtectedCommandRejectedWithoutHandshake() {
    ResponseAPDU resp = client.transmit(new CommandAPDU(0x80,
        SecureChannelClient.INS_SECRET_PING, 0, 0, new byte[28]));
    assertThat(resp.getSW()).isEqualTo(SW_SECURITY_NOT_SATISFIED);
  }

  @Test
  public void testDeselectWipesSession() throws Exception {
    client.handshake();
    CommandAPDU cmd = client.protect(SecureChannelClient.INS_SECRET_PING,
        "before".getBytes());
    assertThat(client.transmit(cmd).getSW()).isEqualTo(SW_OK);

    simulator.selectApplet(AIDUtil.create(Hex.decode(HELLO_AID_HEX)));
    client.select();

    assertThat(client.transmit(cmd).getSW()).isEqualTo(SW_SECURITY_NOT_SATISFIED);

    client.handshake();
    CommandAPDU fresh = client.protect(SecureChannelClient.INS_SECRET_PING,
        "after".getBytes());
    assertThat(client.transmit(fresh).getSW()).isEqualTo(SW_OK);
  }

  @Test
  public void testNewInitInvalidatesPendingExchange() throws Exception {
    ResponseAPDU init = client.transmit(new CommandAPDU(0x80, 0x10, 0, 0, 255));
    assertThat(init.getSW()).isEqualTo(SW_OK);
    byte[] body = client.startExchange(init.getData());

    assertThat(client.transmit(new CommandAPDU(0x80, 0x10, 0, 0, 255)).getSW())
        .isEqualTo(SW_OK);

    assertThat(client.transmit(new CommandAPDU(0x80, 0x12, 0, 0, body)).getSW())
        .isEqualTo(SW_SECURITY_NOT_SATISFIED);
  }

  @Test
  public void testWrongCla() {
    ResponseAPDU resp = client.transmit(new CommandAPDU(0x00, 0x10, 0, 0, 0));
    assertThat(resp.getSW()).isEqualTo(0x6E00);
  }

  @Test
  public void testHelloWorldUnaffectedInSameSimulator() {
    simulator.selectApplet(AIDUtil.create(Hex.decode(HELLO_AID_HEX)));
    ResponseAPDU resp = client.transmit(new CommandAPDU(0x80, 0x00, 0, 0));
    assertThat(resp.getSW()).isEqualTo(SW_OK);
    assertThat(resp.getData()).isEqualTo("Hello".getBytes());
  }
}
