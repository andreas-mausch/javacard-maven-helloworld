package helloworld.integration;

import static org.assertj.core.api.Assertions.assertThat;

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

  private static CardSimulator simulator;

  private byte[] secureAidBytes;
  private SecureChannelClient client;

  @BeforeAll
  static void beforeAll() throws IOException {
    simulator = new CardSimulator();

    install(HELLO_AID_HEX, HelloWorldApplet.class);
    install(SECURE_AID_HEX, SecureChannelApplet.class);
  }

  private static void install(String aidHex,
      Class<? extends javacard.framework.Applet> appletClass)
      throws IOException {
    byte[] aidBytes = Hex.decode(aidHex);
    AID aid = AIDUtil.create(aidBytes);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(aidBytes.length);
    bos.write(aidBytes);
    simulator.installApplet(aid, appletClass, bos.toByteArray(), (short) 0,
        (byte) bos.size());
    bos.close();
  }

  @BeforeEach
  void beforeEach() {
    simulator.reset();
    secureAidBytes = Hex.decode(SECURE_AID_HEX);
    client = new SecureChannelClient(simulator, secureAidBytes);
    client.select();
  }

  @Test
  public void testHandshakeAndSecretPing() throws Exception {
    client.handshake();

    byte[] message = "grüße, karte!".getBytes("UTF-8");
    CommandAPDU cmd = client.protect(SecureChannelClient.INS_SECRET_PING,
        message);
    ResponseAPDU resp = client.transmit(cmd);
    assertThat(resp.getSW()).isEqualTo(SW_OK);
    assertThat(client.open(SecureChannelClient.INS_SECRET_PING, resp))
        .isEqualTo(message);
  }

  @Test
  public void testMultipleCommandsInSession() throws Exception {
    client.handshake();
    for (int i = 0; i < 5; i++) {
      byte[] message = ("msg-" + i).getBytes();
      CommandAPDU cmd = client.protect(SecureChannelClient.INS_SECRET_PING,
          message);
      ResponseAPDU resp = client.transmit(cmd);
      assertThat(resp.getSW()).isEqualTo(SW_OK);
      assertThat(client.open(SecureChannelClient.INS_SECRET_PING, resp))
          .isEqualTo(message);
    }
  }

  @Test
  public void testProtectedCommandRejectedWithoutHandshake() {
    // Without a handshake there is no session key, so any well-shaped but
    // random payload must be rejected outright.
    ResponseAPDU resp = client.transmit(new CommandAPDU(0x80,
        SecureChannelClient.INS_SECRET_PING, 0, 0, new byte[28]));
    assertThat(resp.getSW()).isEqualTo(SW_SECURITY_NOT_SATISFIED);
  }

  @Test
  public void testTamperedCommandWipesSession() throws Exception {
    client.handshake();

    CommandAPDU cmd = client.protect(SecureChannelClient.INS_SECRET_PING,
        "original".getBytes());
    byte[] tampered = cmd.getBytes().clone();
    tampered[tampered.length - 3] ^= 0x01; // flip one ciphertext byte
    assertThat(client.transmit(new CommandAPDU(tampered)).getSW())
        .isEqualTo(SW_SECURITY_NOT_SATISFIED);

    // Session must be dead: even the untouched command is rejected now.
    assertThat(client.transmit(cmd).getSW())
        .isEqualTo(SW_SECURITY_NOT_SATISFIED);

    // ... until a fresh handshake.
    client.handshake();
    CommandAPDU fresh = client.protect(SecureChannelClient.INS_SECRET_PING,
        "again".getBytes());
    assertThat(client.transmit(fresh).getSW()).isEqualTo(SW_OK);
  }

  @Test
  public void testReplayIsRejected() throws Exception {
    client.handshake();

    CommandAPDU cmd = client.protect(SecureChannelClient.INS_SECRET_PING,
        "once".getBytes());
    assertThat(client.transmit(cmd).getSW()).isEqualTo(SW_OK);

    // Replay of the exact same APDU (same sequence number).
    assertThat(client.transmit(cmd).getSW())
        .isEqualTo(SW_SECURITY_NOT_SATISFIED);
  }

  @Test
  public void testDeselectWipesSession() throws Exception {
    client.handshake();
    CommandAPDU cmd = client.protect(SecureChannelClient.INS_SECRET_PING,
        "before".getBytes());
    assertThat(client.transmit(cmd).getSW()).isEqualTo(SW_OK);

    // Select the other applet: triggers deselect of the secure applet.
    simulator.selectApplet(AIDUtil.create(Hex.decode(HELLO_AID_HEX)));
    client.select();

    // Old session data (prefix/seq state) is gone -> rejected.
    assertThat(client.transmit(cmd).getSW())
        .isEqualTo(SW_SECURITY_NOT_SATISFIED);

    client.handshake();
    CommandAPDU fresh = client.protect(SecureChannelClient.INS_SECRET_PING,
        "after".getBytes());
    assertThat(client.transmit(fresh).getSW()).isEqualTo(SW_OK);
  }

  @Test
  public void testNewInitInvalidatesPendingExchange() throws Exception {
    // INIT once and build the matching EXCHANGE, but do not send it yet.
    ResponseAPDU init = client.transmit(
        new CommandAPDU(0x80, 0x10, 0, 0, 255));
    assertThat(init.getSW()).isEqualTo(SW_OK);
    byte[] body = client.startExchange(init.getData());

    // A fresh INIT rotates the card's ephemeral key and nonce.
    assertThat(client.transmit(new CommandAPDU(0x80, 0x10, 0, 0, 255)).getSW())
        .isEqualTo(SW_OK);

    // The pending EXCHANGE is bound to the rotated transcript -> rejected.
    assertThat(client.transmit(new CommandAPDU(0x80, 0x12, 0, 0, body)).getSW())
        .isEqualTo(SW_SECURITY_NOT_SATISFIED);
  }

  @Test
  public void testWrongCla() {
    ResponseAPDU resp = client.transmit(
        new CommandAPDU(0x00, 0x10, 0, 0, 0));
    assertThat(resp.getSW()).isEqualTo(0x6E00);
  }

  @Test
  public void testHelloWorldUnaffectedInSameSimulator() {
    simulator.selectApplet(AIDUtil.create(Hex.decode(HELLO_AID_HEX)));
    ResponseAPDU resp = client.transmit(
        new CommandAPDU(0x80, 0x00, 0, 0));
    assertThat(resp.getSW()).isEqualTo(SW_OK);
    assertThat(resp.getData()).isEqualTo("Hello".getBytes());
  }
}
