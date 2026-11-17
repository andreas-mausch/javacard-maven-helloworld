package helloworld.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import helloworld.HelloWorldApplet;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class HelloWorldAppletTest {

  // Applet instance AID, injected by javacard-parent from <applet.id> in pom.xml.
  // A default install uses it as the selectable instance AID; the JavaCard package
  // AID is derived from its first 5 bytes (0102030405).
  private static final String APPLET_AID_HEX = System.getProperty("javacard.applet.id.nocolons");
  private static CardSimulator simulator;

  @BeforeAll
  static void beforeAll() throws IOException {
    simulator = new CardSimulator();

    // Install applet; install data carries the AID as [length][bytes], matching the
    // register(bArray, bOffset + 1, bArray[bOffset]) idiom in HelloWorldApplet.
    byte[] aid_bytes = Hex.decode(APPLET_AID_HEX);

    AID aid = AIDUtil.create(aid_bytes);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(aid_bytes.length);
    bos.write(aid_bytes);

    simulator.installApplet(aid, HelloWorldApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.close();
  }

  @BeforeEach
  void beforeEach() throws IOException {
    simulator.reset();

    byte[] aid_bytes = Hex.decode(APPLET_AID_HEX);
    AID aid = AIDUtil.create(aid_bytes);
    assertThat(simulator.selectApplet(aid)).isTrue();
  }

  @Test
  public void testPing() {
    CommandAPDU apdu = new CommandAPDU(0x80, 0x00, 0, 0, 5);
    ResponseAPDU result = simulator.transmitCommand(apdu);
    assertThat(result.getSW()).isEqualTo(0x9000);
    assertThat(result.getData()).isEqualTo("Hello".getBytes());
  }

  @Test
  public void testUnsupportedCLA() {
    CommandAPDU apdu = new CommandAPDU(0x00, 0x00, 0, 0);
    ResponseAPDU result = simulator.transmitCommand(apdu);
    assertThat(result.getSW()).isEqualTo(0x6E00);
  }

  @Test
  public void testUnsupportedINS() {
    CommandAPDU apdu = new CommandAPDU(0x80, 0xFF, 0, 0);
    ResponseAPDU result = simulator.transmitCommand(apdu);
    assertThat(result.getSW()).isEqualTo(0x6D00);
  }
}
