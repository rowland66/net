package org.rowland.jinix.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TestHarness {

    public static void main(String[] args) {
        EthernetDevice etherDev = new EthernetDevice("eth0", "tap0");
        InternetProtocolHandler ipHandler = new InternetProtocolHandler(etherDev,
                InternetProtocolHandler.StringToIpAddress("192.168.128.150"),
                InternetProtocolHandler.StringToIpAddress("255.255.255.0"),
                InternetProtocolHandler.StringToIpAddress(("192.168.128.1")));
        etherDev.registerFrameHandler(EthernetFrame.EtherType.IPV4, ipHandler);
        etherDev.open();
        etherDev.up();

        ARPManager.getInstance().sendARPRequest(etherDev,0xC0A8800F);

        while (true) {
            TCPConnection conn = ipHandler.listen(ProtocolHandler.Protocol.TCP, 5000);

            InputStream is = conn.getTCPConnectionInputStream();
            OutputStream os = conn.getTCPConnectionOutputStream();

            try {
                int c;
                while ((c = is.read()) > 0) {
                    //System.out.print((char) c);
                    os.write(c);
                    if ((char) c == '\n') {
                        os.flush();
                    }
                }
                System.out.println("Received EOF on TCPConnection input stream");
                os.write("Goodbye.\n".getBytes());
                os.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            while(conn.getState() != TCPConnection.State.Closed) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    System.exit(0);
                }
            }
        }
        /**
        try {
            int sequenceNumber = 1;
            while (true) {
                long startTime = System.currentTimeMillis();
                ipHandler.sendIMCPEcho(InternetProtocolHandler.StringToIpAddress("192.168.128.130"), //151.101.65.67
                        1, sequenceNumber++);
                int rtrnSequenceNumber = ipHandler.recvICMPEcho(1000, 1);
                if (rtrnSequenceNumber < 0) {
                    System.out.println("Destination unreachable");
                    continue;
                }
                long pingTime = System.currentTimeMillis() - startTime;
                System.out.println("Received response, seq="+rtrnSequenceNumber+", time="+pingTime);
                long sleepTime = 1000 - pingTime;
                if (sleepTime > 0) {
                    Thread.currentThread().sleep(sleepTime);
                }
            }
        } catch (InterruptedException e) {
            System.exit(0);
        }
        **/

    }
}
