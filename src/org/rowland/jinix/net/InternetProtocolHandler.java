package org.rowland.jinix.net;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

public class InternetProtocolHandler implements Function<SocketBuffer, Boolean> {
    private final EthernetDevice etherDev;
    private final int protocolAddress;
    private final int netmask;
    private final int gatewayAddress;
    short IP4ID;
    Map<ProtocolHandler.Protocol, ProtocolHandler> protocolHandlerMap = new HashMap<>();

    // This will be replaced with a socket concept eventually
    Map<Integer, EchoSynchronizer> echoSynchronizerMap = new HashMap<Integer, EchoSynchronizer>();

    static class EchoSynchronizer {
        CountDownLatch latch;
        int sequenceNumber;

        EchoSynchronizer(int sequenceNumber) {
            latch = new CountDownLatch(1);
            this.sequenceNumber = sequenceNumber;
        }
    }

    InternetProtocolHandler(EthernetDevice device, int protocolAddress, int netmask, int gatewayAddress) {
        this.etherDev = device;
        this.protocolAddress = protocolAddress;
        this.netmask = netmask;
        this.gatewayAddress = gatewayAddress;
        IP4ID = 250;
        registerProtocolHandler(ProtocolHandler.Protocol.ICMP, new ICMPProtocolHandler(this));
        registerProtocolHandler(ProtocolHandler.Protocol.UDP, new UDPProtocolHandler(this));
        registerProtocolHandler(ProtocolHandler.Protocol.TCP, new TCPProtocolHandler(this));
        ARPManager.getInstance().registerProtocolAddress(device, protocolAddress);
    }

    public TCPConnection listen(ProtocolHandler.Protocol protocol, int port) {
        if (protocol == ProtocolHandler.Protocol.TCP) {
            ProtocolHandler handler = protocolHandlerMap.get(protocol);
            return ((TCPProtocolHandler) handler).listen(port);
        }
        throw new IllegalArgumentException();
    }

    int getProtocolAddress() {
        return this.protocolAddress;
    }

    public synchronized void registerProtocolHandler(ProtocolHandler.Protocol protocol, ProtocolHandler handler) {
        this.protocolHandlerMap.put(protocol, handler);
    }

    public Boolean apply(SocketBuffer skb) {

        IP4Packet.setupSKB(skb);
        IP4Packet ip4Packet = new IP4Packet(skb);

        if (ip4Packet.getDestinationAddress() != protocolAddress) {
            return false;
        }

        if (!ip4Packet.hasValidCheckSum()) {
            System.out.println("Received IP4 packet with invalid header checksum");
            return false;
        }

        for (ProtocolHandler.Protocol protocol : ProtocolHandler.Protocol.values()) {
            if (protocol.ipHeaderCode == ip4Packet.getProtocol()) {
                protocolHandlerMap.get(protocol).processMessage(skb);
                break;
            }
        }
        return true;
    }

    void sendIMCPEcho(int destination, int identifier, int sequeneceNumber) {
        ICMPProtocolHandler icmpProtocolHandler = (ICMPProtocolHandler) protocolHandlerMap.get(ProtocolHandler.Protocol.ICMP);
        SocketBuffer skb = icmpProtocolHandler.createEchoRequest(identifier, sequeneceNumber);
        sendIPMessage(destination, ProtocolHandler.Protocol.ICMP, skb);

        Integer id = Integer.valueOf(identifier);
        if (echoSynchronizerMap.containsKey(id)) {
            echoSynchronizerMap.remove(id);
        }
        echoSynchronizerMap.put(id, new EchoSynchronizer(sequeneceNumber));
    }

    int recvICMPEcho(long timeout, int identifier) throws InterruptedException {
        Integer id = Integer.valueOf(identifier);
        if (!echoSynchronizerMap.containsKey(id)) {
            throw new RuntimeException("Illegal call to recvICMPEcho with not outstanding request");
        }
        EchoSynchronizer echoSynchronizer = echoSynchronizerMap.get(id);
        if (echoSynchronizer.latch.await(timeout, TimeUnit.MILLISECONDS)) {
            echoSynchronizerMap.remove(id);
            return echoSynchronizer.sequenceNumber;
        }
        return -1;
    }

    void sendIPMessage(int destination, ProtocolHandler.Protocol protocol, SocketBuffer skb) {
        IP4Packet replyIP4Packet = new IP4Packet(protocol.ipHeaderCode,
                IP4ID++,
                protocolAddress,
                destination,
                skb);

        if ((destination & netmask) != (protocolAddress & netmask)) {
            destination = this.gatewayAddress;
        }

        Long destinationHardwareAddress = ARPManager.getInstance().lookup(etherDev, destination);
        if (destinationHardwareAddress == null) {
            // If lookup fails, ARPManager will send an ARP request to try to resolve the protocol address
            etherDev.applyEthernetFrame(0L, EthernetFrame.EtherType.IPV4, skb);
            ARPManager.getInstance().resolveAndTransmit(etherDev, destination, skb);
            return;
        }
        etherDev.applyEthernetFrame(destinationHardwareAddress, EthernetFrame.EtherType.IPV4, skb);
        etherDev.enqueueTransmitEthernetFrame(skb);
    }

    static String ipAddressToString(int ipAddress) {
        StringBuffer buffer = new StringBuffer();
        buffer.append(Long.toUnsignedString(((long) (ipAddress >> 3*8)) & 0xff, 10)).append(".");
        buffer.append(Long.toUnsignedString(((long) (ipAddress >> 2*8)) & 0xff, 10)).append(".");
        buffer.append(Long.toUnsignedString(((long) (ipAddress >> 1*8)) & 0xff, 10)).append(".");
        buffer.append(Long.toUnsignedString(((long) ipAddress) & 0xff, 10));
        return buffer.toString();
    }

    static int StringToIpAddress(String ipAddressString) {
        StringTokenizer ipAddrStrTokenizer = new StringTokenizer(ipAddressString, ".");
        if (ipAddrStrTokenizer.countTokens() != 4) {
            throw new RuntimeException("Invalid IP Address: "+ipAddressString);
        }
        long ipAddr = 0;
        int shiftBits = 24;
        while (ipAddrStrTokenizer.hasMoreElements()) {
            try {
                String ipAddrStrSection = (String) ipAddrStrTokenizer.nextElement();
                int ipOctet = Integer.parseInt(ipAddrStrSection);
                if (ipOctet < 0 || ipOctet > 0xff) {
                    throw new RuntimeException("Invalid IP Address: "+ipAddressString);
                }
                ipAddr += (Integer.valueOf(ipAddrStrSection).intValue() << shiftBits);
                shiftBits -= 8;
            } catch (NumberFormatException e) {
                throw new RuntimeException("Invalid IP Address: "+ipAddressString);
            }
        }
        return (int) ipAddr;
    }
}
