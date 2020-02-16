package org.rowland.jinix.net;

import java.nio.ByteBuffer;
import java.util.*;

/**
 * ARPManager is used by the IPV4 protocol
 */
public class ARPManager implements FrameHandler {
    private static ARPManager singleton;
    List<InterfaceDevice> interfaceDeviceList;

    public ARPManager() {
        interfaceDeviceList = new ArrayList<InterfaceDevice>(4);
    }

    public static synchronized ARPManager getInstance() {
        if (singleton == null) {
            singleton = new ARPManager();
        }
        return singleton;
    }

    public void registerDevice(EthernetDevice dev, long hardwareAddress) {
        String deviceName = dev.getName();
        for (InterfaceDevice id : interfaceDeviceList) {
            if (id.deviceName.equals(deviceName)) {
                if (id.deviceHardwareAddress != hardwareAddress) {
                    id.deviceHardwareAddress = hardwareAddress;
                    id.arpMap.clear();
                }
                return;
            }
        }

        // If we have gotten here, then this is a new device
        InterfaceDevice id = new InterfaceDevice();
        id.deviceName = deviceName;
        id.device = dev;
        id.deviceHardwareAddress = hardwareAddress;
        id.arpMap = new HashMap<Integer, Long>(16);
        interfaceDeviceList.add(id);
    }

    public boolean registerProtocolAddress(EthernetDevice dev, int protocolAddress) {
        String deviceName = dev.getName();
        for (InterfaceDevice id : interfaceDeviceList) {
            if (id.deviceName.equals(deviceName)) {
                id.deviceProtocolAddress = protocolAddress;
                id.arpMap.clear();
                return true;
            }
        }
        return false;
    }

    @Override
    public void processFramePayload(EthernetDevice dev, SocketBuffer skb) {

        ARPPacket packet = new ARPPacket(skb);
        ARPPacket.setupSKB(skb);

        InterfaceDevice id = getInterfaceDevice(dev.getName());

        if (id == null) {
            throw new RuntimeException("Illegal attempt to process message for unknown device: "+dev.getName());
        }

        if (packet.getHardwareType() != 0x01) {
            return;
        }
        if (packet.getProtocolType() != 0x0800) {
            return;
        }

        Integer senderIP = Integer.valueOf(packet.getSenderProtocolAddress());
        synchronized (id) {
            if (senderIP != 0 &&
                    (!id.arpMap.containsKey(senderIP) || !id.arpMap.get(senderIP).equals(Long.valueOf(packet.getSenderHardwareAddress())))) {
                long senderHardwareAddress = Long.valueOf(packet.getSenderHardwareAddress());
                id.arpMap.put(senderIP, senderHardwareAddress);
                //System.out.println("Added address to arpMap: "+
                //     InternetProtocolHandler.ipAddressToString(packet.getSenderProtocolAddress()) + ":" +
                //    EthernetFrame.hardwareAddressToString(packet.getSenderHardwareAddress()));
                if (id.deferredFrames.containsKey(Integer.valueOf(senderIP))) {
                    List<SocketBuffer> deferredFramesList = id.deferredFrames.get(Integer.valueOf(senderIP));
                    for (SocketBuffer deferredFrame : deferredFramesList) {
                        dev.applyEthernetFrame(senderHardwareAddress, EthernetFrame.EtherType.IPV4, deferredFrame);
                        dev.enqueueTransmitEthernetFrame(deferredFrame);
                    }
                    id.deferredFrames.remove(Integer.valueOf(senderIP));
                }
            }
        }

        if (packet.getTargetProtocolAddress() == id.deviceProtocolAddress) {
            if (packet.getOperation() == ARPPacket.OPERATION_REQUEST) {
                packet.setTargetHardwareAddress(packet.getSenderHardwareAddress());
                packet.setTargetProtocolAddress(packet.getSenderProtocolAddress());
                packet.setSenderHardwareAddress(id.deviceHardwareAddress);
                packet.setSenderProtocolAddress(id.deviceProtocolAddress);
                packet.setOperation(ARPPacket.OPERATION_REPLY);

                SocketBuffer rtrnSkb = SocketBuffer.getNextAvailableSocketBuffer();
                rtrnSkb.setPayload(skb.getPayload(), 0);
                dev.applyEthernetFrame(packet.getTargetHardwareAddress(), EthernetFrame.EtherType.ARP, rtrnSkb);
                dev.enqueueTransmitEthernetFrame(rtrnSkb);
            }
        }

        return;
    }

    void sendARPRequest(EthernetDevice etherDev, int protocolAddress) {
        InterfaceDevice id = getInterfaceDevice(etherDev.getName());

        SocketBuffer skb = SocketBuffer.getNextAvailableSocketBuffer();
        ARPPacket packet = new ARPPacket();
        packet.setHardwareType(0x01);
        packet.setProtocolType(0x0800);
        packet.setHardwareAddressLength(6);
        packet.setProtocolAddressLength(4);
        packet.setOperation(ARPPacket.OPERATION_REQUEST);
        packet.setSenderHardwareAddress(id.deviceHardwareAddress);
        packet.setSenderProtocolAddress(id.deviceProtocolAddress);
        packet.setTargetHardwareAddress(0);
        packet.setTargetProtocolAddress(protocolAddress);

        skb.setPayload(packet.getPacketData(), 0);
        etherDev.applyEthernetFrame(EthernetFrame.ETHERNET_BROADCAST_ADDR, EthernetFrame.EtherType.ARP, skb);
        etherDev.enqueueTransmitEthernetFrame(skb);
    }

    Long lookup(EthernetDevice etherDev, int protocolAddress) {
        InterfaceDevice id = getInterfaceDevice(etherDev.getName());

        if (id == null) {
            throw new RuntimeException("Illegal attempt to lookup hardware address for an unknown device: "+etherDev.getName());
        }

        return id.arpMap.get(Integer.valueOf(protocolAddress));
    }

    void resolveAndTransmit(EthernetDevice etherDevice, int protocolAddress, SocketBuffer skb) {

        for (InterfaceDevice id : interfaceDeviceList) {
            if (id.deviceName.equals(etherDevice.getName())) {
                synchronized (id) {
                    if (id.arpMap.containsKey(protocolAddress)) {
                        Long destinationHardwareAddress = id.arpMap.get(protocolAddress);
                        etherDevice.applyEthernetFrame(destinationHardwareAddress, EthernetFrame.EtherType.IPV4, skb);
                        etherDevice.enqueueTransmitEthernetFrame(skb);
                        return;
                    }
                    List<SocketBuffer> deferredFramesList = id.deferredFrames.get(protocolAddress);
                    if (deferredFramesList == null) {
                        deferredFramesList = new LinkedList<SocketBuffer>();
                        id.deferredFrames.put(protocolAddress, deferredFramesList);
                    }
                    //skb.incrementUseCount();
                    deferredFramesList.add(skb);
                }

                sendARPRequest(etherDevice, protocolAddress);
            }
        }
    }

    private InterfaceDevice getInterfaceDevice(String deviceName) {
        for (InterfaceDevice id : interfaceDeviceList) {
            if (id.deviceName.equals(deviceName)) {
                return id;
            }
        }
        return null;
    }

    private static class InterfaceDevice {
        String deviceName;
        EthernetDevice device;
        long deviceHardwareAddress;
        int deviceProtocolAddress;
        Map<Integer,Long> arpMap = new HashMap<>();
        Map<Integer, List<SocketBuffer>> deferredFrames = new HashMap<Integer, List<SocketBuffer>>();
    }
}
