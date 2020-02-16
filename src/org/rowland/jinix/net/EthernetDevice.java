package org.rowland.jinix.net;

import sun.nio.ch.DirectBuffer;

import java.awt.*;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Created by rsmith on 5/24/2017.
 */
public class EthernetDevice {

    private String name;
    private String osDevice;
    private int devFileDescriptor;
    private long hardwareAddress;
    private EnumMap<EthernetFrame.EtherType, FrameHandler> frameHandlerMap;
    private BlockingQueue<SocketBuffer> txQueue;
    private volatile boolean running;
    private Thread receiveThread, transmitThread;

    static {
        System.loadLibrary("EthernetDevice");
    }

    EthernetDevice(String name, String dev) {
        this.name = name;
        this.osDevice = dev;
        this.devFileDescriptor = -1;
        this.hardwareAddress = 226667692705204L;
        this.frameHandlerMap = new EnumMap<EthernetFrame.EtherType, FrameHandler>(EthernetFrame.EtherType.class);
        this.running = false;
        txQueue = new ArrayBlockingQueue<SocketBuffer>(256);

        ARPManager arpManager = ARPManager.getInstance();
        arpManager.registerDevice(this, this.hardwareAddress);
    }

    String getName() {
        return this.name;
    }

    long getHardwareAddress() {
        return this.hardwareAddress;
    }

    void setHardwareAddress(long hwa) {
        this.hardwareAddress = hwa;
    }

    synchronized void registerFrameHandler(EthernetFrame.EtherType etherType, FrameHandler handler) {

        if (handler == null) {
            throw new RuntimeException("Illegal attempt to register a null reference for an EtherType");
        }

        if (frameHandlerMap.containsKey(etherType)) {
            throw new RuntimeException("Illegal attempt to register a FrameHandler for an EtherType that already has a registed FrameHandler");
        }

        frameHandlerMap.put(etherType, handler);
    }

    synchronized FrameHandler deregisterFrameHandler(EthernetFrame.EtherType etherType) {

        if (!frameHandlerMap.containsKey(etherType)) {
            throw new RuntimeException("Illegal attempt to deregister a FrameHandler for an EtherType that has no registered FrameHandler");
        }

        return frameHandlerMap.remove(etherType);
    }

    void open() {
        if (devFileDescriptor > -1) {
            throw new IllegalStateException("Ethernet device is already open");
        }
        devFileDescriptor = openDevice(osDevice);
    }

    void close() {
        if (devFileDescriptor == -1) {
            throw new IllegalStateException("Ethernet device is already closed");
        }
        closeDevice(devFileDescriptor);
        devFileDescriptor = -1;
    }

    void up() {
        receiveThread = new Thread(Thread.currentThread().getThreadGroup(), new ReceiveThreadRunnable(), getName()+" Receive Thread");
        transmitThread = new Thread(Thread.currentThread().getThreadGroup(), new TransmitThreadRunnable(), getName()+" Transmit Thread");
        running = true;
        receiveThread.start();
        transmitThread.start();
    }

    void down() {
        running = false;
    }

    SocketBuffer receiveEthernetFrameDirect() {
        SocketBuffer skb = SocketBuffer.getNextAvailableSocketBuffer();
        int size = receiveEthernetFrameDirect(devFileDescriptor, skb.getDataBuffer());
        if (size < 0) {
            throw new RuntimeException("Receive error: "+size);
        }
        skb.initializeL2(size);
        return skb;
    }

    void enqueueTransmitEthernetFrame(SocketBuffer skb) {
        txQueue.add(skb);
    }

    void applyEthernetFrame(long destination, EthernetFrame.EtherType etherType, SocketBuffer skb) {
        new EthernetFrame(destination, getHardwareAddress(), etherType.getHeaderCode(), skb);
    }

    private native int openDevice(String name);

    private native int receiveEthernetFrame(int fd, byte[] buffer);

    private native int receiveEthernetFrameDirect(int fd, Buffer buffer);

    private native int transmitEthernetFrame(int fd, byte[] buffer);

    private native int transmitEthernetFrameDirect(int fd, Buffer buffer, int offset, int length);

    private native void closeDevice(int fd);

    private class ReceiveThreadRunnable implements Runnable {
        @Override
        public void run() {
            while (running) {
                SocketBuffer skb = receiveEthernetFrameDirect();
                //dumpPacket("Rx",skb.getDataBuffer(), 0, skb.getDataBuffer().limit());
                EthernetFrame.setupSKB(skb);
                EthernetFrame frame = new EthernetFrame(skb);

                try {
                    if (frame.getEthernetType() == EthernetFrame.EtherType.ARP.getHeaderCode()) {
                        ARPManager.getInstance().processFramePayload(EthernetDevice.this, skb);
                        continue;
                    }

                    if (frame.getEthernetType() == EthernetFrame.EtherType.IPV4.getHeaderCode()) {
                        FrameHandler frameHandler = frameHandlerMap.get(EthernetFrame.EtherType.IPV4);
                        frameHandler.processFramePayload(EthernetDevice.this, skb);
                        continue;
                    }

                    // We will simply drop any other types of received packets
                } catch (RuntimeException e){
                    System.out.println(e.getMessage());
                    e.printStackTrace();
                } finally {
                    frame.releaseSocketBuffer();
                }
            }
        }
    }

    private class TransmitThreadRunnable implements Runnable {
        @Override
        public void run() {
            SocketBuffer skb = null;
            try {
                while (running) {
                    skb = txQueue.poll(500, TimeUnit.MILLISECONDS);
                    if (skb == null) {
                        continue;
                    }
                    if (skb.getL2Header() == null) {
                        System.out.println("ERROR: transmit skb with no L2Header");
                        continue;
                    }
                    if (skb.getPayload() == null) {
                        System.out.println("ERROR: transmit skb with no payload");
                        continue;
                    }
                    int offset = (int) (((DirectBuffer) skb.getL2Header()).address() - ((DirectBuffer) skb.getDataBuffer()).address());
                    int size = (int) (((DirectBuffer) skb.getPayload()).address() + skb.getPayload().limit() - ((DirectBuffer) skb.getL2Header()).address());
                    skb.getDataBuffer().position(0);
                    //dumpPacket("Tx",skb.getDataBuffer(), offset, skb.getL2Header().limit());
                    int rtrn = transmitEthernetFrameDirect(devFileDescriptor, skb.getDataBuffer(), offset, size);
                    SocketBuffer.returnSocketBuffer(skb);
                    if (rtrn < 0) {
                        throw new RuntimeException("Transmit error: "+size);
                    }
                }
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    private void dumpPacket(String prefixMessage, ByteBuffer buffer, int offset, int limit) {
        byte[] pktData = new byte[limit-offset];
        buffer.position(offset);
        buffer.get(pktData, 0, pktData.length);
        EthernetFrame frame = new EthernetFrame(pktData, pktData.length);
        System.out.print(prefixMessage+": ");
        System.out.print("Src: "+EthernetFrame.hardwareAddressToString(frame.getSourceHardwareAddress()));
        System.out.print(" ");
        System.out.print("Dest: "+EthernetFrame.hardwareAddressToString(frame.getDestinationHardwareAddress()));
        System.out.println();
        buffer.position(offset);
    }
}
