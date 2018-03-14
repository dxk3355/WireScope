package main.java.com.WireScope;

import java.io.File;
import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.util.Packets;
import org.pcap4j.util.PropertiesLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import main.java.com.gui.WireScopeMain;

public class MonitorThread extends Thread {

	final static Logger logger = LoggerFactory.getLogger(MonitorThread.class);
	LinkedBlockingQueue<Packet> packetQueue;
	PcapNetworkInterface inteface;
	volatile AtomicBoolean running = new AtomicBoolean();
	boolean fileOutput = false;
	File file = null;

	String filter;

	/**
	 * 
	 * @param packetQueue thread safe queue to put the packets in
	 * @param inteface interface to pull packets from
	 * @param filter filter to use following rules from http://biot.com/capstats/bpf.html 
	 */
	public MonitorThread(LinkedBlockingQueue<Packet> packetQueue, PcapNetworkInterface inteface, String filter) {
		this.packetQueue = packetQueue;
		this.inteface = inteface;
		this.filter = filter;
		running.set(true);
	}

	/**
	 * Create an output file other don't create one
	 * @param file File to use
	 */
	public void setFileOutput(File file) {
		this.file = file;
		fileOutput = true;
	}

	/**
	 * Stop the thread
	 */
	public void StopUpdating() {
		running.set(false);
	}

	@Override
	public void run() {
		PcapDumper dumper = null;

		try {
			// Set it to the max size of an ethernet packet and in promiscous mode with a 1 second timeout
			final PcapHandle handle = inteface.openLive(65536, PromiscuousMode.PROMISCUOUS, 1000);

			handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

			if (fileOutput) {
				dumper = handle.dumpOpen(file.getAbsolutePath());
			}

			int num = 0;
			while (running.get()) {
				Packet packet = handle.getNextPacket();

				if (packet == null) {
					continue;
				} else {
					packetQueue.add(packet);

					if (fileOutput) {
						dumper.dump(packet, handle.getTimestamp());
					}

					logger.debug(handle.getTimestamp().toString());
					logger.debug(packet.toString());

					num++;
					if (num >= 5000) {
						break;
					}
				}
			}

			PcapStat ps = handle.getStats();
			logger.info("ps_recv: " + ps.getNumPacketsReceived());
			logger.info("ps_drop: " + ps.getNumPacketsDropped());
			logger.info("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
			if (com.sun.jna.Platform.isWindows()) {
				logger.info("bs_capt: " + ps.getNumPacketsCaptured());
			}

			if (fileOutput) {
				dumper.close();
			}
			handle.close();

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
