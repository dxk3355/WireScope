package main.java.com.WireScope;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UpdateTextOutput extends Thread {

	final static Logger logger = LoggerFactory.getLogger(UpdateTextOutput.class);

	volatile AtomicBoolean running = new AtomicBoolean();
	DefaultTableModel tableModel;
	LinkedBlockingQueue<Packet> packetQueue;
	JTable table;

	public UpdateTextOutput(LinkedBlockingQueue<Packet> packetQueue, DefaultTableModel tableModel, JTable table) {
		this.tableModel = tableModel;
		this.packetQueue = packetQueue;
		this.table = table;
		running.set(true);
	}

	public void StopUpdating() {
		running.set(false);
	}

	@Override
	public void run() {

		boolean changed = false;

		// while the thread is running and until the queue is empty
		while (running.get() || !packetQueue.isEmpty()) {
			try {
				changed = false;

				while (!packetQueue.isEmpty()) {
					if (tableModel.getRowCount() > 1000) { // If the row count is too high remove the top row.
						tableModel.removeRow(0);
					}

					// Make sure you set the Static Packet factory in the classpath or this doesn't work
					Packet packet = packetQueue.poll();

					if (packet.contains(IpV4Packet.class)) {
						IpV4Packet ip4v = packet.get(IpV4Packet.class); // IPv4 is a high level packet type

						if (ip4v.getPayload().contains(DnsPacket.class)) {
							DnsPacket dns = ip4v.getPayload().get(DnsPacket.class);

							tableModel.addRow(new Object[] { "DNS", ip4v.getHeader().getSrcAddr(),
									ip4v.getHeader().getDstAddr(), dns.toString() });
						} else if (ip4v.getPayload().contains(IcmpV4CommonPacket.class)) {
							IcmpV4CommonPacket icmp = ip4v.getPayload().get(IcmpV4CommonPacket.class);

							tableModel.addRow(new Object[] { "ICMP", ip4v.getHeader().getSrcAddr(),
									ip4v.getHeader().getDstAddr(), icmp.toString() });

						} else {
							tableModel.addRow(new Object[] { "IPv4", ip4v.getHeader().getSrcAddr(),
									ip4v.getHeader().getDstAddr(), ip4v.toString() });

						}

					} else if (packet.contains(IpV6Packet.class)) {
						IpV6Packet ip6v = packet.get(IpV6Packet.class); // IPv6 is a high level packet type

						if (ip6v.getPayload().contains(DnsPacket.class)) {
							DnsPacket dns = ip6v.getPayload().get(DnsPacket.class);

							tableModel.addRow(new Object[] { "DNS", ip6v.getHeader().getSrcAddr(),
									ip6v.getHeader().getDstAddr(), dns.toString() });
						} else if (ip6v.getPayload().contains(IcmpV4CommonPacket.class)) {
							IcmpV4CommonPacket icmp = ip6v.getPayload().get(IcmpV4CommonPacket.class);

							tableModel.addRow(new Object[] { "ICMP", ip6v.getHeader().getSrcAddr(),
									ip6v.getHeader().getDstAddr(), icmp.toString() });

						} else {
							tableModel.addRow(new Object[] { "IPv6", ip6v.getHeader().getSrcAddr(),
									ip6v.getHeader().getDstAddr(), ip6v.toString() });
						}
					} else if (packet.contains(ArpPacket.class)) { // ARP is a layer 2 packet type so won't be found by ipv4 or 6
						ArpPacket arp = packet.get(ArpPacket.class);
						tableModel.addRow(new Object[] { "ARP", arp.getHeader().getSrcHardwareAddr(),
								arp.getHeader().getDstHardwareAddr(), arp.toString() });
					} else {
						logger.info("Unknown packet type");
					}
					changed = true;
				}
				if (changed) {
					table.getParent().revalidate(); // update the output table gui
				}
				try {
					Thread.sleep(250);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

}
