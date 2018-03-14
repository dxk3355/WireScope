package main.java.com.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.FlowLayout;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.SynchronousQueue;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import main.java.com.WireScope.MonitorThread;
import main.java.com.WireScope.UpdateTextOutput;

import javax.swing.JTextArea;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JCheckBox;
import java.awt.event.ItemListener;
import java.io.File;
import java.awt.event.ItemEvent;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class WireScopeMain {

	final static Logger logger = LoggerFactory.getLogger(WireScopeMain.class);
	private List<PcapNetworkInterface> interfaces;
	private JFrame frame;
	private JTextField txtFilters;
	private JComboBox ddlInterfaces;
	private MonitorThread monitorThread;
	private UpdateTextOutput updateTextOutputThread;
	private boolean running;
	JPanel pnlData;
	JButton btnStart, btnStop;
	JCheckBox chkBoxDumpFile;
	JLabel lblFilePath = new JLabel("");
	JTextArea txtData;

	private LinkedBlockingQueue<Packet> packetQueue;
	private JTable tblOutput;
	private DefaultTableModel tableModel;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					WireScopeMain window = new WireScopeMain();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public WireScopeMain() {
		initialize();
		try {
			interfaces = org.pcap4j.core.Pcaps.findAllDevs();
			populateInterfaceList();
		} catch (PcapNativeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private void populateInterfaceList() {
		for (PcapNetworkInterface inFace : interfaces) {
			ddlInterfaces.addItem(new ComboItem(inFace.getDescription(), inFace.getName()));
			logger.info("Interface: " + inFace.getDescription());
		}
	}

	private void StartMonitoring() {
		packetQueue = new LinkedBlockingQueue<Packet>();

		try {
			PcapNetworkInterface inteface = interfaces.get(ddlInterfaces.getSelectedIndex());

			for (PcapAddress addr : inteface.getAddresses()) {
				if (addr.getAddress() != null) {
					logger.info("IP address: " + addr.getAddress());
				}
			}

			monitorThread = new MonitorThread(packetQueue, inteface, txtFilters.getText());

			if (chkBoxDumpFile.isSelected()) {
				File file = new File(lblFilePath.getText());
				monitorThread.setFileOutput(file);
			}

			monitorThread.start();

			updateTextOutputThread = new UpdateTextOutput(packetQueue, tableModel, tblOutput);
			updateTextOutputThread.start();

			btnStart.setEnabled(false);
			btnStop.setEnabled(true);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 708, 496);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(new BorderLayout(0, 0));

		JPanel pnlSide = new JPanel();
		pnlSide.setLayout(new BoxLayout(pnlSide, BoxLayout.Y_AXIS));

		JPanel panel_1 = new JPanel();
		pnlSide.add(panel_1);
		panel_1.setLayout(new BoxLayout(panel_1, BoxLayout.X_AXIS));

		btnStart = new JButton("\u25B6");
		btnStart.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				StartMonitoring();
			}
		});
		panel_1.add(btnStart);
		btnStart.setForeground(new Color(0, 128, 0));

		btnStop = new JButton("\u25A0");
		btnStop.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {

				monitorThread.StopUpdating();
				updateTextOutputThread.StopUpdating();

				btnStart.setEnabled(true);
				btnStop.setEnabled(false);
			}
		});
		btnStop.setEnabled(false);

		panel_1.add(btnStop);
		btnStop.setForeground(new Color(255, 0, 0));

		JPanel panel_2 = new JPanel();
		pnlSide.add(panel_2);
		panel_2.setLayout(new FlowLayout(FlowLayout.LEADING, 5, 5));

		JLabel lblInterface = new JLabel("Interface");
		panel_2.add(lblInterface);

		ddlInterfaces = new JComboBox();
		panel_2.add(ddlInterfaces);

		JPanel panel_3 = new JPanel();
		pnlSide.add(panel_3);

		JLabel lblArguments = new JLabel("Filter");
		panel_3.add(lblArguments);

		txtFilters = new JTextField();
		panel_3.add(txtFilters);
		txtFilters.setColumns(10);

		JPanel panel_4 = new JPanel();
		pnlSide.add(panel_4);

		chkBoxDumpFile = new JCheckBox("Enabled");
		// Create a dump file
		chkBoxDumpFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if (chkBoxDumpFile.isSelected()) {
					JFileChooser chooser = new JFileChooser();
					FileNameExtensionFilter filter = new FileNameExtensionFilter("pcap file", ".pcapFile");
					chooser.setFileFilter(filter);
					int returnVal = chooser.showSaveDialog(frame);
					if (returnVal == JFileChooser.APPROVE_OPTION) {
						lblFilePath.setText(chooser.getSelectedFile().getAbsolutePath());
						if (!lblFilePath.getText().endsWith(".pcap")) {
							lblFilePath.setText(lblFilePath.getText() + ".pcap");					
						}
					} else if (returnVal == JFileChooser.CANCEL_OPTION) {
						chkBoxDumpFile.setSelected(false);
						lblFilePath.setText("");
					}
				} else {
					lblFilePath.setText("");
					return;
				}
				;
			}
		});

		panel_4.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));

		JLabel lblDmp = new JLabel("Dump File");
		panel_4.add(lblDmp);
		panel_4.add(chkBoxDumpFile);
		frame.getContentPane().add(pnlSide, BorderLayout.WEST);

		JPanel panel = new JPanel();
		pnlSide.add(panel);

		JPanel pnlCenter = new JPanel();
		frame.getContentPane().add(pnlCenter, BorderLayout.CENTER);
		pnlCenter.setLayout(new BorderLayout(0, 0));

		tableModel = new DefaultTableModel(
				new Object[][] {
				},
				new String[] {
					 "Type", "Src", "Dst","Data"
				}
			);
		
		tblOutput = new JTable();
		tblOutput.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) {
				 int row = tblOutput.rowAtPoint(arg0.getPoint());
			        int col = tblOutput.columnAtPoint(arg0.getPoint());
			        if (row >= 0 && col >= 0) {
			        	String data = tableModel.getValueAt(tblOutput.getSelectedRow(), 3).toString();
			        	txtData.setText(data);
			        	pnlData.setVisible(true);
			        }
			}
		});
		tblOutput.setModel(tableModel);
		tblOutput.setShowHorizontalLines(false);

		JScrollPane scrollPane = new JScrollPane(tblOutput);
		pnlCenter.add(scrollPane, BorderLayout.CENTER);
		
		pnlData = new JPanel();
		pnlCenter.add(pnlData, BorderLayout.SOUTH);
		pnlData.setLayout(new BorderLayout(0, 0));
		
		txtData = new JTextArea();
		pnlData.add(txtData, BorderLayout.CENTER);
		
		JButton btnCloseData = new JButton("Close");
		btnCloseData.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent arg0) {
				pnlData.setVisible(false);
			}
		});
		pnlData.add(btnCloseData, BorderLayout.EAST);
		pnlData.setVisible(false);

		frame.getContentPane().add(lblFilePath, BorderLayout.SOUTH);

	}

}
