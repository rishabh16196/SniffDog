/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import java.sql.Connection;
import com.sun.org.apache.xalan.internal.xsltc.compiler.util.StringStack;
import java.awt.EventQueue;
import java.awt.Font;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.labels.PieSectionLabelGenerator;
import org.jfree.chart.labels.StandardPieSectionLabelGenerator;
import org.jfree.chart.plot.PiePlot;
import org.jfree.data.general.DefaultPieDataset;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.network.Rip;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.wan.PPP;

/**
 *
 * @author Rishabh
 */
public class Statistical_Analysis {

    static private int nounce = 0;
    static private int CWR = 0;
    static private int ECN = 0;
    static private int URG = 0;
    static private int ACK = 0;
    static private int PSH = 0;
    static private int RST = 0;
    static private int SYN = 0;
    static private int FIN = 0;
    static private int MF = 0;

    static int icmp = 0;
    static int http = 0;
    static int total_packets = 0;
    static int udp = 0;
    static int tcp = 0;
    static int ppp = 0;
    static int arp = 0;
    static int ip4 = 0;
    static int ip6 = 0;
    static int Ethernet = 0;
    static int https = 0;
    
    
    static int fwd = 1;
    static int bkw = 0;
    static PPP ppp1 = new PPP();
    static Ethernet eth = new Ethernet();
    static Arp arp1 = new Arp();
    static Icmp icmp1 = new Icmp();
    static Ip4 ipv4 = new Ip4();
    static Ip6 ipv6 = new Ip6();
    static JTable flow;
    static DefaultTableModel dtm;
    static Http http1 = new Http();
    static Tcp tcp1 = new Tcp();
    static Udp udp1 = new Udp();
    static StringBuilder error = new StringBuilder();
    static Connection con;
    static Statement stmt;
    static Map<JFlowKey, JFlow> map = new HashMap<JFlowKey, JFlow>();
    static int num = 0;
    static Map<JFlowKey, Integer> map1 = new HashMap<JFlowKey, Integer>();

    public static void anal(String filename) throws SQLException {
        Pcap pcap = Pcap.openOffline("C:\\Users\\Rishabh\\Downloads\\NetworkAnal\\" + filename + ".pcap", error);

        try {
            Class.forName("com.mysql.jdbc.Driver");
            con = DriverManager.getConnection("jdbc:mysql://localhost:3306/network_anal", "root", "admin");
            stmt = con.createStatement();
        } catch (Exception e) {
        
        }

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {
                total_packets++;

                checkheader(packet);
                checkflags(packet);

                try {
                    go1(packet);
                } catch (SQLException ex) {
                    Logger.getLogger(Statistical_Analysis.class.getName()).log(Level.SEVERE, null, ex);
                }

                
                cleardata();
            }
        };
        
        pcap.loop(-1, jpacketHandler, "jNetPcap rocks!");
try {
                    stmt.executeBatch();
                } catch (SQLException ex) {
                    Logger.getLogger(Statistical_Analysis.class.getName()).log(Level.SEVERE, null, ex);
                }
    }

    static void cleardata() {
        icmp = 0;
        http = 0;

        udp = 0;
        tcp = 0;
        ppp = 0;
        arp = 0;
        ip4 = 0;
        ip6 = 0;
        https = 0;
        Ethernet = 0;
    }

    static void checkflags(PcapPacket p) {

        if (p.hasHeader(tcp1)) {

            ACK = (tcp1.flags_ACK() ? 1 : 0);
            URG = (tcp1.flags_URG() ? 1 : 0);
            SYN = (tcp1.flags_SYN() ? 1 : 0);
            PSH = (tcp1.flags_PSH() ? 1 : 0);
            CWR = (tcp1.flags_CWR() ? 1 : 0);
            ECN = (tcp1.flags_ECE() ? 1 : 0);
            FIN = (tcp1.flags_FIN() ? 1 : 0);
            RST = (tcp1.flags_RST() ? 1 : 0);
        }
        if (p.hasHeader(ipv4)) {
            MF = ipv4.flags_MF();
        }

        try {
            stmt.addBatch("insert into " + User_Interface.filename + "_flagsvalue values(" + total_packets + ","
                    + MF + ","
                    + CWR + ","
                    + ECN + ","
                    + URG + ","
                    + ACK + ","
                    + PSH + ","
                    + RST + ","
                    + SYN + ","
                    + FIN + ")"
            );
        } catch (SQLException ex) {
            Logger.getLogger(Statistical_Analysis.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    static void checkheader(PcapPacket p) {
        if (p.hasHeader(eth)) {
            Ethernet++;
        }

        if (p.hasHeader(ppp1)) {
            ppp++;
        }
        if (p.hasHeader(arp1)) {
            arp++;
        }
        if (p.hasHeader(icmp1)) {
            icmp++;
        }
        if (p.hasHeader(ipv4)) {
            ip4++;
        }
        if (p.hasHeader(ipv6)) {
            ip6++;
        }
        
        if (p.hasHeader(tcp1)) {
            tcp++;
            if (tcp1.destination() == 443 || tcp1.source() == 443) {
                https++;
            }
            if (tcp1.destination() == 80 || tcp1.source() == 80) {
                http++;
            }

        }
        if (p.hasHeader(udp1)) {
            udp++;
        }
        try {
            stmt.addBatch("insert into " + User_Interface.filename + "_packetinfo values(" + total_packets + ","
                    + p.getCaptureHeader().wirelen() + ","
                    + Ethernet + ","
                    + ip4 + ","
                    + ip6 + ","
                    + tcp + ","
                    + udp + ","
                    + http + ","
                    + https + ","
                    + arp + ","
                    + icmp + ","
                    + ppp + ")"
            );
        } catch (SQLException ex) {
            Logger.getLogger(Statistical_Analysis.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    static long first_pack_time;
    static long estb_time = -1;
    static ArrayList<Integer> estbs = new ArrayList<>();

    static void go1(PcapPacket packet) throws SQLException {
         if (total_packets == 1) {
            first_pack_time = packet.getCaptureHeader().timestampInMicros();
            estbs.add(0);
        }
        Tcp tc=new Tcp();
        if(packet.hasHeader(tc)){
       

        JFlowKey jfkey = packet.getState().getFlowKey();
        //System.out.println(jfkey.toString());
        JFlow jf = map.get(jfkey);
        if (jf == null) {
            map1.put(jfkey, ++num);
            map.put(jfkey, jf = new JFlow(jfkey));
            estbs.add(-1);
            
            
        }
        jf.add(packet);
        HashMap<Integer,String> hmsou=new HashMap<>();
        String srcip = null,destip = null;
        long time = packet.getCaptureHeader().timestampInMicros() - first_pack_time;
        int port_host = 0, port_dest = 0;
        int arrow = 0;
        StringBuilder comments = new StringBuilder();
        Ip4 ip = new Ip4();
        if(packet.hasHeader(ip)){
        srcip = FormatUtils.ip(ip.source());
        destip=FormatUtils.ip(ip.destination());
        if(jf.size()==1){hmsou.put(map1.get(jfkey), srcip);}
        if (srcip.equals(hmsou.get(map1.get(jfkey)))) {
            arrow = fwd;
        } else {
            arrow = bkw;
        }
        }
        Http http = new Http();
        
        Tcp tcp = new Tcp();
        if (packet.hasHeader(tcp)) {
            
            int offset = (14 + 20 + 20);

            if (packet.size() > offset && packet.getByte(offset) == 71 && estbs.get(map1.get(jfkey)) == -1) {
                estbs.set(map1.get(jfkey), 1);
            }
            
            comments.append("TCP ");
            port_host = tcp.source();
            port_dest = tcp.destination();

            if (tcp.flags_ACK()) {
                comments.append("ACK ");
            }
            if (tcp.flags_PSH()) {
                comments.append("PSH ");
            }
            if (tcp.flags_SYN()) {
                comments.append("SYN ");
            }
            if (tcp.flags_FIN()) {
                comments.append("FIN ");
            }
            stmt.addBatch("Insert into " + User_Interface.filename + "_seqack values(" + total_packets +
                    "," + tcp.seq() + 
                    "," + tcp.ack() + 
                    "," + estbs.get(map1.get(jfkey)) +
                    ")");
        
        
        
        
        }
        stmt.addBatch("Insert into " + User_Interface.filename + "_flow values(" +
              total_packets +"," +
              time + ",'" +
              srcip+"',"+
              port_host + "," +
              arrow + "," +
              
              port_dest + ",'" +
              destip+"','"+
              comments.toString() +
              "'," + map1.get(jfkey) +
              ")");
      
    }
    }
   
}
