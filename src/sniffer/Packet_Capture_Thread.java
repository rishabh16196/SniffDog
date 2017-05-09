/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;
import jpcap.packet.Packet;
import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.application.Html;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import sun.security.x509.X500Name;

/**
 *
 * @author Rishabh
 */
public class Packet_Capture_Thread extends SwingWorker<Void, PcapPacket> {

    static int number = 1;
    static DefaultTableModel dtm;
    

    public Packet_Capture_Thread(DefaultTableModel dtm) {
        this.dtm = dtm;
    }
   

    @Override
    protected Void doInBackground() throws Exception {

        Pcap pcap
                = Pcap.openOffline("C:\\Users\\Rishabh\\Downloads\\NetworkAnal\\"+User_Interface.filename+".pcap", Start.err);

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            

            public void nextPacket(PcapPacket packet, String user) {

                publish(packet);

            }
        };
        
        pcap.loop(-1, jpacketHandler, "jNetPcap rocks!");

        pcap.close();
        return null;
    }

    @Override
    protected void process(List<PcapPacket> chunks) {
        Ip4 ip=new Ip4();
        
        for (PcapPacket p:chunks) {
            
            if(p.hasHeader(ip)){
            dtm.addRow(new Object[]{number++, FormatUtils.ip(ip.source()),FormatUtils.ip(ip.destination())});
            User_Interface.p[(User_Interface.i)++] =p;
            }
        }
    }
}
