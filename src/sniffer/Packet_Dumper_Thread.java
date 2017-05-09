/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import javax.swing.SwingWorker;
import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import sun.security.x509.X500Name;

/**
 *
 * @author Rishabh
 */
public class Packet_Dumper_Thread extends SwingWorker<Void,Void>{
   static Pcap pcap;
   
   @Override
    public Void doInBackground(){
   
   
    int snaplen=64*1064;
    int flags=Pcap.MODE_PROMISCUOUS;
    int timeout=10*1000;
  String file="C:\\Users\\Rishabh\\Downloads\\NetworkAnal\\"+User_Interface.filename+".pcap";
   
  PcapBpfProgram prog=new PcapBpfProgram();
        
  pcap=Pcap.openLive(Start.device.getName(), snaplen,flags, timeout, Start.err);
        
  if(User_Interface.jToggleButton1.isSelected()){
  String filter=User_Interface.jTextField3.getText();
 pcap.compile(prog, filter, 0, 0xFFFFFF00);
 pcap.setFilter(prog);}
  PcapDumper dumper=pcap.dumpOpen(file);
       
        ByteBufferHandler<PcapDumper> handler1=new ByteBufferHandler<PcapDumper>() {
        @Override
        public void nextPacket(PcapHeader header, ByteBuffer buffer, PcapDumper user) {
           
            dumper.dump(header, buffer);
            
        }
    };
        
    pcap.loop(-1,handler1,dumper);
    dumper.close();
   pcap.close();
    return null;
    }  
    
}
