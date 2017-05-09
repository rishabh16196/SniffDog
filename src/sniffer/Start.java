/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 *
 * @author Rishabh
 */
public class Start {
    
    public static List<PcapIf> dev = new ArrayList<>();
    public static PcapIf device;
public static StringBuilder err = new StringBuilder();
    static void listNetworkInterfaces() {
        User_Interface.jTextArea1.setText("");
        
        
        int r = Pcap.findAllDevs(dev, err);
        //System.out.println(Pcap.OK);

        if (r == Pcap.NOT_OK || dev.isEmpty()) {
            User_Interface.jTextArea1.append("Can't read list of devices, error is " + err
                    .toString());
            return;
        }
        
        System.out.println("Network devices found:");
        int i = 1;
        for (PcapIf devices : dev) {
            User_Interface.jTextArea1.append((i++) + "\n" + devices.getName() + "\n" + devices.getDescription() + "\n"
                    + "-------------------------------------------" + "\n");

            // System.out.println(devices.getName());
            //System.out.println(devices.getDescription());
            //System.out.println(devices.get);
        }
        User_Interface.jTextArea1.setCaretPosition(0);
    }
    
    static void go(int i) {
        if (i < 0 || i > dev.size() - 1) {
            User_Interface.jLabel1.setVisible(true);
            return;
        }
        device = dev.get(i);
        User_Interface.jTextArea1.setText("");
        User_Interface.jTextArea1.setText("Sniffing on device" + device.getName() + "...Press go to start sniffing.");
        User_Interface.jTextArea1.setCaretPosition(0);
    }
    
}
