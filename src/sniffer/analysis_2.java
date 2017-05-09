/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.labels.PieSectionLabelGenerator;
import org.jfree.chart.labels.StandardPieSectionLabelGenerator;
import org.jfree.chart.plot.MultiplePiePlot;
import org.jfree.chart.plot.PiePlot;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.util.TableOrder;

/**
 *
 * @author Rishabh
 */
public class analysis_2 {
    static void createflagschart(int total_packets,int MF,int RST,int SYN,int FIN){
        
        
         final DefaultCategoryDataset dataset = new DefaultCategoryDataset();
        dataset.addValue(total_packets, "total_packets", "MF");
        dataset.addValue(total_packets, "total_packets", "RST");
       dataset.addValue(total_packets, "total_packets", "SYN");
       dataset.addValue(total_packets, "total_packets", "FIN");

        dataset.addValue(MF, "MF", "MF");
        dataset.addValue(RST, "RST", "RST");
       dataset.addValue(SYN, "SYN", "SYN");
       dataset.addValue(FIN, "FIN", "FIN");
        
       final JFreeChart chart = ChartFactory.createMultiplePieChart3D(
            "Multiple Pie Chart Demo 3", dataset, TableOrder.BY_COLUMN, true, true, false
        ); 
        MultiplePiePlot plot = (MultiplePiePlot) chart.getPlot();
        JFreeChart subchart = plot.getPieChart();
        PiePlot p = (PiePlot) subchart.getPlot();
        p.setIgnoreNullValues(true);
        p.setIgnoreZeroValues(true);
        ChartPanel cp=new ChartPanel(chart, false, false, false, true, true);
        cp.setName("Flags");
        Statistics_Interface.jTabbedPane1.add(cp);
    }
    
    static void createhttpvshttpschart(long httplength,long httpslength,long httppackets,long httpspackets){
        
        
         final DefaultCategoryDataset dataset = new DefaultCategoryDataset();
        dataset.addValue(httppackets, "HTTP", "Packets");
        dataset.addValue(httpspackets, "HTTPS", "Packets");
       
        dataset.addValue(httplength, "HTTP", "Bytes transferred");
        dataset.addValue(httpslength, "HTTPS", "Bytes transferred");
       
       final JFreeChart chart = ChartFactory.createMultiplePieChart3D(
            "Multiple Pie Chart Demo 3", dataset, TableOrder.BY_COLUMN, true, true, false
        ); 
        MultiplePiePlot plot = (MultiplePiePlot) chart.getPlot();
        JFreeChart subchart = plot.getPieChart();
        PiePlot p = (PiePlot) subchart.getPlot();
        p.setIgnoreNullValues(true);
        p.setIgnoreZeroValues(true);
        ChartPanel cp=new ChartPanel(chart, false, false, false, true, true);
        cp.setName("HTTPvsHTTPS");
        Statistics_Interface.jTabbedPane1.add(cp);
    }
}
