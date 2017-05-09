/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import static sniffer.Statistical_Analysis.con;

/**
 *
 * @author Rishabh
 */
public class Applogger {

    static Connection con;

    static {
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Applogger.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            con = DriverManager.getConnection("jdbc:mysql://localhost:3306/network_anal", "root", "admin");
        } catch (SQLException ex) {
            Logger.getLogger(Applogger.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public class netstat extends Thread {

        String filename;
        Statement stmt;
        Process runtime = null;

        public netstat(String filename) {
            this.filename = filename;
            try {
                stmt = con.createStatement();
            } catch (SQLException e) {
            }
        }
        String cmd = "cmd /c netstat -p TCP -no | find \"TCP\"";

        @Override
        public void run() {
            while (User_Interface.capture == true) {
                try {
                    runtime = Runtime.getRuntime().exec(cmd);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

                // Scanner sc=new Scanner(runtime.getInputStream());
                BufferedReader br = new BufferedReader(new InputStreamReader(runtime.getInputStream()));
                //int lineno = 0;
                while (true) {
                    String line = null;
                    try {
                        line = br.readLine();
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    if (line == null) {
                        break;
                    }
                    //lineno++;
                    //System.out.print(lineno + " ");
                    StringTokenizer st = new StringTokenizer(line, ": \n");
                    st.nextToken();
                    String localadd = st.nextToken();
                    String localport = st.nextToken();
                    String destadd = st.nextToken();
                    String destport = st.nextToken();
                    st.nextToken();
                    String pid = st.nextToken();
                    //System.out.println(st.countTokens());
                    try {
                        stmt.execute("insert into " + filename + "_netstat values('" + localadd + "','" + localport + "','" + destadd + "','" + destport + "','" + pid + "')");
                    } catch (SQLException e) {
                        // TODO Auto-generated catch block
                        //	e.printStackTrace();
                    }

                    //System.out.println(line);
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

            }

        }
    }

    public class tasklist extends Thread {

        String filename;
        Statement stmt;
        Process runtime = null;

        public tasklist(String filename) {
            this.filename = filename;
            try {
                stmt = con.createStatement();
            } catch (SQLException e) {
            }
        }
        String cmd = "cmd /c tasklist | find \"K\"";

        @Override
        public void run() {
            while (User_Interface.capture == true) {
                try {
                    runtime = Runtime.getRuntime().exec(cmd);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

                // Scanner sc=new Scanner(runtime.getInputStream());
                BufferedReader br = new BufferedReader(new InputStreamReader(runtime.getInputStream()));
                //int lineno = 0;
                while (true) {
                    String line = null;
                    try {
                        line = br.readLine();
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    if (line == null) {
                        break;
                    }
                    //lineno++;
                    //System.out.print(lineno + " ");
                    StringTokenizer st = new StringTokenizer(line);
                    String app = st.nextToken();
                    String pid = st.nextToken();

                    //System.out.println(st.countTokens());
                    try {
                        stmt.execute("insert into " + filename + "_tasklist values('" + app + "','" + pid + "')");
                    } catch (SQLException e) {
                        // TODO Auto-generated catch block
                        //	e.printStackTrace();
                    }

                    //System.out.println(line);
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

            }

        }
    }

}
