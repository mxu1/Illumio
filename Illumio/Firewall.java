import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.io.*;
import java.util.*;

public class Firewall {
    
    String Filename;
    String direction;
    String protocol;
    String port;
    String ip_address;

    boolean portRange;
    boolean IPRange;

    int startPortRange;
    int endPortRange;
    String startIPRange;
    String endIPRange;

    Firewall(String name){
        setFilename(name);
    }

    public void setFilename(String name) {
        Filename = name;
        setRules(Filename);
    }

    private void setRules(String name) {
        File file = new File(name);
        BufferedReader br = null;
        String line = "";
        String cvsSplitBy = ",";
        try {
            br = new BufferedReader(new FileReader(file));
            while ((line = br.readLine()) != null) {
                String[] input = line.split(cvsSplitBy);
                direction = input[0];
                protocol = input[1];
                port = input[2];
                ip_address = input[3];
                
                //removing quotes
                direction = direction.replace("\"", "");
                protocol = protocol.replace("\"", "");
                port = port.replace("\"", "");
                ip_address = ip_address.replace("\"", "");
                
                //remove space
                direction = direction.replace(" ", "");
                protocol = protocol.replace(" ", "");
                port = port.replace(" ", "");
                ip_address = ip_address.replace(" ", "");

                setPortRange(port);
                setIPRange(ip_address);

                System.out.println("direction " + direction + " , protocol=" + protocol + ", port: " + port + ", ip " + ip_address);   
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void setPortRange(String port) {
        int index = port.indexOf("-");
        if (index == -1 ) {
            portRange = false;
            startPortRange = Integer.parseInt(port);
        } else {
            String split[] = port.split("-", 2);
            startPortRange = Integer.parseInt(split[0]);
            endPortRange = Integer.parseInt(split[1]);
            portRange = true;
        }
    }

    private void setIPRange(String ipAddress) {
        int index = ip_address.indexOf("-");
        if (index == -1 ) {
            IPRange = false;
            startIPRange = port;
        } else {
            String split[] = ip_address.split("-", 2);
            startIPRange = split[0];
            endIPRange = split[1];
            // System.out.println(startIPRange);
            // System.out.println(endIPRange);
            IPRange = true;
        }
    }

    private static long ipToLong(InetAddress ip) {
		byte[] octets = ip.getAddress();
		long result = 0;
		for (byte octet : octets) {
			result <<= 8;
			result |= octet & 0xff;
		}
		return result;
    }

    public static boolean isValidRange(String ipStart, String ipEnd, String ipToCheck) {
		try {
			long ipLo = ipToLong(InetAddress.getByName(ipStart));
			long ipHi = ipToLong(InetAddress.getByName(ipEnd));
			long ipToTest = ipToLong(InetAddress.getByName(ipToCheck));
			return (ipToTest >= ipLo && ipToTest <= ipHi);
		} catch (UnknownHostException e) {
			e.printStackTrace();
			return false;
		}
    }
    
    public  boolean IPnumberOrRange(String IPNumber) {
        //if there's a ip range
        if (IPRange) {
            if (isValidRange(startIPRange, endIPRange, IPNumber)) {
                return true;
            }
        }
        // if not an ip range
        else if (ip_address.equals(IPNumber)) {
            return true;
        }
        return false;
    }
    public boolean accept_packet(String dir, String prot, int p, String IPNumber) {
        boolean tf = false;
        if (!portRange) {    
            tf = Integer.parseInt(port) == p;
        }
        dir = dir.replace(" ", "");
        System.out.println("dir : " + direction.replaceAll("\\P{Print}","").equals(dir.trim().replaceAll("\\P{Print}","")));
        System.out.println("prot : " + prot.equals(protocol));
        System.out.println("port : " + tf);
        System.out.println("ip : " + IPnumberOrRange(IPNumber));

        if (dir.replaceAll("\\P{Print}","").equals(direction.replaceAll("\\P{Print}","")) && prot.equals(protocol)) {
            if (portRange) {
                if (startPortRange <= p && p <= endPortRange) {
                    return IPnumberOrRange(IPNumber);
                }
            }
            //not a port range
            else if (Integer.parseInt(port) == p) {
                return IPnumberOrRange(IPNumber);
            }
        }
        // not everything matched
        return false;
    }
    public static void main(String[] args) {
        String inbound = "inbound";
        Firewall fw  =  new Firewall("Test1.csv");
        System.out.println(fw.accept_packet(inbound, "tcp", 80, "192.168.1.2"));

        Firewall fw2  =  new Firewall("Test2.csv");
        System.out.println(fw2.accept_packet(inbound, "tcp", 80, "192.168.1.2"));

        Firewall fw3  =  new Firewall("Test3.csv");
        System.out.println(fw3.accept_packet(inbound, "tcp", 80, "192.168.1.2"));

        Firewall fw4  =  new Firewall("Test4.csv");
        System.out.println(fw4.accept_packet(inbound, "tcp", 80, "192.168.1.2"));

        Firewall fw5 = new Firewall("Test3.csv");
        System.out.println(fw5.accept_packet("inbound", "udp", 53, "192.168.2.1"));
        
        Firewall fw6 = new Firewall("Test2.csv");
        System.out.println(fw6.accept_packet("outbound", "tcp", 10234, "192.168.10.11"));
    }
}
