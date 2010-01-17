package org.neverfear.whois.tests;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.neverfear.whois.WhoisQuery;
import org.neverfear.whois.WhoisResponse;

import junit.framework.TestCase;

// These tests may not be yet working. I've not checked for a while.
public class GoogleTest extends TestCase {

	protected void setUp() throws Exception {
	}
	
	public void testGoogleDomains() {
		FileInputStream  fin;
		DataInputStream dis;
		int bytesRead = 0;
		byte[] bytes = new byte[1024];
		String data = "";
		
		String filename = "D:\\google.domains\\domains.txt";
		try {
			fin = new FileInputStream(filename);
			dis = new DataInputStream(fin);
			while((bytesRead = dis.read(bytes)) != -1) {
				data += new String(bytes, 0, bytesRead);
			}
			fin.close();
			
			for(String domain : data.split("\n")) {
				System.out.println("Processing " + domain + "...");
				testDomain(domain);
			}
		} catch (FileNotFoundException e) {
			System.err.println("Failed to open '" + filename + "' for reading.");
		} catch (IOException e) {
			e.printStackTrace(System.err);
		}
	}
	
	public void testDomain(String domain) {
		FileInputStream  fin;
		DataInputStream dis;
		int bytesRead = 0;
		byte[] bytes = new byte[1024];
		String data = "";
		
		String filename = "D:\\google.domains\\" + domain + ".txt";
		try {
			fin = new FileInputStream(filename);
			dis = new DataInputStream(fin);
			while((bytesRead = dis.read(bytes)) != -1) {
				data += new String(bytes, 0, bytesRead);
			}
			fin.close();
			
			WhoisQuery query = new WhoisQuery(domain);
			WhoisResponse response = query.getResponse();
			
			if (!data.equals(response.getData())) {
				System.err.println("Data for " + response.getName() + " is not equal to GNU Whois");
				System.out.println(response.getData());
				System.err.println("Compared to");
				System.out.println(data);
				System.err.println("End of print");
			}
			assertEquals(data, response.getData());
			
		} catch (FileNotFoundException e) {
			System.err.println("Failed to open '" + filename + "' for reading.");
		} catch (IOException e) {
			e.printStackTrace(System.err);
		}
		
		
	}

}
