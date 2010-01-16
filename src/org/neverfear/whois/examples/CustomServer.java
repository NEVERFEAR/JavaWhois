package org.neverfear.whois.examples;

import org.neverfear.whois.ResolveDefault;
import org.neverfear.whois.WhoisResponse;
import org.neverfear.whois.WhoisServer;

public class CustomServer {
	public static void main(String[] args) throws Exception {
		// Construct a whois server to use the default resolver and query the whois.neverfear.org.
		WhoisServer server = new WhoisServer(new ResolveDefault("whois.neverfear.org"));
		// Query this server for the record neverfear.org.
		WhoisResponse response = server.query("neverfear.org");
		// Print the response.
		System.out.println(response.getData());
	}
}
