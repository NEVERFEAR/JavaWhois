package org.neverfear.whois;

import java.io.IOException;
import java.net.UnknownHostException;

/**
 * Represents a whois server.
 * @author doug@neverfear.org
 *
 */
public class WhoisServer {

	private ServerResolver resolver;
	private String tld;
	
	/**
	 * Construct a whois server instance for the given top level domain and an appropriate resolver instance.
	 * @param tld A top level domain.
	 * @param resolver A compatible resolver.
	 */
	public WhoisServer(String tld, ServerResolver resolver) {
		this.tld = tld;
		this.resolver = resolver;
	}
	
	/**
	 * Construct a whois server instance for a resolver instance.
	 * @param resolver A resolver.
	 */
	public WhoisServer(ServerResolver resolver) {
		this.tld = null;
		this.resolver = resolver;
	}
	
	/**
	 * Get the top level domain this server handles.
	 * @return A top level domain.
	 */
	public String getTLD() {
		return this.tld;
	}
	
	/**
	 * Query this server for the given domain name.
	 * @param domain A domain name.
	 * @return A {@link WhoisResponse} object.
	 * @throws UnknownHostException
	 * @throws IOException
	 */
	public WhoisResponse query(String domain) throws UnknownHostException, IOException {
		return resolver.query(domain);
	}
	
}
