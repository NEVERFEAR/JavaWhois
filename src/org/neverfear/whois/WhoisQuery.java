package org.neverfear.whois;

import java.net.UnknownHostException;
import java.io.IOException;

/**
 * Represents a whois query.
 * @author doug@neverfear.org
 *
 */
public class WhoisQuery {
	private String query;
	private WhoisResponse response;
	
	/**
	 * Construct a query for the given name.
	 * @param name A domain name.
	 */
	public WhoisQuery(String name) {
		query = name;
		response = null;
	}
	
	/**
	 * Destroy the existing response.
	 */
	public void reset() {
		response = null;
	}
	
	/**
	 * Get the response for this query.
	 * @return A {@link WhoisResponse} object
	 * @throws UnknownHostException
	 * @throws IOException
	 */
	public WhoisResponse getResponse() throws UnknownHostException, IOException {
		if (this.response == null) {
			this.response = WhoisServerPool.query(query);
		}
		return this.response;
		
	}
}
