package org.neverfear.whois;

import java.io.IOException;
import java.net.UnknownHostException;

/**
 * Represents a resolver for handling URL. (Stub)
 * @author doug@neverfear.org
 *
 */
public class ResolveURL implements ServerResolver {

	private String url;
	
	/**
	 * Construct a resolver for the given url.
	 * @param url A url.
	 */
	public ResolveURL(String url) {
		this.url = url;
	}
	
	/**
	 * Get the whois server host name.
	 * @return A host name.
	 */
	public String getServer() {
		return url;
	}
	
	
	@Override
	public WhoisResponse query(String domain) throws IOException,
			UnknownHostException {
		throw new UnsupportedOperationException("URLs are currently not supported");
	}

}
