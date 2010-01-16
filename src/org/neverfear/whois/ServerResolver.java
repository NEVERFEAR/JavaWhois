package org.neverfear.whois;

import java.io.IOException;
import java.net.UnknownHostException;

/**
 * An interface representing a WHOIS server resolver that can be queried.
 * @author doug@neverfear.org
 *
 */
public interface ServerResolver {

	/**
	 * Query the server for the given name.
	 * @param name A domain name.
	 * @return A {@link WhoisResponse} object.
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public WhoisResponse query(String name) throws IOException, UnknownHostException;
}
