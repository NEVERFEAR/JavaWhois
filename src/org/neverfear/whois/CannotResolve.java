package org.neverfear.whois;

import java.io.IOException;
import java.net.UnknownHostException;

/**
 * Represents a resolver that cannot be used.
 * @author doug@neverfear.org
 *
 */
public class CannotResolve implements ServerResolver {
	
	
	@Override
	public WhoisResponse query(String domain) throws IOException,
			UnknownHostException {
		throw new UnknownHostException("There are no whois servers available for " + domain);
	}

}
