package org.neverfear.whois;

import java.io.IOException;
import java.net.UnknownHostException;

/**
 * Resolve an Afilias domain name. See {@link http://www.afilias.info/} for more information.
 * @author doug@neverfear.org
 *
 */
public class ResolveAfilias extends ResolveCRSNIC {
	
	/**
	 * The whois server host name.
	 */
	public final static String WHOIS_HOST = "whois.afilias-grs.info";
	
	/**
	 * The whois server host port.
	 */
	public final static int WHOIS_PORT = 43;

	private String server;
	private int port;
	
	private static ResolveAfilias instance;
	
	/**
	 * Create an Afilias resolver. Cannot be instantiated outside of this object.
	 */
	private ResolveAfilias() {
		super(WHOIS_HOST);
	}
	
	/**
	 * Get an instance of a afilias resolver.
	 * @return The Afilias resolver
	 */
	public static ResolveAfilias getInstance() {
		if (instance == null) {
			instance = new ResolveAfilias();
		}
		return instance;
	}
	
	/**
	 * Get the whois server host name.
	 * @return A host name.
	 */
	public String getServer() {
		return server;
	}

	/**
	 * Get the whois server host port.
	 * @return A host port.
	 */
	public int getPort() {
		return port;
	}
	
	@Override
	public WhoisResponse query(String name) throws IOException, UnknownHostException  {
		return search(name);
	}

}
