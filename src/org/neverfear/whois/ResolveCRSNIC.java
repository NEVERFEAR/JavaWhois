package org.neverfear.whois;

import java.io.IOException;
import java.net.UnknownHostException;

/**
 * Represents a resolver for CRSNIC domain names.
 * @author doug@neverfear.org
 *
 */
public class ResolveCRSNIC implements ServerResolver {

	/**
	 * The whois server port.
	 */
	public final static int WHOIS_PORT = 43;

	protected static String DOMAIN_STR = "Domain Name:";
	protected static String WHOIS_STR  = "Whois Server:";

	
	private String server;
	private int port;
	private ServerResolver resolver; // Internal resolver
	
	/**
	 * Construct a resolver for the given whois server.
	 * @param server A host name.
	 */
	public ResolveCRSNIC(String server) {
		this.server = server;
		this.port = WHOIS_PORT;
		this.resolver = new ResolveDefault(server);
		
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
	public WhoisResponse query(String name) throws IOException, UnknownHostException {
		return exactSearch(name);
	}
	
	/**
	 * Perform an partial search on the CRSNIC database for the given name.
	 * @param name A domain name.
	 * @return A {@link WhoisResponse} object.
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public WhoisResponse partialSearch(String name) throws IOException, UnknownHostException {
		return search(name, "partial ");
	}
	
	/**
	 * Perform an exact search on the CRSNIC database for the given name.
	 * @param name A domain name.
	 * @return A {@link WhoisResponse} object.
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public WhoisResponse exactSearch(String name) throws IOException, UnknownHostException {
		return search(name, "full ");
	}
	
	/**
	 * Perform a summary search on the CRSNIC database for the given name.
	 * @param name A domain name.
	 * @return A {@link WhoisResponse} object.
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public WhoisResponse summarySearch(String name) throws IOException, UnknownHostException {
		return search(name, "summary ");
	}
	
	/**
	 * Perform an expanded search on the CRSNIC database for the given name.
	 * @param name A domain name.
	 * @return A {@link WhoisResponse} object.
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public WhoisResponse expandedSearch(String name) throws IOException, UnknownHostException {
		return search(name, "expand ");
	}
	
	/**
	 * Search the CRSNIC database for the given name.
	 * @param name A domain name.
	 * @return A {@link WhoisResponse} object.
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public WhoisResponse search(String name) throws IOException, UnknownHostException {
		return search(name, "");
	}
	
	/**
	 * Search the CRSNIC database for the given name using the given query type.
	 * @param name A domain name.
	 * @param modifier A CRSNIC query modifier.
	 * @return A {@link WhoisResponse} object.
	 * @throws IOException
	 * @throws UnknownHostException
	 */
	public WhoisResponse search(String name, String modifier) throws IOException, UnknownHostException {
		// Fetch the result for name and convert all new lines into unix form.
		String data = resolver.query(modifier + name).getData().replace("\r\n", "\n").replace('\r', '\n');
		int currentPosition = 0;
		int serverStart;
		int nextCRLF;
		String hostname; // The whois server hostname
		
		// While the domain string is found
		while((currentPosition = data.indexOf(DOMAIN_STR, currentPosition)) != -1) {
		
			serverStart = data.indexOf(WHOIS_STR, currentPosition);
			if (serverStart != -1) {
				
				// Is there two new lines between the domain and whois server.
				// This implies that the whois server isn't related to the last found domain.
				if (data.substring(currentPosition, serverStart).indexOf('\n') == -1) {
					continue; // abort and try for the next one
				}
				
				serverStart += WHOIS_STR.length(); // move after the whois string
				nextCRLF = data.indexOf('\n', serverStart); // find the end of the hostname
				if (nextCRLF != -1) {
					hostname = data.substring(serverStart, nextCRLF);
				} else { // Assume it's the last line although I don't think this should happen
					hostname = data.substring(serverStart);
				}
				// Make a query to the given hostname and append the data.
				data += new ResolveDefault(hostname.trim()).query(name).getData();
				break;
			} else {
				break;
			}
			
		}
		return new WhoisResponse(name, data);
	}

}
