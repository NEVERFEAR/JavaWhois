package org.neverfear.whois;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.net.UnknownHostException;

/**
 * A default server for standard queries.
 * @author doug@neverfear.org
 *
 */
public class ResolveDefault implements ServerResolver {

	/**
	 * The default server port.
	 */
	public final static int WHOIS_PORT = 43;

	private String server;
	private int port;
	
	/**
	 * Construct a resolver for the given server host name.
	 * @param server A host name.
	 */
	public ResolveDefault(String server) {
		this.server = server;
		this.port = WHOIS_PORT;
	}
	
	/**
	 * Construct a resolver for the given server host name and host port.
	 * @param server A host name.
	 * @param port A host port.
	 */
	public ResolveDefault(String server, int port) {
		this.server = server;
		this.port = port;
	}
	
	/**
	 * Get the server host name.
	 * @return The host name.
	 */
	public String getServer() {
		return server;
	}
	
	/**
	 * Get the server host port.
	 * @return The host port.
	 */
	public int getPort() {
		return port;
	}
	
	@Override
	public WhoisResponse query(String name) throws IOException, UnknownHostException {

		int length		= -1;
		String data		= "";
		byte[] bytes	= new byte[1024];
		Socket sock 	= new Socket(this.server, this.port);
		InputStream in 	= sock.getInputStream();
		PrintStream out	= new PrintStream(sock.getOutputStream());
		
		out.print(name + "\r\n");
		out.flush();
		
		while((length = in.read(bytes)) != -1) {
			data += new String(bytes, 0, length);
		}
		
		return new WhoisResponse(name, data);
	}

}
