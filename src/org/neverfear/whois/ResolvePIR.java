package org.neverfear.whois;

import java.io.IOException;
import java.net.UnknownHostException;

import org.neverfear.whois.parsers.WhoisParseException;
import org.neverfear.whois.parsers.pir.PublicInterestRegistryResponse;


/**
 * Represents a public interest registry.
 * @author doug@neverfear.org
 */
public class ResolvePIR extends ResolveCRSNIC {
	
	@Override
	public WhoisResponse search(String name, String modifier) throws UnknownHostException, IOException {
		WhoisResponse response = super.search(name, modifier);
		try {
			return new PublicInterestRegistryResponse(response);
		} catch (WhoisParseException e) {
			// TODO: This behaviour is going to be very helpful to users. 
			// Need to fix this such that we allow the users to decide if they
			// Simply want the raw response or whether they are genuinely 
			// interested in the parsed response.
			return response;
		}
	}

	/**
	 * The whois server host name.
	 */
	public final static String WHOIS_HOST = "whois.publicinterestregistry.net";

	protected static String DOMAIN_STR = "Registrant Name:SEE SPONSORING REGISTRAR";
	protected static String WHOIS_STR  = "Registrant Street1:Whois Server:";
	
	private static ResolvePIR instance;
	
	/**
	 * Construct a PIR resolver. Only instantiated outside this class.
	 */
	private ResolvePIR() {
		super(WHOIS_HOST);
		// TODO: Fix this properly!
		super.WHOIS_STR = WHOIS_STR;
		super.DOMAIN_STR = DOMAIN_STR;
	}
	
	/**
	 * Get an instance of the PIR resolver.
	 * @return
	 */
	public static ResolvePIR getInstance() {
		if (instance == null) {
			instance = new ResolvePIR();
		}
		return instance;
	}
}
