package org.neverfear.whois;


/**
 * Represents a public interest registry.
 * @author doug@neverfear.org
 */
public class ResolvePIR extends ResolveCRSNIC {
	
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
