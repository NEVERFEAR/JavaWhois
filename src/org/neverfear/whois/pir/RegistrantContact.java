package org.neverfear.whois.pir;

import java.io.IOException;

/**
 * The contact information for the domain registrant.
 * @author doug@neverfear.org
 */
public class RegistrantContact extends AbstractContact {

	public final static String TYPE = "Registrant";
	
	public String getData( ) throws IOException {
		return super.getData( TYPE );
	}
	
}
