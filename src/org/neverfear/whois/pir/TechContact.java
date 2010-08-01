package org.neverfear.whois.pir;

import java.io.IOException;

/**
 * The contact information for the domain technical contact.
 * @author doug@neverfear.org
 */
public class TechContact extends AbstractContact {

	public final static String TYPE = "Tech";
	
	public String getData( ) throws IOException {
		return super.getData( TYPE );
	}
	
}
