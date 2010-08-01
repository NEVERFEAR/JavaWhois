package org.neverfear.whois.pir;

import java.io.IOException;

/**
 * The contact information for the domain administration contact.
 * @author doug@neverfear.org
 */
public class AdminContact extends AbstractContact {

	public final static String TYPE = "Admin";
	
	public String getData( ) throws IOException {
		return super.getData( TYPE );
	}
	
}
