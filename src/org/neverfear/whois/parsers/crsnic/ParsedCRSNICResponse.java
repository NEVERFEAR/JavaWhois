/**
 * 
 */
package org.neverfear.whois.parsers.crsnic;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.text.ParseException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.neverfear.whois.Countries;
import org.neverfear.whois.WhoisResponse;
import org.neverfear.whois.parsers.WhoisParseException;
import org.neverfear.whois.parsers.pir.AbstractContact;
import org.neverfear.whois.parsers.pir.AdminContact;
import org.neverfear.whois.parsers.pir.RegistrantContact;
import org.neverfear.whois.parsers.pir.TechContact;

/**
 * A parsed CRSNIC response.
 * 
 * @author doug@neverfear.org
 */
public abstract class ParsedCRSNICResponse extends WhoisResponse {

	private static final String		PATTERN_PHONE_NUMBER			= "\\+?[0-9]{0,3}\\.?[0-9]+";

	// Not RFC 822 but it'll do for now
	private static final String		PATTERN_EMAIL_822				= "(?:(?:\\r\\n)?[ \\t])*(?:(?:(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+"
																			+ "(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))"
																			+ "|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)"
																			+ "?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] "
																			+ "\\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\"."
																			+ "\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[\\t]))*\"(?:(?:\\r"
																			+ "\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] "
																			+ "\\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\"."
																			+ "\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*](?:(?:\\r\\n)?[ \\t])*)(?:\\."
																			+ "(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:"
																			+ "(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]"
																			+ "\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*|(?:[^()<>@,;:\\\\\".\\[\\]"
																			+ "\\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\"."
																			+ "\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r"
																			+ "\\n) ?[\\t])*)*\\<(?:(?:\\r\\n)?[ \\t])*(?:@(?:[^()<>@,;:\\\\\"."
																			+ "\\[\\] \\000-\\031]+(?:(?:(?:\\ r\\n)?[\\t])+|\\Z|(?=[\\[\"()<>@,;:"
																			+ "\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[\\t])*)"
																			+ "(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+"
																			+ "(?:(?:(?:\\r\\n) ?[\\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\["
																			+ "([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*(?:,@(?:(?:\\r"
																			+ "\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r"
																			+ "\\n)?[\\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]"
																			+ "\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t"
																			+ "])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])"
																			+ "+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*"
																			+ "\\](?:(?:\\r\\n)?[ \\t])*))*)*:(?:(?:\\r\\n)?[ \\t])*)?(?:[^()<>@,;:"
																			+ "\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()"
																			+ "<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t"
																			+ "]))*\"(?:(?:\\r \\n)?[\\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:"
																			+ "\\\\\".\\[\\] \\000-\\031]+(?:(?:(?: \\r\\n)?[\\t])+|\\Z|(?=[\\[\"()"
																			+ "<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t"
																			+ "]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:"
																			+ "\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()"
																			+ "<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?"
																			+ "[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-"
																			+ "\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))"
																			+ "|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*\\>(?:(?:\\r"
																			+ "\\n)?[ \\t])*)|(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r"
																			+ "\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r"
																			+ "\\\\]|\\\\.|(?:(?:\\r\\n)? [\\t]))*\"(?:(?:\\r\\n)?[ \\t])*)*:(?:(?:"
																			+ "\\r\\n)?[ \\t])*(?:(?:(?:[^()<>@,;:\\\\\".\\[\\]\\000-\\031]+(?:(?:"
																			+ "(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:"
																			+ "[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ "
																			+ "\\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] "
																			+ "\\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:"
																			+ "\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t])"
																			+ ")*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:"
																			+ "\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=["
																			+ "\\[\"()<>@,;:\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:"
																			+ "\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:"
																			+ "\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|"
																			+ "(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)"
																			+ "*\\](?:(?:\\r\\n)?[ \\t])*))*|(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]"
																			+ "+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))"
																			+ "|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?"
																			+ "[ \\t])*)*\\<(?:(?:\\r\\n)?[ \\t])*(?:@(?:[^()<>@,;:\\\\\".\\[\\]"
																			+ "\\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\"."
																			+ "\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:"
																			+ "\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\" .\\[\\]\\000-\\031]+"
																			+ "(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|"
																			+ "\\[([^\\[]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*(?:,@(?:(?:\\r"
																			+ "\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\ [\\]\\000-\\031]+(?:(?:(?:\\r\\n)"
																			+ "?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]r\\\\]|"
																			+ "\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:"
																			+ "[^()<>@,;:\\\\\".\\[\\]\\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|"
																			+ "(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\]"
																			+ "(?:(?:\\r\\n)?[ \\t])*))*)*:(?:(?:\\r\\n)?[ \\t])*)?(?:[^()"
																			+ "<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z"
																			+ "|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\.|(?:"
																			+ "(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:"
																			+ "\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:"
																			+ "(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|"
																			+ "\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r"
																			+ "\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\"."
																			+ "\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?="
																			+ "[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)"
																			+ "*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:"
																			+ "[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t"
																			+ "])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r"
																			+ "\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*\\>(?:(?:\\r\\n)?"
																			+ "[ \\t])*)(?:,\\s*(?:(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+"
																			+ "(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\".\\[\\]]))|"
																			+ "\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:\\r"
																			+ "\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\"."
																			+ "\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()"
																			+ "<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r"
																			+ "\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?["
																			+ "\\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r"
																			+ "\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^"
																			+ "\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:"
																			+ "\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:"
																			+ "(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\["
																			+ "\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ "
																			+ "\\t])*))*|(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:"
																			+ "(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[]]))|"
																			+ "\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r\\n)?[ \\t]))*\"(?:(?:"
																			+ "\\r\\n)?[ \\t])*)*\\<(?:(?:\\r\\n) ?[\\t])*(?:@(?:[^()<>@,;"
																			+ ":\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|"
																			+ "(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|"
																			+ "\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n) ?["
																			+ "\\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r"
																			+ "\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[("
																			+ "[^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*(?:,@(?:"
																			+ "(?:\\r\\n)?[\\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+"
																			+ "(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|"
																			+ "\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:"
																			+ "\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r"
																			+ "\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|"
																			+ "\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*)*:(?:(?:\\r\\n)?[ \\t])*)?(?:[^()"
																			+ "<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=["
																			+ "\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:\\r"
																			+ "\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*)(?:\\.(?:(?:\\r\\n)?[ \\t])"
																			+ "*(?:[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|"
																			+ "\\Z|(?=[\\[\"()<>@,;:\\\\\".\\[\\]]))|\"(?:[^\\\"\\r\\\\]|\\\\.|(?:(?:"
																			+ "\\r\\n)?[ \\t]))*\"(?:(?:\\r\\n)?[ \\t])*))*@(?:(?:\\r\\n)?[ \\t])*(?:"
																			+ "[^()<>@,;:\\\\\".\\[\\] \\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?="
																			+ "[\\[\"()<>@,;:\\\\\".\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r"
																			+ "\\n)?[ \\t])*)(?:.(?:(?:\\r\\n)?[ \\t])*(?:[^()<>@,;:\\\\\".\\[\\] "
																			+ "\\000-\\031]+(?:(?:(?:\\r\\n)?[ \\t])+|\\Z|(?=[\\[\"()<>@,;:\\\\\"."
																			+ "\\[\\]]))|\\[([^\\[\\]\\r\\\\]|\\\\.)*\\](?:(?:\\r\\n)?[ \\t])*))*\\>"
																			+ "(?:(?:\\r\\n)?[ \\t])*))*)?;\\s*)";

	// Name Servers
	private static final Pattern	patternNameServers1Label		= Pattern.compile( "^Domain servers in listed order:$" );
	private static final Pattern    patternNameServers2Label  		= Pattern.compile( "^Name Server[\\.]*[ ](.*?)$" );
	
	// Contact labels
	private static final Pattern	patternRegistrantLabel			= Pattern.compile( "^Registrant(.*?)?:$" );
	private static final Pattern	patternAdministratorLabel		= Pattern.compile( "^Administrative Contact(.*?)?:$" );
	private static final Pattern	patternTechnicalLabel			= Pattern.compile( "^Technical Contact(.*?)?:$" );
	
	// Contact information
	private static final Pattern	patternEmailPhoneFax			= Pattern.compile( "^" + PATTERN_EMAIL_822 + " (" + PATTERN_PHONE_NUMBER + ") Fax: (" + PATTERN_PHONE_NUMBER + ")$" );
	private static final Pattern	patternPhoneFax					= Pattern.compile( "^(" + PATTERN_PHONE_NUMBER + ")[ ]*Fax (" + PATTERN_PHONE_NUMBER + ")$" );
	private static final Pattern	patternPhone					= Pattern.compile( "^(" + PATTERN_PHONE_NUMBER + ")" );
	private static final Pattern	patternNameEmail				= Pattern.compile( "^(.*?)[ ]+" + PATTERN_EMAIL_822 + "$" );
	
	// Domain information
	private static final Pattern	patternDomainNameLabel			= Pattern.compile( "^Domain Name:([ ]*.*?)$" );
	private static final Pattern	patternRegistrarName1Label		= Pattern.compile( "^Registrar Name:([ ]*.*?)$" );
	private static final Pattern	patternRegistrarName2Label		= Pattern.compile( "^Registered through:([ ]*.*?)$" );
	private static final Pattern	patternRegistrarWhoisLabel		= Pattern.compile( "^Registrar Whois:([ ]*.*?)$" );
	private static final Pattern	patternRegistrarHomepageLabel	= Pattern.compile( "^Registrar Homepage:([ ]*.*?)$" );

	private static final Pattern[]	patternsCreatedOn				= {
			Pattern.compile( "^Created on(.*?): 1997-09-15\\.$" ), // google.com
			Pattern.compile( "^Record created on 19-Mar-1986\\.$" ), // ibm.com
			Pattern.compile( "^Creation Date(.*?) 1991-05-02$" )	// microsoft.com
																	};

	private static final Pattern[]	patternsExpiresOn				= {
			Pattern.compile( "^Expires on(.*?): 1997-09-15\\.$" ), // google.com
			Pattern.compile( "^Record expires on 19-Mar-1986\\.$" ), // ibm.com
			Pattern.compile( "^Expiry Date(.*?) 2015-05-04$" )		// microsoft.com
																	};

	private enum LabelStates {
		UNKNOWN, IN_REGISTRANT, IN_ADMINISTRATOR, IN_TECHNICAL, IN_NAMESERVER
	};

	public ParsedCRSNICResponse( String name, String data) throws WhoisParseException {
		super( name, data );
		parse( data );
	}

	/**
	 * Parse the line for specific contact information and load it into contact.
	 * 
	 * @param line
	 *            A line of response data.
	 * @param contact
	 *            A contact instance.
	 * @param prefix
	 *            The contact line prefix.
	 * @return true if the line was recognised as a contact information and set
	 *         on the object. false otherwise.
	 * @throws ParseException
	 */
	protected static boolean parseContact( String line, AbstractContact contact) throws ParseException {
		Matcher match;

		if ( (match = patternNameEmail.matcher( line )).matches() ) {
			contact.setName( match.group(0) );
			contact.setEmail( match.group(1) );
			return true;
		} else if ( (match = patternEmailPhoneFax.matcher( line )).matches() ) {
			contact.setEmail( match.group(0) );
			contact.setPhone( match.group(1) );
			contact.setFax( match.group(2) );
			return true;
		} else if ( (match = patternPhoneFax.matcher( line )).matches() ) {
			contact.setPhone( match.group(0) );
			contact.setFax( match.group(1) );
			return true;
		} else if ( (match = patternPhone.matcher( line )).matches() ) {
			contact.setPhone( match.group(0) );
			return true;
		} else if ( Countries.isCountry( line ) ) {
			contact.setCountry( line );
		}
		
		return false;
	}

	/**
	 * Parse the given public interest registry response data.
	 * 
	 * @param data
	 *            The response data.
	 * @return true.
	 * @throws ParseException
	 * @throws IOException
	 */
	protected synchronized boolean parse( String data ) throws WhoisParseException {

		Matcher match;
		LabelStates state = LabelStates.UNKNOWN;

		RegistrantContact registrant = new RegistrantContact();
		AdminContact admin = new AdminContact();
		TechContact tech = new TechContact();

		clearNameServers();

		StringReader dataReader = new StringReader( data );
		BufferedReader reader = new BufferedReader( dataReader );
		String line;

		try {
			while ( (line = reader.readLine()) != null ) {
				line = line.trim();
				
				//
				
				if ( (match = patternRegistrarName1Label.matcher( line )).matches() ) {
					setRegistrar( match.group(0) );
					continue;
				} else if ( (match = patternRegistrarName2Label.matcher( line )).matches() ) {
					setRegistrar( match.group(0) );
					continue;
				}
				
				//
				
				if ( (match = patternRegistrantLabel.matcher( line )).matches() ) {
					state = LabelStates.IN_REGISTRANT;
					continue;
				} else if ( (match = patternAdministratorLabel.matcher( line )).matches() ) {
					state = LabelStates.IN_ADMINISTRATOR;
					continue;
				} else if ( (match = patternTechnicalLabel.matcher( line )).matches() ) {
					state = LabelStates.IN_TECHNICAL;
					continue;
				} else if ( (match = patternNameServers1Label.matcher( line )).matches() ) {
					state = LabelStates.IN_NAMESERVER;
					continue;
				}
				
				//
				
				if ( (match = patternNameServers2Label.matcher( line )).matches() ) {
					addNameServer( match.group(0) );
					continue;
				}
				
				//
				
				switch(state) {
					case IN_REGISTRANT:
						if (parseContact( line, registrant )) {
							continue;
						}
						break;
					case IN_ADMINISTRATOR:
						if (parseContact( line, admin )) {
							continue;
						}
						break;
					case IN_TECHNICAL:
						if (parseContact( line, tech )) {
							continue;
						}
						break;
					case IN_NAMESERVER:
						addNameServer( line );
						break;
				}
				
				
			}
		} catch (IOException e) {
			throw new WhoisParseException("Failed to readLine", e);
		} catch (ParseException e) {
			throw new WhoisParseException("Failed to parse contact", e);
		}
		return true;
	}


	/**
	 * Set the sponsoring registrar.
	 * 
	 * @param registrar
	 */
	protected abstract void setRegistrar( String registrar );
	
	/**
	 * Clear out the list of name servers.
	 */
	protected abstract void clearNameServers();

	/**
	 * Remove the name server from the name server list.
	 * 
	 * @param nameserver
	 *            A hostname.
	 * @return
	 */
	protected abstract boolean removeNameServer( String nameserver );

	/**
	 * Add a name server to the name server list.
	 * 
	 * @param nameserver
	 *            A hostname.
	 * @return
	 */
	protected abstract boolean addNameServer( String nameserver );
	
}
