package org.neverfear.whois.parsers.pir;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.neverfear.whois.WhoisResponse;
import org.neverfear.whois.parsers.WhoisParseException;

/**
 * A parsed public interest registry response.
 * 
 * @author doug@neverfear.org
 * 
 */
public abstract class ParsedPIRResponse extends WhoisResponse {

	private static final DateFormat	format						= new SimpleDateFormat( "dd-MMM-yyyy HH:mm:ss z" );
	private static final String		regexDate					= "([0-9]{1,2}\\-[A-Za-z]{3}\\-[0-9]{4} [0-9]{1,2}:[0-9]{2}:[0-9]{2} .*)";

	private static final Pattern	patternDomainID				= Pattern.compile( "^Domain ID:(.+)$" );
	private static final Pattern	patternDomainName			= Pattern.compile( "^Domain Name:(.+)$" );
	private static final Pattern	patternCreatedOn			= Pattern.compile( "^Created On:" + regexDate + "$" );
	private static final Pattern	patternLastUpdatedOn		= Pattern.compile( "^Last Updated On:" + regexDate + "$" );
	private static final Pattern	patternLastExpirationDate	= Pattern.compile( "^Expiration Date:" + regexDate + "$" );
	private static final Pattern	patternSponsoringRegistrar	= Pattern.compile( "^Sponsoring Registrar:(.*)$" );

	private static final String		regexContactID				= "ID:(.+)$";
	private static final String		regexContactName			= "Name:(.+)$";
	private static final String		regexContactOrganization	= "Organization:(.*)$";
	private static final String		regexContactStreet1			= "Street1:(.*)$";
	private static final String		regexContactStreet2			= "Street2:(.*)$";
	private static final String		regexContactStreet3			= "Street3:(.*)$";
	private static final String		regexContactCity			= "City:(.*)$";
	private static final String		regexContactProvince		= "State/Province:(.*)$";
	private static final String		regexContactPostalCode		= "Postal Code:(.*)$";
	private static final String		regexContactCountry			= "Country:(.*)$";
	private static final String		regexContactPhone			= "Phone:(.*)$";
	private static final String		regexContactPhoneExt		= "Phone Ext.:(.*)$";
	private static final String		regexContactFax				= "FAX:(.*)$";
	private static final String		regexContactFaxExt			= "FAX Ext.:(.*)$";
	private static final String		regexContactEmail			= "Email:(.*)$";

	private static final Pattern	patternNameServer			= Pattern.compile( "^Name Server:(.*)$" );
	private static final Pattern	patternDnsSecurity			= Pattern.compile( "^DNSSEC:(.*)$" );

	private static final String		REGISTRANT_PREFIX			= "Registrant ";
	private static final String		ADMIN_PREFIX				= "Admin ";
	private static final String		TECH_PREFIX					= "Tech ";


	/**
	 * Construct a PIR parsed whois response. Protected constructor.
	 * 
	 * @param name
	 *            The name that was queried.
	 */
	protected ParsedPIRResponse( String name ) {
		super( name );
	}
	
	/**
	 * Construct a PIR parsed whois response.
	 * 
	 * @param name
	 *            The name that was queried.
	 * @param data
	 *            The response data.
	 * @throws ParseException
	 * @throws IOException
	 */
	public ParsedPIRResponse( String name, String data ) throws WhoisParseException {
		super( name, data );
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
	protected static boolean parseContact( String line, AbstractContact contact, String prefix ) throws ParseException {
		if ( !line.startsWith( prefix ) ) {
			return false;
		}

		Matcher match;

		if ( (match = Pattern.compile( prefix + regexContactID ).matcher( line )).matches() ) {
			contact.setID( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactName ).matcher( line )).matches() ) {
			contact.setName( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactOrganization ).matcher( line )).matches() ) {
			contact.setOrganization( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactStreet1 ).matcher( line )).matches() ) {
			contact.setStreet1( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactStreet2 ).matcher( line )).matches() ) {
			contact.setStreet2( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactStreet3 ).matcher( line )).matches() ) {
			contact.setStreet3( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactCity ).matcher( line )).matches() ) {
			contact.setCity( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactProvince ).matcher( line )).matches() ) {
			contact.setProvince( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactPostalCode ).matcher( line )).matches() ) {
			contact.setPostalCode( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactCountry ).matcher( line )).matches() ) {
			contact.setCountry( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactPhone ).matcher( line )).matches() ) {
			contact.setPhone( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactPhoneExt ).matcher( line )).matches() ) {
			contact.setPhoneExtension( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactFax ).matcher( line )).matches() ) {
			contact.setFax( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactFaxExt ).matcher( line )).matches() ) {
			contact.setFaxExtension( match.group( 1 ) );
			return true;
		}

		if ( (match = Pattern.compile( prefix + regexContactEmail ).matcher( line )).matches() ) {
			contact.setEmail( match.group( 1 ) );
			return true;
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
	protected boolean parse( String data ) throws WhoisParseException {
		Matcher match;

		RegistrantContact registrant = new RegistrantContact();
		AdminContact admin = new AdminContact();
		TechContact tech = new TechContact();

		clearNameServers();

		StringReader dataReader = new StringReader( data );
		BufferedReader reader = new BufferedReader( dataReader );
		String line;

		try {
			while ( (line = reader.readLine()) != null ) {
				if ( (match = patternDomainID.matcher( line )).matches() ) {
					setID( match.group( 1 ) );
					continue;
				}

				if ( (match = patternDomainName.matcher( line )).matches() ) {
					setName( match.group( 1 ) );
					continue;
				}

				if ( (match = patternCreatedOn.matcher( line )).matches() ) {
					setCreatedOn( match.group( 1 ) );
					continue;
				}

				if ( (match = patternLastUpdatedOn.matcher( line )).matches() ) {
					setLastUpdated( match.group( 1 ) );
					continue;
				}

				if ( (match = patternLastExpirationDate.matcher( line )).matches() ) {
					setExpirationDate( match.group( 1 ) );
					continue;
				}

				if ( (match = patternSponsoringRegistrar.matcher( line )).matches() ) {
					setRegistrar( match.group( 1 ) );
					continue;
				}

				if ( parseContact( line, registrant, REGISTRANT_PREFIX ) ) {
					continue;
				}

				if ( parseContact( line, admin, ADMIN_PREFIX ) ) {
					continue;
				}

				if ( parseContact( line, tech, TECH_PREFIX ) ) {
					continue;
				}

				if ( (match = patternNameServer.matcher( line )).matches() ) {
					String nameServer = match.group( 1 ).trim();
					if ( nameServer.length() != 0 ) {
						addNameServer( nameServer );
					}
					continue;
				}

				if ( (match = patternDnsSecurity.matcher( line )).matches() ) {
					setDnsSecurity( match.group( 1 ) );
					continue;
				}

			}
		} catch (IOException e) {
			throw new WhoisParseException("Failed to readLine", e);
		} catch (ParseException e) {
			throw new WhoisParseException("Failed to parse contact", e);
		}

		setRegistrant( registrant );
		setAdmin( admin );
		setTech( tech );

		return true;
	}

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

	/**
	 * Set whether DNS security is enabled as a string.
	 * 
	 * @param dnsSecurity
	 */
	protected abstract void setDnsSecurity( String dnsSecurity );

	/**
	 * Set the sponsoring registrar.
	 * 
	 * @param registrar
	 */
	protected abstract void setRegistrar( String registrar );

	/**
	 * Set the expiration date as a string.
	 * 
	 * @param expirationDate
	 *            the expiration date.
	 */
	protected abstract void setExpirationDate( Date expirationDate );

	/**
	 * Set the last updated date as a string.
	 * 
	 * @param lastUpdated
	 *            the date last updated.
	 */
	protected abstract void setLastUpdated( Date lastUpdated );

	/**
	 * Set the created on date as a string.
	 * 
	 * @param createdOn
	 *            the creation date.
	 */
	protected abstract void setCreatedOn( Date createdOn );

	/**
	 * Set the queried name.
	 * 
	 * @param name
	 */
	protected abstract void setName( String name );

	/**
	 * Set the response ID
	 * 
	 * @param id
	 */
	protected abstract void setID( String id );

	/**
	 * Set the registrant contact.
	 * 
	 * @param registrant
	 *            A contact object.
	 */
	protected abstract void setRegistrant( RegistrantContact registrant );

	/**
	 * Set the administrative contact.
	 * 
	 * @param admin
	 *            A contact object.
	 */
	protected abstract void setAdmin( AdminContact admin );

	/**
	 * Set the technical contact.
	 * 
	 * @param tech
	 *            A contact object.
	 */
	protected abstract void setTech( TechContact tech );

	/**
	 * Set the expiration date as a string. This is parsed and compiled into a
	 * Date object.
	 * 
	 * @param expirationDate
	 *            A date string in the following format: dd-MMM-yyyy HH:mm:ss z.
	 * @throws ParseException
	 */
	protected void setExpirationDate( String expirationDate ) throws ParseException {
		setExpirationDate( format.parse( expirationDate ) );
	}

	/**
	 * Set the last updated date as a string. This is parsed and compiled into a
	 * Date object.
	 * 
	 * @param lastUpdated
	 *            A date string in the following format: dd-MMM-yyyy HH:mm:ss z.
	 * @throws ParseException
	 */
	protected void setLastUpdated( String lastUpdated ) throws ParseException {
		setLastUpdated( format.parse( lastUpdated ) );
	}

	/**
	 * Set the created on date as a string. This is parsed and compiled into a
	 * Date object.
	 * 
	 * @param createdOn
	 *            A date string in the following format: dd-MMM-yyyy HH:mm:ss z.
	 * @throws ParseException
	 */
	protected void setCreatedOn( String createdOn ) throws ParseException {
		setCreatedOn( format.parse( createdOn ) );
	}

	@Override
	public String getData() {
		if (super.getData() == null) {
			StringBuffer buffer = new StringBuffer();
			
			buffer.append( "Domain ID:" );
			
			setData(buffer.toString());
		}
		return super.getData();
	}
	

}
