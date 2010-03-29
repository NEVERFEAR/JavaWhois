package org.neverfear.whois.pir;

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

/**
 * Parses a PIR response
 * 
 * @author doug@neverfear.org
 * 
 */
public abstract class PIRParser extends WhoisResponse {

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

	public PIRParser( String name, String data ) throws ParseException, IOException {
		super( name, data );
	}

	protected boolean parseContact( String line, AbstractContact contact, String prefix ) throws ParseException {
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
	 * Parse the given PIR data
	 * 
	 * @param data
	 * @return
	 * @throws ParseException
	 */
	protected boolean parse( String data ) throws ParseException, IOException {

		RegistrantContact registrant = new RegistrantContact();
		AdminContact admin = new AdminContact();
		TechContact tech = new TechContact();

		Matcher match;

		clearNameServers();

		StringReader dataReader = new StringReader( data );
		BufferedReader reader = new BufferedReader( dataReader );
		String line;

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
				addNameServer( match.group( 1 ) );
				continue;
			}

			if ( (match = patternDnsSecurity.matcher( line )).matches() ) {
				setDnsSecurity( match.group( 1 ) );
				continue;
			}

		}

		setRegistrant( registrant );
		setAdmin( admin );
		setTech( tech );

		return true;
	}

	protected abstract void clearNameServers();

	protected abstract boolean removeNameServer( String nameserver );

	protected abstract boolean addNameServer( String nameserver );

	protected abstract void setDnsSecurity( String dnsSecurity );

	protected abstract void setRegistrar( String registrar );

	protected abstract void setExpirationDate( Date expirationDate );

	protected abstract void setLastUpdated( Date lastUpdated );

	protected abstract void setCreatedOn( Date createdOn );

	protected abstract void setName( String name );

	protected abstract void setID( String id );

	protected abstract void setRegistrant( RegistrantContact registrant );

	protected abstract void setAdmin( AdminContact admin );

	protected abstract void setTech( TechContact tech );

	protected void setExpirationDate( String expirationDate ) throws ParseException {
		setExpirationDate( format.parse( expirationDate ) );
	}

	protected void setLastUpdated( String lastUpdated ) throws ParseException {
		setLastUpdated( format.parse( lastUpdated ) );
	}

	protected void setCreatedOn( String createdOn ) throws ParseException {
		setCreatedOn( format.parse( createdOn ) );
	}

}
