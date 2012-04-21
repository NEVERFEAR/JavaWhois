package org.neverfear.whois.parsers.pir;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.neverfear.whois.WhoisResponse;
import org.neverfear.whois.parsers.WhoisParseException;

public class PublicInterestRegistryResponse extends ParsedPIRResponse {

	/*
	 * Status:CLIENT DELETE PROHIBITED Status:CLIENT RENEW PROHIBITED
	 * Status:CLIENT TRANSFER PROHIBITED Status:CLIENT UPDATE PROHIBITED
	 */

	private String				ID;
	private String				name;
	private Date				createdOn;
	private Date				lastUpdated;
	private Date				expirationDate;
	private String				registrar;
	// TODO: Status
	private List<String>		nameservers;
	private String				dnsSecurity;	// Should
	// this
	// be a
	// Boolean?
	private RegistrantContact	registrant;
	private AdminContact		admin;
	private TechContact			tech;


	/**
	 * Construct a PIR response around a query name. This object will need configuring.
	 * Then when you call getData() it will generate appropriate PIR formatted text.
	 * @param name
	 * @throws ParseException
	 * @throws IOException
	 */
	public PublicInterestRegistryResponse( String name ) {
		super( name );
		initCommon();
	}
	
	/**
	 * Construct a PIR response around a query name and some response data.
	 * @param name
	 * @param data
	 * @throws ParseException
	 * @throws IOException
	 */
	public PublicInterestRegistryResponse( String name, String data ) throws WhoisParseException {
		super( name, data );
		initCommon();
		parse( data );
	}
	
	public PublicInterestRegistryResponse( WhoisResponse response) throws WhoisParseException {
		this(response.getName(), response.getData());
	}
	
	private void initCommon() {
		nameservers = new ArrayList<String>();
	}

	public String getID() {
		return ID;
	}

	@Override
	protected void setID( String iD ) {
		ID = iD;
	}

	public String getName() {
		return name;
	}

	@Override
	protected void setName( String name ) {
		this.name = name;
	}

	public Date getCreatedOn() {
		return createdOn;
	}

	@Override
	protected void setCreatedOn( Date createdOn ) {
		this.createdOn = createdOn;
	}

	public Date getLastUpdated() {
		return lastUpdated;
	}

	@Override
	protected void setLastUpdated( Date lastUpdated ) {
		this.lastUpdated = lastUpdated;
	}

	public Date getExpirationDate() {
		return expirationDate;
	}

	@Override
	protected void setExpirationDate( Date expirationDate ) {
		this.expirationDate = expirationDate;
	}

	public String getRegistrar() {
		return registrar;
	}

	@Override
	protected void setRegistrar( String registrar ) {
		this.registrar = registrar;
	}

	public String getDnsSecurity() {
		return dnsSecurity;
	}

	@Override
	protected void setDnsSecurity( String dnsSecurity ) {
		this.dnsSecurity = dnsSecurity;
	}

	/**
	 * Clears all current name servers out.
	 * 
	 * @return true or false.
	 */
	@Override
	protected void clearNameServers() {
		nameservers.clear();
	}

	/**
	 * Add the given name server.
	 * 
	 * @param nameserver
	 *            A hostname.
	 * @return true or false.
	 */
	@Override
	protected boolean addNameServer( String nameserver ) {
		return nameservers.add( nameserver );
	}

	/**
	 * Remove the given name server.
	 * 
	 * @param nameserver
	 *            A hostname.
	 * @return true or false.
	 */
	@Override
	protected boolean removeNameServer( String nameserver ) {
		return nameservers.remove( nameserver );
	}

	/**
	 * If this domain info has the given name server.
	 * 
	 * @param nameserver
	 *            A hostname.
	 * @return true or false.
	 */
	public boolean hasNameServer( String nameserver ) {
		return nameservers.contains( nameserver );
	}

	/**
	 * Get a copy of the internal nameservers.
	 * 
	 * @return A List of Strings
	 */
	public List<String> getNameServers() {
		return new ArrayList<String>( nameservers );
	}

	public RegistrantContact getRegistrant() {
		return registrant;
	}

	protected void setRegistrant( RegistrantContact registrant ) {
		this.registrant = registrant;
	}

	public AdminContact getAdmin() {
		return admin;
	}

	protected void setAdmin( AdminContact admin ) {
		this.admin = admin;
	}

	public TechContact getTech() {
		return tech;
	}

	protected void setTech( TechContact tech ) {
		this.tech = tech;
	}

	@Override
	public String toString() {
		return "PublicInterestRegistryResponse [ID=" + ID + ", admin=" + admin + ", createdOn=" + createdOn + ", dnsSecurity=" + dnsSecurity
				+ ", expirationDate=" + expirationDate + ", lastUpdated=" + lastUpdated + ", name=" + name + ", nameservers=" + nameservers
				+ ", registrant=" + registrant + ", registrar=" + registrar + ", tech=" + tech + "]";
	}

	/**
	 * Parse the data and create a ParsedPIRResponse object.
	 * 
	 * @param name
	 *            The queried name.
	 * @param data
	 *            The whois response data.
	 * @return A built ParsedPIRResponse.
	 */
	public static PublicInterestRegistryResponse create( String name, String data ) throws WhoisParseException {
		return new PublicInterestRegistryResponse( name, data );
	}

}
