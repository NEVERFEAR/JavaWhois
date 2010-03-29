package org.neverfear.whois.pir;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class PIRDomainInfo extends PIRParser {

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
	private List<String>		nameservers	= new ArrayList<String>();
	private String				dnsSecurity;							// Should
																		// this
																		// be a
																		// Boolean?
	private RegistrantContact	registrant;
	private AdminContact		admin;
	private TechContact			tech;

	public PIRDomainInfo(String name, String data) throws ParseException, IOException {
		super(name, data);
		parse(data);
	}

	public String getID() {
		return ID;
	}

	@Override
	protected void setID(String iD) {
		ID = iD;
	}

	public String getName() {
		return name;
	}

	@Override
	protected void setName(String name) {
		this.name = name;
	}

	public Date getCreatedOn() {
		return createdOn;
	}

	@Override
	protected void setCreatedOn(Date createdOn) {
		this.createdOn = createdOn;
	}

	public Date getLastUpdated() {
		return lastUpdated;
	}

	@Override
	protected void setLastUpdated(Date lastUpdated) {
		this.lastUpdated = lastUpdated;
	}

	public Date getExpirationDate() {
		return expirationDate;
	}

	@Override
	protected void setExpirationDate(Date expirationDate) {
		this.expirationDate = expirationDate;
	}

	public String getRegistrar() {
		return registrar;
	}

	@Override
	protected void setRegistrar(String registrar) {
		this.registrar = registrar;
	}

	public String getDnsSecurity() {
		return dnsSecurity;
	}

	@Override
	protected void setDnsSecurity(String dnsSecurity) {
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
	protected boolean addNameServer(String nameserver) {
		return nameservers.add(nameserver);
	}

	/**
	 * Remove the given name server.
	 * 
	 * @param nameserver
	 *            A hostname.
	 * @return true or false.
	 */
	@Override
	protected boolean removeNameServer(String nameserver) {
		return nameservers.remove(nameserver);
	}

	/**
	 * If this domain info has the given name server.
	 * 
	 * @param nameserver
	 *            A hostname.
	 * @return true or false.
	 */
	public boolean hasNameServer(String nameserver) {
		return nameservers.contains(nameserver);
	}

	/**
	 * Get a copy of the internal nameservers.
	 * 
	 * @return A List of Strings
	 */
	public List<String> getNameServers() {
		return new ArrayList<String>(nameservers);
	}

	public RegistrantContact getRegistrant() {
		return registrant;
	}

	protected void setRegistrant(RegistrantContact registrant) {
		this.registrant = registrant;
	}

	public AdminContact getAdmin() {
		return admin;
	}

	protected void setAdmin(AdminContact admin) {
		this.admin = admin;
	}

	public TechContact getTech() {
		return tech;
	}

	protected void setTech(TechContact tech) {
		this.tech = tech;
	}

	@Override
	public String toString() {
		return "PIRDomainInfo [ID=" + ID + ", admin=" + admin + ", createdOn=" + createdOn + ", dnsSecurity=" + dnsSecurity
				+ ", expirationDate=" + expirationDate + ", lastUpdated=" + lastUpdated + ", name=" + name + ", nameservers=" + nameservers
				+ ", registrant=" + registrant + ", registrar=" + registrar + ", tech=" + tech + "]";
	}

}
