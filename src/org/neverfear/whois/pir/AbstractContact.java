package org.neverfear.whois.pir;

import java.io.IOException;
import java.io.InputStream;

/**
 * Generalised information on public interest registry contacts.
 * 
 * @author doug@neverfear.org
 */
public abstract class AbstractContact {

	private String	ID;
	private String	name;
	private String	organization;
	private String	street1;
	private String	street2;
	private String	street3;
	private String	city;
	private String	province;
	private String	postalCode;
	private String	country;
	private String	phone;
	private String	phoneExtension;
	private String	fax;
	private String	faxExtension;
	private String	email;

	public String getID() {
		return ID;
	}

	public void setID( String iD ) {
		ID = iD;
	}

	public String getName() {
		return name;
	}

	public void setName( String name ) {
		this.name = name;
	}

	public String getOrganization() {
		return organization;
	}

	public void setOrganization( String organization ) {
		this.organization = organization;
	}

	public String getStreet1() {
		return street1;
	}

	public void setStreet1( String street1 ) {
		this.street1 = street1;
	}

	public String getStreet2() {
		return street2;
	}

	public void setStreet2( String street2 ) {
		this.street2 = street2;
	}

	public String getStreet3() {
		return street3;
	}

	public void setStreet3( String street3 ) {
		this.street3 = street3;
	}

	public String getStreet() {
		return getStreet1() + "\n" + getStreet2() + "\n" + getStreet3();
	}
	
	/**
	 * Get a full street address. Including street, city, province, postal code and country separated by new lines.
	 * @return
	 */
	public String getAddress() {
		return getStreet() + "\n" + getCity() + "\n" + getProvince() + "\n" + getPostalCode() + "\n" + getCountry() + "\n";
	}

	public String getCity() {
		return city;
	}

	public void setCity( String city ) {
		this.city = city;
	}

	public String getProvince() {
		return province;
	}

	public void setProvince( String province ) {
		this.province = province;
	}

	public String getPostalCode() {
		return postalCode;
	}

	public void setPostalCode( String postalCode ) {
		this.postalCode = postalCode;
	}

	public String getCountry() {
		return country;
	}

	public void setCountry( String country ) {
		this.country = country;
	}

	public String getPhone() {
		return phone;
	}

	public void setPhone( String phone ) {
		this.phone = phone;
	}

	public String getPhoneExtension() {
		return phoneExtension;
	}

	public void setPhoneExtension( String phoneExtension ) {
		this.phoneExtension = phoneExtension;
	}

	public String getFax() {
		return fax;
	}

	public void setFax( String fax ) {
		this.fax = fax;
	}

	public String getFaxExtension() {
		return faxExtension;
	}

	public void setFaxExtension( String faxExtension ) {
		this.faxExtension = faxExtension;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail( String email ) {
		this.email = email;
	}

	@Override
	public String toString() {
		return "AbstractContact [ID=" + ID + ", city=" + city + ", country=" + country + ", email=" + email + ", fax=" + fax
				+ ", faxExtension=" + faxExtension + ", name=" + name + ", organization=" + organization + ", phone=" + phone
				+ ", phoneExtension=" + phoneExtension + ", postalCode=" + postalCode + ", province=" + province + ", street1=" + street1
				+ ", street2=" + street2 + ", street3=" + street3 + "]";
	}
	
	private String loadResource( String name ) throws IOException {
		final InputStream is = ClassLoader.getSystemResourceAsStream( name );
		byte[] b = new byte[512];
		int count = -1;
		StringBuffer buffer = new StringBuffer();
		while ( (count = is.read( b )) != -1 ) {
			buffer.append( new String( b, 0, count ) );
		}
		return buffer.toString();
	}
	
	/**
	 * Get the constructed PIR data for this contact.
	 * @return
	 */
	public String getData(String linePrefix) throws IOException
	{
		String template = loadResource("org/neverfear/whois/pir/contact.template");
		return String.format( template, linePrefix, getID(), getName(), getOrganization(), getStreet1(), getStreet2(), getStreet3(), 
				getCity(), getProvince(), getPostalCode(), getCountry(), getPhone(), getPhoneExtension(), getFax(), getFaxExtension(), 
				getEmail());
	}
	
	
}
