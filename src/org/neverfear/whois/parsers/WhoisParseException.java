package org.neverfear.whois.parsers;

public class WhoisParseException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 4518930446352291683L;

	/**
	 * @param message
	 * @param cause
	 */
	public WhoisParseException(String message, Throwable cause) {
		super(message, cause);
	}

}
