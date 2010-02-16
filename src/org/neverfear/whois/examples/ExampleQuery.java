package org.neverfear.whois.examples;

import org.neverfear.whois.WhoisQuery;
import org.neverfear.whois.WhoisResponse;

public class ExampleQuery {
	public static void main(String [] args) throws Exception {
		WhoisQuery query = new WhoisQuery("neverfear.org");
		WhoisResponse response = query.getResponse();
		System.out.println(response.getData());
	}
}