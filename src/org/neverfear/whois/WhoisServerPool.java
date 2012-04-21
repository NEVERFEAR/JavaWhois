package org.neverfear.whois;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * A class representing a pool of WHOIS servers.
 * @author doug@neverfear.org
 *
 */
public class WhoisServerPool {
	
	/**
	 * A Map of TLDs to WhoisServce instances.
	 */
	public static final HashMap<String, WhoisServer> servers = new HashMap<String, WhoisServer>() {
		/**
		 * 
		 */
		private static final long serialVersionUID = 2955465571286080919L;

		{
		    put(".br.com",  			new WhoisServer(".br.com",   				new ResolveDefault("whois.centralnic.net")));
		    put(".cn.com",  			new WhoisServer(".cn.com",   				new ResolveDefault("whois.centralnic.net")));
		    put(".de.com",  			new WhoisServer(".de.com",   				new ResolveDefault("whois.centralnic.net")));
			put(".eu.com",  			new WhoisServer(".eu.com",   				new ResolveDefault("whois.centralnic.net")));
		    put(".gb.com",  			new WhoisServer(".gb.com",   				new ResolveDefault("whois.centralnic.net")));
		    put(".gb.net",  			new WhoisServer(".gb.net",   				new ResolveDefault("whois.centralnic.net")));
		    put(".hu.com",  			new WhoisServer(".hu.com",   				new ResolveDefault("whois.centralnic.net")));
		    put(".no.com",  			new WhoisServer(".no.com",  				new ResolveDefault("whois.centralnic.net")));
		    put(".qc.com",  			new WhoisServer(".qc.com",  				new ResolveDefault("whois.centralnic.net")));
		    put(".ru.com",  			new WhoisServer(".ru.com",  				new ResolveDefault("whois.centralnic.net")));
			put(".sa.com",  			new WhoisServer(".sa.com", 		  			new ResolveDefault("whois.centralnic.net")));
		    put(".se.com",  			new WhoisServer(".se.com",  				new ResolveDefault("whois.centralnic.net")));
		    put(".se.net",  			new WhoisServer(".se.net",  				new ResolveDefault("whois.centralnic.net")));
		    put(".uk.com",  			new WhoisServer(".uk.com",  				new ResolveDefault("whois.centralnic.net")));
		    put(".uk.net",  			new WhoisServer(".uk.net",   				new ResolveDefault("whois.centralnic.net")));
		    put(".us.com",  			new WhoisServer(".us.com",   				new ResolveDefault("whois.centralnic.net")));
		    put(".uy.com",  			new WhoisServer(".uy.com",   				new ResolveDefault("whois.centralnic.net")));
		    put(".za.com",  			new WhoisServer(".za.com",   				new ResolveDefault("whois.centralnic.net")));
		    put(".jpn.com", 			new WhoisServer(".jpn.com",  				new ResolveDefault("whois.centralnic.net")));
		    put(".web.com", 			new WhoisServer(".web.com",  				new ResolveDefault("whois.centralnic.net")));
		    put(".com",     			new WhoisServer(".com",      				new ResolveCRSNIC("whois.crsnic.net")));
		    put(".za.net",  			new WhoisServer(".za.net",   				new ResolveDefault("whois.za.net")));
		    put(".net",     			new WhoisServer(".net",      				new ResolveCRSNIC("whois.crsnic.net")));
		    put(".eu.org",  			new WhoisServer(".eu.org",   				new ResolveDefault("whois.eu.org")));
		    put(".za.org",  			new WhoisServer(".za.org",   				new ResolveDefault("whois.za.org")));
		    put(".org",     			new WhoisServer(".org",      				ResolvePIR.getInstance()));
		    put(".edu",     			new WhoisServer(".edu",      				new ResolveDefault("whois.educause.net")));
		    put(".gov",     			new WhoisServer(".gov",      				new ResolveDefault("whois.nic.gov")));
		    put(".int",     			new WhoisServer(".int",      				new ResolveDefault("whois.iana.org")));
		    put(".mil",     			new WhoisServer(".mil",      				new CannotResolve()));
		    put(".e164.arpa",			new WhoisServer(".e164.arpa",				new ResolveDefault("whois.ripe.net")));
		    //put(".in-addr.arpa",    	new WhoisServer(".in-addr.arpa",     		new ResolveDefault("")));
		    put(".arpa",    			new WhoisServer(".arpa",     				new ResolveDefault("whois.iana.org")));
		    put(".aero",    			new WhoisServer(".aero",     				new ResolveDefault("whois.aero")));
		    put(".asia",    			new WhoisServer(".asia",     				new ResolveDefault("whois.nic.asia")));
		    put(".biz",     			new WhoisServer(".biz",      				new ResolveDefault("whois.nic.biz")));
		    put(".cat",     			new WhoisServer(".cat",      				new ResolveDefault("whois.cat")));
		    put(".coop",    			new WhoisServer(".coop",     				new ResolveDefault("whois.nic.coop")));
		    put(".info",    			new WhoisServer(".info",     				new ResolveDefault("whois.afilias.info")));
		    put(".jobs",    			new WhoisServer(".jobs",     				new ResolveCRSNIC("jobswhois.verisign-grs.com")));
		    put(".mobi",    			new WhoisServer(".mobi",     				new ResolveDefault("whois.dotmobiregistry.net")));
		    put(".museum",  			new WhoisServer(".museum",   				new ResolveDefault("whois.museum")));
		    put(".name",    			new WhoisServer(".name",     				new ResolveDefault("whois.nic.name")));
		    put(".pro",     			new WhoisServer(".pro",      				new ResolveDefault("whois.registrypro.pro")));
		    put(".tel",     			new WhoisServer(".tel",      				new ResolveDefault("whois.nic.tel")));
		    put(".travel",  			new WhoisServer(".travel",   				new ResolveDefault("whois.nic.travel")));
		    put(".ac",      			new WhoisServer(".ac",       				new ResolveDefault("whois.nic.ac")));
		    put(".ad",      			new WhoisServer(".ad",       				new CannotResolve()));
		    put(".ae",      			new WhoisServer(".ae",       				new ResolveDefault("whois.aeda.net.ae")));
		    put(".af",      			new WhoisServer(".af",       				new ResolveDefault("whois.nic.af")));
		    put(".ag",      			new WhoisServer(".ag",       				new ResolveDefault("whois.nic.ag")));
		    put(".ai",      			new WhoisServer(".ai",       				new ResolveDefault("whois.ai")));
		    put(".al",      			new WhoisServer(".al",       				new CannotResolve()));
		    put(".am",      			new WhoisServer(".am",       				new ResolveDefault("whois.nic.am")));
		    put(".an",      			new WhoisServer(".an",       				new CannotResolve()));
		    put(".ao",      			new WhoisServer(".ao",       				new CannotResolve()));
		    put(".aq",      			new WhoisServer(".aq",       				new CannotResolve()));
		    put(".ar",      			new WhoisServer(".ar",       				new ResolveURL("http://www.nic.ar/")));
		    put(".as",      			new WhoisServer(".as",       				new ResolveDefault("whois.nic.as")));
		    put(".at",      			new WhoisServer(".at",       				new ResolveDefault("whois.nic.at")));
		    put(".au",      			new WhoisServer(".au",       				new ResolveDefault("whois.ausregistry.net.au")));
		    put(".aw",      			new WhoisServer(".aw",       				new CannotResolve()));
		    put(".ax",      			new WhoisServer(".ax",       				new CannotResolve()));
		    put(".az",      			new WhoisServer(".az",       				new ResolveURL("http://www.nic.az/AzCheck.htm")));
		    put(".ba",      			new WhoisServer(".ba",       				new ResolveURL("http://www.nic.ba/stream/whois/")));
		    put(".bb",      			new WhoisServer(".bb",       				new ResolveURL("http://www.barbadosdomains.net/search_domain.php")));
		    put(".bd",      			new WhoisServer(".bd",       				new ResolveDefault("www.whois.com.bd")));
		    put(".be",      			new WhoisServer(".be",       				new ResolveDefault("whois.dns.be")));
		    put(".bf",      			new WhoisServer(".bf",       				new CannotResolve()));
		    put(".bg",      			new WhoisServer(".bg",       				new ResolveDefault("whois.register.bg")));
		    put(".bh",      			new WhoisServer(".bh",       				new CannotResolve()));
		    put(".bi",      			new WhoisServer(".bi",       				new ResolveURL("http://www.nic.bi/Nic_search.asp")));
		    put(".bj",      			new WhoisServer(".bj",       				new ResolveDefault("whois.nic.bj")));
		    put(".bm",      			new WhoisServer(".bm",       				new ResolveURL("http://207.228.133.14/cgi-bin/lansaweb?procfun+BMWHO+BMWHO2+WHO")));
		    put(".bn",      			new WhoisServer(".bn",       				new CannotResolve()));
		    put(".bo",      			new WhoisServer(".bo",       				new ResolveURL("http://www.nic.bo/")));
		    put(".br",      			new WhoisServer(".br",       				new ResolveDefault("whois.nic.br")));
		    put(".bs",      			new WhoisServer(".bs",       				new ResolveURL("http://www.nic.bs/cgi-bin/search.pl")));
		    put(".bt",      			new WhoisServer(".bt",       				new ResolveURL("http://www.nic.bt/")));
		    put(".bv",      			new WhoisServer(".bv",       				new CannotResolve()));
		    put(".by",      			new WhoisServer(".by",       				new ResolveURL("http://www.tld.by/indexeng.html")));
		    put(".bw",      			new WhoisServer(".bw",       				new CannotResolve()));
		    put(".bz",      			new WhoisServer(".bz",       				ResolveAfilias.getInstance()));
		    put(".co.ca",   			new WhoisServer(".co.ca",    				new ResolveDefault("whois.co.ca")));
		    put(".ca",      			new WhoisServer(".ca",       				new ResolveDefault("whois.cira.ca")));
		    put(".cc",      			new WhoisServer(".cc",       				new ResolveCRSNIC("whois.nic.cc")));
		    put(".cd",      			new WhoisServer(".cd",       				new ResolveDefault("whois.nic.cd")));
		    put(".cf",      			new WhoisServer(".cf",       				new CannotResolve()));
		    put(".cg",      			new WhoisServer(".cg",       				new ResolveURL("http://www.nic.cg/cgi-bin/whois.pl")));
		    put(".ch",      			new WhoisServer(".ch",       				new ResolveDefault("whois.nic.ch")));
		    put(".ci",      			new WhoisServer(".ci",       				new ResolveDefault("www.nic.ci")));
		    put(".ck",      			new WhoisServer(".ck",       				new ResolveDefault("whois.nic.ck")));
		    put(".cl",      			new WhoisServer(".cl",       				new ResolveDefault("whois.nic.cl")));
		    put(".cm",      			new WhoisServer(".cm",       				new CannotResolve()));
		    put(".edu.cn",  			new WhoisServer(".edu.cn",   				new ResolveDefault("whois.edu.cn")));
		    put(".cn",      			new WhoisServer(".cn",       				new ResolveDefault("whois.cnnic.net.cn")));
		    put(".uk.co",   			new WhoisServer(".uk.co",    				new ResolveDefault("whois.uk.co")));
		    put(".co",      			new WhoisServer(".co",       				new ResolveURL("https://www.nic.co/")));
		    put(".cr",      			new WhoisServer(".cr",       				new ResolveURL("http://www.nic.cr/niccr_publico/showRegistroDominiosScreen.do")));
		    put(".cu",      			new WhoisServer(".cu",       				new ResolveURL("http://www.nic.cu/consult.html")));
		    put(".cv",      			new WhoisServer(".cv",       				new CannotResolve()));
		    put(".cx",      			new WhoisServer(".cx",       				new ResolveDefault("whois.nic.cx")));
		    put(".cy",      			new WhoisServer(".cy",       				new ResolveURL("http://www.nic.cy/nslookup/online_database.php")));
		    put(".cz",      			new WhoisServer(".cz",       				new ResolveDefault("whois.nic.cz")));
		    put(".de",      			new WhoisServer(".de",       				new ResolveDefault("whois.denic.de")));
		    put(".dj",      			new WhoisServer(".dj",       				new ResolveDefault("whois.domain.dj")));
		    put(".dk",      			new WhoisServer(".dk",       				new ResolveDefault("whois.dk-hostmaster.dk")));
		    put(".dm",      			new WhoisServer(".dm",       				new ResolveDefault("whois.nic.dm")));
		    put(".do",      			new WhoisServer(".do",       				new ResolveURL("http://www.nic.do/whois-h.php3")));
		    put(".dz",      			new WhoisServer(".dz",       				new ResolveURL("https://www.nic.dz/")));
		    put(".ec",     		 		new WhoisServer(".ec",   				    new ResolveURL("http://www.nic.ec/whois/eng/whois.asp")));
		    put(".ee",      			new WhoisServer(".ee",   				    new ResolveDefault("whois.eenet.ee")));
		    put(".eg",      			new WhoisServer(".eg",    				   	new CannotResolve()));
		    put(".er",      			new WhoisServer(".er",    				   	new CannotResolve()));
		    put(".es",      			new WhoisServer(".es",   				    new ResolveURL("https://www.nic.es/")));
		    put(".et",      			new WhoisServer(".et",    				   	new CannotResolve()));
		    put(".eu",      			new WhoisServer(".eu",   				    new ResolveDefault("whois.eu")));
		    put(".fi",      			new WhoisServer(".fi",   				    new ResolveDefault("whois.ficora.fi")));
		    put(".fj",      			new WhoisServer(".fj",   				    new ResolveDefault("whois.usp.ac.fj")));
		    put(".fk",      			new WhoisServer(".fk",    				   	new CannotResolve()));
		    put(".fm",      			new WhoisServer(".fm",   				    new ResolveURL("http://www.dot.fm/whois.html")));
		    put(".fo",      			new WhoisServer(".fo",   				    new ResolveDefault("whois.ripe.net")));
		    put(".fr",      			new WhoisServer(".fr",   				    new ResolveDefault("whois.nic.fr")));
		    put(".ga",      			new WhoisServer(".ga",    				   	new CannotResolve()));
		    put(".gb",      			new WhoisServer(".gb",    				   	new CannotResolve()));
		    put(".gd",      			new WhoisServer(".gd",   					new ResolveDefault("whois.adamsnames.tc")));
		    put(".ge",      			new WhoisServer(".ge",   				    new ResolveURL("http://whois.sanet.ge/")));
		    put(".gf",      			new WhoisServer(".gf",   				    new ResolveDefault("whois.nplus.gf")));
		    put(".gg",      			new WhoisServer(".gg",   				    new ResolveDefault("whois.gg")));
		    put(".gh",      			new WhoisServer(".gh",   				    new ResolveURL("http://www.nic.gh/customer/search_c.htm")));
		    put(".gi",      			new WhoisServer(".gi",   				    ResolveAfilias.getInstance()));
		    put(".gl",      			new WhoisServer(".gl",    				   	new CannotResolve()));
		    put(".gm",      			new WhoisServer(".gm",   				    new ResolveDefault("whois.ripe.net")));
		    put(".gn",      			new WhoisServer(".gn",    				   	new CannotResolve()));
		    put(".gp",      			new WhoisServer(".gp",   				    new ResolveDefault("whois.nic.gp")));
		    put(".gq",      			new WhoisServer(".gq",       				new CannotResolve()));
		    put(".gr",      			new WhoisServer(".gr",   				    new ResolveURL("https://grweb.ics.forth.gr/Whois?lang=en")));
		    put(".gs",      			new WhoisServer(".gs",   				    new ResolveDefault("whois.nic.gs")));
		    put(".gt",      			new WhoisServer(".gt",   				    new ResolveURL("http://www.gt/whois.htm")));
		    put(".gu",      			new WhoisServer(".gu",   				    new ResolveURL("http://gadao.gov.gu/domainsearch.htm")));
		    put(".gw",      			new WhoisServer(".gw",       				new CannotResolve()));
		    put(".gy",      			new WhoisServer(".gy",   				    new ResolveDefault("whois.registry.gy")));
		    put(".hk",      			new WhoisServer(".hk",   				    new ResolveDefault("whois.hkdnr.net.hk")));
		    put(".hm",      			new WhoisServer(".hm",   				    new ResolveDefault("whois.registry.hm")));
		    put(".hn",      			new WhoisServer(".hn",   				    ResolveAfilias.getInstance()));
		    put(".hr",      			new WhoisServer(".hr",   				    new ResolveURL("http://www.dns.hr/pretrazivanje.html")));
		    put(".ht",      			new WhoisServer(".ht",   				    new ResolveDefault("whois.nic.ht")));
		    put(".hu",      			new WhoisServer(".hu",   				    new ResolveDefault("whois.nic.hu")));
		    put(".id",      			new WhoisServer(".id",   				    new ResolveDefault("whois.idnic.net.id")));
		    put(".ie",      			new WhoisServer(".ie",   				    new ResolveDefault("whois.domainregistry.ie")));
		    put(".il",      			new WhoisServer(".il",   				    new ResolveDefault("whois.isoc.org.il")));
		    put(".im",      			new WhoisServer(".im",   				    new ResolveDefault("whois.nic.im")));
		    put(".in",      			new WhoisServer(".in",   				    new ResolveDefault("whois.registry.in")));
		    put(".io",      			new WhoisServer(".io",   				    new ResolveDefault("whois.nic.io")));
		    put(".iq",      			new WhoisServer(".iq",       				new CannotResolve()));
		    put(".ir",      			new WhoisServer(".ir",   				    new ResolveDefault("whois.nic.ir")));
		    put(".is",      			new WhoisServer(".is",   				    new ResolveDefault("whois.isnet.is")));
		    put(".it",      			new WhoisServer(".it",   				    new ResolveDefault("whois.nic.it")));
		    put(".je",      			new WhoisServer(".je",   				    new ResolveDefault("whois.je")));
		    put(".jm",      			new WhoisServer(".jm",       				new CannotResolve()));
		    put(".jo",      			new WhoisServer(".jo",   				    new ResolveURL("http://www.dns.jo/Whois.aspx")));
		    put(".jp",      			new WhoisServer(".jp",   				    new ResolveDefault("whois.jprs.jp")));
		    put(".ke",      			new WhoisServer(".ke",   				    new ResolveDefault("whois.kenic.or.ke")));
		    put(".kg",      			new WhoisServer(".kg",   				    new ResolveDefault("whois.domain.kg")));
		    put(".kh",      			new WhoisServer(".kh",       				new CannotResolve()));
		    put(".ki",      			new WhoisServer(".ki",   				    new ResolveURL("http://www.ki/dns/")));
		    put(".km",      			new WhoisServer(".km",       				new CannotResolve()));
		    put(".kn",      			new WhoisServer(".kn",       				new CannotResolve()));
		    put(".kp",      			new WhoisServer(".kp",   				    new ResolveDefault("whois.kcce.kp")));
		    put(".kr",      			new WhoisServer(".kr",   				    new ResolveDefault("whois.nic.or.kr")));
		    put(".kw",      			new WhoisServer(".kw",   				    new ResolveURL("http://www.kw/")));
		    put(".ky",      			new WhoisServer(".ky",   				    new ResolveURL("http://kynseweb.messagesecure.com/kywebadmin/")));
		    put(".kz",      			new WhoisServer(".kz",   				    new ResolveDefault("whois.nic.kz")));
		    put(".la",      			new WhoisServer(".la",   				    new ResolveDefault("whois.nic.la")));
		    put(".lb",      			new WhoisServer(".lb",   				    new ResolveURL("http://www.aub.edu.lb/lbdr/search.html")));
		    put(".lc",      			new WhoisServer(".lc",   				    ResolveAfilias.getInstance()));
		    put(".li",      			new WhoisServer(".li",   				    new ResolveDefault("whois.nic.li")));
		    put(".lk",      			new WhoisServer(".lk",   				    new ResolveDefault("whois.nic.lk")));
		    put(".lr",      			new WhoisServer(".lr",       				new CannotResolve()));
		    put(".ls",      			new WhoisServer(".ls",   				    new ResolveURL("http://www.co.ls/data/leo2.asp")));
		    put(".lt",      			new WhoisServer(".lt",   				    new ResolveDefault("whois.domreg.lt")));
		    put(".lu",      			new WhoisServer(".lu",   				    new ResolveDefault("whois.dns.lu")));
		    put(".lv",      			new WhoisServer(".lv",   				    new ResolveDefault("whois.nic.lv")));
		    put(".ly",      			new WhoisServer(".ly",   				    new ResolveDefault("whois.nic.ly")));
		    put(".ma",      			new WhoisServer(".ma",   				    new ResolveDefault("whois.iam.net.ma")));
		    put(".mc",      			new WhoisServer(".mc",   				    new ResolveDefault("whois.ripe.net")));
		    put(".md",      			new WhoisServer(".md",   				    new ResolveURL("http://www.dns.md/wh1.php")));
		    put(".me",      			new WhoisServer(".me",   				    new ResolveDefault("whois.meregistry.net")));
		    put(".mg",      			new WhoisServer(".mg",   				    new ResolveDefault("whois.nic.mg")));
		    put(".mh",      			new WhoisServer(".mh",       				new CannotResolve()));
		    put(".mk",      			new WhoisServer(".mk",   				    new ResolveURL("http://dns.marnet.net.mk/registar.php")));
		    put(".ml",      			new WhoisServer(".ml",       				new CannotResolve()));
		    put(".mm",      			new WhoisServer(".mm",   				    new ResolveDefault("whois.nic.mm")));
		    put(".mn",      			new WhoisServer(".mn",   				    ResolveAfilias.getInstance()));
		    put(".mo",      			new WhoisServer(".mo",   				    new ResolveURL("http://www.monic.net.mo/")));
		    put(".mp",      			new WhoisServer(".mp",       				new CannotResolve()));
		    put(".mq",     				new WhoisServer(".mq",   				    new ResolveDefault("whois.nic.mq")));
		    put(".mr",      			new WhoisServer(".mr",       				new CannotResolve()));
		    put(".ms",      			new WhoisServer(".ms",   				    new ResolveDefault("whois.nic.ms")));
		    put(".mt",      			new WhoisServer(".mt",   				    new ResolveURL("https://www.nic.org.mt/dotmt/")));
		    put(".mu",      			new WhoisServer(".mu",   				    new ResolveDefault("whois.nic.mu")));
		    put(".mv",      			new WhoisServer(".mv",       				new CannotResolve()));
		    put(".mw",      			new WhoisServer(".mw",   				    new ResolveURL("http://www.registrar.mw/")));
		    put(".mx",      			new WhoisServer(".mx",   				    new ResolveDefault("whois.nic.mx")));
		    put(".my",      			new WhoisServer(".my",   				    new ResolveDefault("whois.mynic.net.my")));
		    put(".mz",      			new WhoisServer(".mz",       				new CannotResolve()));
		    put(".na",      			new WhoisServer(".na",   				    new ResolveDefault("whois.na-nic.com.na")));
		    put(".nc",      			new WhoisServer(".nc",   				    new ResolveDefault("whois.cctld.nc")));
		    put(".ne",      			new WhoisServer(".ne",       				new CannotResolve()));
		    put(".nf",      			new WhoisServer(".nf",   				    new ResolveDefault("whois.nic.nf")));
		    put(".ng",      			new WhoisServer(".ng",   				    new ResolveDefault("whois.register.net.ng")));
		    put(".ni",      			new WhoisServer(".ni",   				    new ResolveURL("http://www.nic.ni/consulta.htm")));
		    put(".nl",      			new WhoisServer(".nl",   				    new ResolveDefault("whois.domain-registry.nl")));
		    put(".no",      			new WhoisServer(".no",   				    new ResolveDefault("whois.norid.no")));
		    put(".np",      			new WhoisServer(".np",   				    new ResolveURL("http://www.mos.com.np/domsearch.html")));
		    put(".nr",      			new WhoisServer(".nr",   				    new ResolveURL("http://www.cenpac.net.nr/dns/whois.html")));
		    put(".nu",      			new WhoisServer(".nu",   				    new ResolveDefault("whois.nic.nu")));
		    put(".nz",      			new WhoisServer(".nz",   				    new ResolveDefault("whois.srs.net.nz")));
		    put(".om",      			new WhoisServer(".om",   				    new ResolveURL("http://www.omnic.om/onlineUser/WHOISLookup.jsp")));
		    put(".pa",      			new WhoisServer(".pa",   				    new ResolveURL("http://www.nic.pa/")));
		    put(".pe",      			new WhoisServer(".pe",   				    new ResolveDefault("whois.nic.pe")));
		    put(".pf",      			new WhoisServer(".pf",       				new CannotResolve()));
		    put(".pg",      			new WhoisServer(".pg",       				new CannotResolve()));
		    put(".ph",      			new WhoisServer(".ph",   				    new ResolveURL("http://www.dot.ph/")));
		    put(".pk",      			new WhoisServer(".pk",   				    new ResolveURL("http://www.pknic.net.pk/")));
		    put(".co.pl",   			new WhoisServer(".co.pl",      				new ResolveDefault("whois.co.pl")));
		    put(".pl",      			new WhoisServer(".pl",   				    new ResolveDefault("whois.dns.pl")));
		    put(".pm",      			new WhoisServer(".pm",   				    new ResolveDefault("whois.nic.fr")));
		    put(".pn",      			new WhoisServer(".pn",   				    new ResolveURL("http://www.pitcairn.pn/PnRegistry/")));
		    put(".pr",      			new WhoisServer(".pr",   				    new ResolveDefault("whois.nic.pr")));
		    put(".ps",      			new WhoisServer(".ps",   				    new ResolveURL("http://www.nic.ps/whois/whois.html")));
		    put(".pt",      			new WhoisServer(".pt",   				    new ResolveDefault("whois.dns.pt")));
		    put(".pw",      			new WhoisServer(".pw",   				    new ResolveDefault("whois.nic.pw")));
		    put(".py",      			new WhoisServer(".py",   				    new ResolveURL("http://www.nic.py/consultas.html")));
		    put(".qa",      			new WhoisServer(".qa",       				new CannotResolve()));
		    put(".re",      			new WhoisServer(".re",   				    new ResolveDefault("whois.nic.fr")));
		    put(".ro",      			new WhoisServer(".ro",   				    new ResolveDefault("whois.rotld.ro")));
		    put(".rs",      			new WhoisServer(".rs",   				    new ResolveURL("http://www.nic.rs/en/whois")));
		    put(".edu.ru",  			new WhoisServer(".edu.ru",   				new ResolveDefault("whois.informika.ru")));
		    put(".ru",      			new WhoisServer(".ru",   				    new ResolveDefault("whois.ripn.net")));
		    put(".rw",      			new WhoisServer(".rw",   				    new ResolveURL("http://www.nic.rw/cgi-bin/whoisrw.pl")));
		    put(".sa",      			new WhoisServer(".sa",   				    new ResolveDefault("saudinic.net.sa")));
		    put(".sb",      			new WhoisServer(".sb",   				    new ResolveDefault("whois.nic.net.sb")));
		    put(".sc",      			new WhoisServer(".sc",   				    ResolveAfilias.getInstance()));
		    put(".sd",      			new WhoisServer(".sd",       				new CannotResolve()));
		    put(".se",      			new WhoisServer(".se",   				    new ResolveDefault("whois.nic-se.se")));
		    put(".sg",      			new WhoisServer(".sg",   				    new ResolveDefault("whois.nic.net.sg")));
		    put(".sh",      			new WhoisServer(".sh",   				    new ResolveDefault("whois.nic.sh")));
		    put(".si",      			new WhoisServer(".si",   				    new ResolveDefault("whois.arnes.si")));
		    put(".sj",      			new WhoisServer(".sj",       				new CannotResolve()));
		    put(".sk",      			new WhoisServer(".sk",   				    new ResolveDefault("whois.sk-nic.sk")));
		    put(".sl",      			new WhoisServer(".sl",   				    new ResolveDefault("whois.nic.sl")));
		    put(".sm",      			new WhoisServer(".sm",   				    new ResolveDefault("whois.ripe.net")));
		    put(".sn",      			new WhoisServer(".sn",   				    new ResolveDefault("whois.nic.sn")));
		    put(".so",      			new WhoisServer(".so",       				new CannotResolve()));
		    put(".sr",      			new WhoisServer(".sr",   				    new ResolveDefault("whois.register.sr")));
		    put(".st",      			new WhoisServer(".st",   				    new ResolveDefault("whois.nic.st")));
		    put(".su",      			new WhoisServer(".su",   				    new ResolveDefault("whois.ripn.net")));
		    put(".sv",      			new WhoisServer(".sv",   				    new ResolveURL("http://www.uca.edu.sv/dns/")));
		    put(".sy",      			new WhoisServer(".sy",       				new CannotResolve()));
		    put(".sz",      			new WhoisServer(".sz",       				new CannotResolve()));
		    put(".tc",      			new WhoisServer(".tc",   				    new ResolveDefault("whois.adamsnames.tc")));
		    put(".td",      			new WhoisServer(".td",       				new CannotResolve()));
		    put(".tf",      			new WhoisServer(".tf",   				    new ResolveDefault("whois.nic.tf")));
		    put(".tg",      			new WhoisServer(".tg",   				    new ResolveURL("http://www.nic.tg/")));
		    put(".th",      			new WhoisServer(".th",   				    new ResolveDefault("whois.thnic.net")));
		    put(".tj",      			new WhoisServer(".tj",   				    new ResolveDefault("whois.nic.tj")));
		    put(".tk",      			new WhoisServer(".tk",   				    new ResolveDefault("whois.dot.tk")));
		    put(".tl",      			new WhoisServer(".tl",   				    new ResolveDefault("whois.nic.tl")));
		    put(".tm",      			new WhoisServer(".tm",   				    new ResolveDefault("whois.nic.tm")));
		    put(".tn",      			new WhoisServer(".tn",   				    new ResolveURL("http://whois.ati.tn/")));
		    put(".to",      			new WhoisServer(".to",   				    new ResolveDefault("whois.tonic.to")));
		    put(".tp",      			new WhoisServer(".tp",   				    new ResolveDefault("whois.nic.tp")));
		    put(".tr",      			new WhoisServer(".tr",   				    new ResolveDefault("whois.metu.edu.tr")));
		    put(".tt",      			new WhoisServer(".tt",   				    new ResolveURL("http://www.nic.tt/cgi-bin/search.pl")));
		    put(".tv",      			new WhoisServer(".tv",   				    new ResolveCRSNIC("whois.nic.tv")));
		    put(".tw",      			new WhoisServer(".tw",   				    new ResolveDefault("whois.twnic.net")));
		    put(".tz",      			new WhoisServer(".tz",   				    new ResolveURL("http://whois.tznic.or.tz/")));
		    put(".ua",      			new WhoisServer(".ua",   				    new ResolveDefault("whois.net.ua")));
		    put(".ug",     				new WhoisServer(".ug",   				    new ResolveDefault("www.registry.co.ug")));
		    put(".ac.uk",   			new WhoisServer(".ac.uk",    				new ResolveDefault("whois.ja.net")));
		    put(".bl.uk",   			new WhoisServer(".bl.uk",    				new CannotResolve()));
		    put(".british-library.uk",	new WhoisServer(".british-library.uk",		new CannotResolve()));
		    put(".gov.uk",  			new WhoisServer(".gov.uk",   				new ResolveDefault("whois.ja.net")));
		    put(".icnet.uk",        	new WhoisServer(".icnet.uk",				new CannotResolve()));
		    put(".jet.uk",  			new WhoisServer(".jet.uk",   				new CannotResolve()));
		    put(".mod.uk",  			new WhoisServer(".mod.uk",   				new CannotResolve()));
		    put(".nhs.uk",  			new WhoisServer(".nhs.uk",   				new CannotResolve()));
		    put(".nls.uk",  			new WhoisServer(".nls.uk",   				new CannotResolve()));
		    put(".parliament.uk",   	new WhoisServer(".parliament.uk",			new CannotResolve()));
		    put(".police.uk",       	new WhoisServer(".police.uk",				new CannotResolve()));
		    put(".uk",      			new WhoisServer(".uk",       				new ResolveDefault("whois.nic.uk")));
		    put(".fed.us",  			new WhoisServer(".fed.us",   				new ResolveDefault("whois.nic.gov")));
		    put(".us",      			new WhoisServer(".us",       				new ResolveDefault("whois.nic.us")));
		    put(".com.uy",  			new WhoisServer(".com.uy",   				new ResolveURL("https://nic.anteldata.com.uy/dns/")));
		    put(".uy",      			new WhoisServer(".uy",       				new ResolveDefault("whois.nic.org.uy")));
		    put(".uz",      			new WhoisServer(".uz",       				new ResolveDefault("whois.cctld.uz")));
		    put(".va",      			new WhoisServer(".va",       				new ResolveDefault("whois.ripe.net")));
		    put(".vc",      			new WhoisServer(".vc",       				ResolveAfilias.getInstance()));
		    put(".ve",      			new WhoisServer(".ve",       				new ResolveDefault("whois.nic.ve")));
		    put(".vg",      			new WhoisServer(".vg",       				new ResolveDefault("whois.adamsnames.tc")));
		    put(".vi",      			new WhoisServer(".vi",       				new ResolveURL("http://www.nic.vi/whoisform.htm")));
		    put(".vn",      			new WhoisServer(".vn",       				new ResolveURL("http://www.vnnic.vn/english/")));
		    put(".vu",      			new WhoisServer(".vu",       				new ResolveURL("http://www.vunic.vu/whois.html")));
		    put(".wf",      			new WhoisServer(".wf",      				new ResolveDefault("whois.nic.wf")));
		    put(".ws",      			new WhoisServer(".ws",       				new ResolveDefault("whois.samoanic.ws")));
		    put(".ye",      			new WhoisServer(".ye",       				new CannotResolve()));
		    put(".yt",      			new WhoisServer(".yt",       				new ResolveDefault("whois.nic.yt")));
		    put(".yu",      			new WhoisServer(".yu",       				new CannotResolve()));
		    put(".ac.za",   			new WhoisServer(".ac.za",    				new ResolveDefault("whois.ac.za")));
		    put(".co.za",   			new WhoisServer(".co.za",    				new ResolveDefault("whois.coza.net.za")));
		    put(".gov.za",  			new WhoisServer(".gov.za",   				new ResolveDefault("whois.gov.za")));
		    put(".org.za",  			new WhoisServer(".org.za",   				new ResolveURL("http://www.org.za/")));
		    put(".za",      			new WhoisServer(".za",       				new CannotResolve()));
		    put(".zm",      			new WhoisServer(".zm",       				new CannotResolve()));
		    put(".zw",      			new WhoisServer(".zw",       				new CannotResolve()));
		    put("-dom",     			new WhoisServer("-dom",      				new ResolveDefault("whois.networksolutions.com")));
		    put("-org",     			new WhoisServer("-org",      				new ResolveDefault("whois.networksolutions.com")));
		    put("-hst",     			new WhoisServer("-hst",      				new ResolveDefault("whois.networksolutions.com")));
		    put("-arin",    			new WhoisServer("-arin",     				new ResolveDefault("whois.arin.net")));
		    put("-ripe",    			new WhoisServer("-ripe",     				new ResolveDefault("whois.ripe.net")));
		    put("-mnt",     			new WhoisServer("-mnt",      				new ResolveDefault("whois.ripe.net")));
		    put("-lacnic",  			new WhoisServer("-lacnic",   				new ResolveDefault("whois.lacnic.net")));
		    put("-afrinic", 			new WhoisServer("-afrinic",  				new ResolveDefault("whois.afrinic.net")));
		    put("-ap",      			new WhoisServer("-ap",       				new ResolveDefault("whois.apnic.net")));
		    put("-ar",      			new WhoisServer("-ar",       				new ResolveDefault("whois.aunic.net")));
		    put("-cn",      			new WhoisServer("-cn",       				new ResolveDefault("whois.cnnic.net.cn")));
		    put("-cz",      			new WhoisServer("-cz",       				new ResolveDefault("whois.nic.cz")));
		    put("-dk",      			new WhoisServer("-dk",       				new ResolveDefault("whois.dk-hostmaster.dk")));
		    put("-il",      			new WhoisServer("-il",       				new ResolveDefault("whois.isoc.org.il")));
		    put("-is",      			new WhoisServer("-is",       				new ResolveDefault("whois.isnet.is")));
		    put("-kg",      			new WhoisServer("-kg",       				new ResolveDefault("whois.domain.kg")));
		    put("-ti",      			new WhoisServer("-ti",       				new ResolveDefault("whois.telstra.net")));
		    put("-tw",      			new WhoisServer("-tw",       				new ResolveDefault("whois.twnic.net")));
		    put("-6bone",   			new WhoisServer("-6bone",      				new ResolveDefault("whois.6bone.net")));
		    put("-coop",    			new WhoisServer("-coop",     				new ResolveDefault("whois.nic.coop")));
		    put("-cknic",   			new WhoisServer("-cknic",      				new ResolveDefault("whois.nic.ck")));
		    put("-idnic",   			new WhoisServer("-idnic",      				new ResolveDefault("whois.idnic.net.id")));
		    put("-itnic",   			new WhoisServer("-itnic",      				new ResolveDefault("whois.nic.it")));
		    put("-frnic",   			new WhoisServer("-frnic",      				new ResolveDefault("whois.nic.fr")));
		    put("-gandi",   			new WhoisServer("-gandi",      				new ResolveDefault("whois.gandi.net")));
		    put("-kenic",   			new WhoisServer("-kenic",      				new ResolveDefault("whois.kenic.or.ke")));
		    put("-lrms",    			new WhoisServer("-lrms",     				new ResolveDefault("whois.afilias.info")));
		    put("-metu",    			new WhoisServer("-metu",     				new ResolveDefault("whois.metu.edu.tr")));
		    put("-nicat",   			new WhoisServer("-nicat",      				new ResolveDefault("whois.nic.at")));
		    put("-nicir",   			new WhoisServer("-nicir",      				new ResolveDefault("whois.nic.ir")));
		    put("-norid",   			new WhoisServer("-norid",      				new ResolveDefault("whois.norid.no")));
		    put("-ripn",    			new WhoisServer("-ripn",     				new ResolveDefault("whois.ripn.net")));
		    put("-rotld",   			new WhoisServer("-rotld",      				new ResolveDefault("whois.rotld.ro")));
		    put("-sgnic",   			new WhoisServer("-sgnic",      				new ResolveDefault("whois.nic.net.sg")));
		    put("-tel",     			new WhoisServer("-tel",      				new ResolveDefault("whois.nic.tel")));
		    put("-uanic",   			new WhoisServer("-uanic",      				new ResolveDefault("whois.com.ua")));
		    put("-uynic",  				new WhoisServer("-uynic",      				new ResolveDefault("www.rau.edu.uy")));
		    put("-sixxs",   			new WhoisServer("-sixxs",      				new ResolveDefault("whois.sixxs.net")));
		}
	};
	
	/**
	 * Get a list of supported TLDs. The result set contains dots and hyphens for the appropriate suffixes. e.g. '.eu.org' or '-sixxs'.
	 * @return Gets a set of supported top level domains.
	 */
	public static Set<String> getSupportedTLDSet()
	{
		return new HashSet<String>(servers.keySet());
	}
	
	/**
	 * Extract the TLD from the given name.
	 * @param name A domain name.
	 * @return The co-responding top level domain name.
	 */
	public static String getTLD(String name) {
		String longest = null;
		for(String tld : servers.keySet()) {
			if (name.endsWith(tld)) {
				if (longest == null || tld.length() > longest.length()) {
					longest = tld;
				}
			}
		}
		return longest;
	}
	
	/**
	 * Get the {@link WhoisServer} for the given name.
	 * @param name A domain name.
	 * @return An initalised WhoisServer instance that can query the given name.
	 */
	public static WhoisServer getServer(String name) {
		return servers.get(getTLD(name));
	}

	/**
	 * Query the given domain name. Calls {@link WhoisServer#query(String)}.
	 * @param name A domain name.
	 * @return A {@link WhoisResponse] instance for this query.
	 * @throws UnknownHostException
	 * @throws IOException
	 */
	public static WhoisResponse query(String name) throws UnknownHostException, IOException {
		return getServer(name).query(name);
	}
}
