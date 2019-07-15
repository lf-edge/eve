// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedpac

import "testing"

type case_table struct {
	url    string
	host   string
	expect string
}

func TestPac(t *testing.T) {
	pacs := []struct {
		pac   string
		tests []case_table
	}{
		// pac0
		{`function FindProxyForURL(url, host) {

// If the hostname matches, send direct.
    if (dnsDomainIs(host, ".intranet.domain.com") ||
        shExpMatch(host, "(*.abcdomain.com|abcdomain.com)"))
        return "DIRECT";

// If the protocol or URL matches, send direct.
    if (url.substring(0, 4)=="ftp:" ||
        shExpMatch(url, "http://abcdomain.com/folder/*"))
        return "DIRECT";

// If the requested website is hosted within the internal network, send direct.
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0",  "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0",  "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.255.255.0"))
        return "DIRECT";

// If the IP address of the local machine is within a defined
// subnet, send to a specific proxy.
    if (isInNet(myIpAddress(), "10.10.5.0", "255.255.255.0"))
        return "PROXY 1.2.3.4:8080";

// DEFAULT RULE: All other traffic, use below proxies, in fail-over order.
    return "PROXY 4.5.6.7:8080; PROXY 7.8.9.10:8080";

}`,
			[]case_table{
				{url: "http://abcdomain.com", host: "abcdomain.com", expect: "DIRECT"},
				{url: "ftp://mydomain.com/x/", host: "mydomain.com", expect: "DIRECT"},
				{"http://a.local/x/", "a.local", "DIRECT"},
				{"http://10.1.2.3/", "10.1.2.3", "DIRECT"},
				{"http://172.16.1.2/x/", "172.16.1.2", "DIRECT"},
				{"http://192.168.1.2/x/", "192.168.1.2", "DIRECT"},
				{"http://127.0.0.5/x/", "127.0.0.5", "DIRECT"},
				{"http://google.com/x", "google.com", "PROXY 4.5.6.7:8080; PROXY 7.8.9.10:8080"},
			},
		},

		// pac1
		{`// This PAC file is from http://cns.ntou.edu.tw/lib.pac.

function FindProxyForURL(url, host) {
var RESOLV_IP;
var lchost = host.toLowerCase();
if(check(host,"*.*.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"*.ebsco-content.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"129.35.213.31",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"129.35.248.48",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"134.243.85.3",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"134.243.85.4",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"140.121.140.100",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"140.121.140.102",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"140.121.140.103",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"140.121.180.109",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"156.csis.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"165.193.122.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"165.193.141.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"167.216.170.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"167.216.171.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"170.225.184.106",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"170.225.184.107",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"170.225.96.21",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"170.225.99.9",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"192.83.186.103",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"192.83.186.70",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"192.83.186.71",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"192.83.186.72",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"192.83.186.84",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"199.4.154.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"199.4.155.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"202.70.173.2",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"203.70.208.88",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"203.74.36.75",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"205.240.244.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"205.240.245.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"205.240.246.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"205.240.247.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"205.243.231.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"210.243.166.93",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"211.20.182.42",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"211.79.206.2",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"211.79.206.4",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"211.79.506.4",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"220.228.59.156",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"63.240.105.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"63.240.113.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"63.84.162.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"63.86.118.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"63.86.119.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"65.246.184.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"65.246.185.",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"aac.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ac.els-cdn.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"admin-apps.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"admin-router.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"admin.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"aem.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"afraf.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ageing.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"aje.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"alcalc.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"aler.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"annhyg.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"annonc.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"antonio.ingentaselect.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ao.osa.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"aob.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"aoip.osa.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"aolp.osa.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"aoot.osa.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ap.ejournal.ascc.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"apl.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"apollo.sinica.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"apps.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"apps.webofknowledgev4.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"arjournals.annualreviews.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ascelibrary.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"atoz.ebsco.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"beck-online.beck.de",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"beheco.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"bencao.infolinker.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"big5.oversea.cnki.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"bioinformatics.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"biostatistics.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"bizboard.nikkeibp.co.jp",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"bizboard.nikkeibp.co.jp/daigaku",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"bja.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"bjc.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"bjsw.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"bmb.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"bmf.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"brain.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"brief-treatment.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"carcin.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cco.cambridge.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cdj.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cdli.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cds1.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cds2.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cec.lib.apabi.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cep.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cercor.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"chaos.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"charts.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"chemse.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ci.nii.ac.jp",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cje.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cjn.csis.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"clipsy.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cm.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cm.webofknowledgev4.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cmr.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cnki.csis.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cnki50.csis.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"collections.chadwyck.co.uk",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"concert.wisenews.net.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"content.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cornell.mirror.aps.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"cpe.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"csa.e-lib.nctu.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ct.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"database.yomiuri.co.jp",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"db.lib.ntou.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"deafed.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"delivery.acm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"demomars.csis.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"diipcs.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"dlib.apabi.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"download.springer.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ea.grolier.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"earthinteractions.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ebook01.koobe.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ebooks.abc-clio.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ebooks.kluweronline.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ebooks.springerlink.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ebooks.windeal.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ec.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"edo.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"edo.tw/ocp.aspx?subs_no=20063",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"eds.a.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"eds.b.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"eds.c.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"eds.d.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"eds.e.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"edu1.wordpedia.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"eebo.chadwyck.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ei.e-lib.nctu.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ei.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ei.stic.gov.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ej.iop.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"elearning.webenglish.tv",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"elib.infolinker.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"emboj.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"engineer.windeal.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"enterprise.astm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"epirev.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"epubs.siam.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"erae.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"eric.lib.nccu.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"es.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"esi.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"esr.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"estipub.isiknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ethesys.lib.ntou.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"fampra.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"g.wanfangdata.com.hk",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"galenet.galegroup.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"gateway.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"german2.nccu.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"global.ebsco-content.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"global.umi.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"globalbb.onesource.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"glycob.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"gme.grolier.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"go-passport.grolier.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"go.galegroup.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"go.grolier.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"go.westlawjapan.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"haworthpress.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"hbrtwn.infolinker.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"hcr.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"hcr3.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"heapol.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"heapro.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"her.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"hjournals.cambridge.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"hk.wanfangdata.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"hmg.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"http://infotrac.galegroup.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"humrep.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"hunteq.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"huso.stpi.narl.org.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"huso.stpi.org.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"hyweb.ebook.hyread.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"iai.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"icc.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ieee.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"igroup.ebrary.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ije.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ijpor.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ilibrary.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"imagebank.osa.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"images.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"infotrac.galegroup.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"infoweb.newsbank.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"international.westlaw.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"intimm.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"intqhc.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"iopscience.iop.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"iospress.metapress.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"irap.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"isi4.isiknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"isiknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jac.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jae.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jap.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jb.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jcm.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jcp.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jcr1.isiknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jeg.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jhered.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jjco.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jleo.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jlt.osa.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jmicro.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jmp.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jn.physiology.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jncicancerspectrum.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"joc.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"josaa.osa.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jot.osa.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"journals.ametsoc.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"journals.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"journals.cambridge.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"journals.kluweronline.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"journals.wspc.com.sg",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jpart.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jpcrd.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jpepsy.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jrse.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jurban.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jvi.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"jxb.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"klassiker.chadwyck.co.uk",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"kmw.ctgin.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"lang.ntou.edu.tw/source.php",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"lb20.ah100.libraryandbook.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"lb20.botw.libraryandbook.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"lb20.dummies.libraryandbook.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"lb20.tabf.libraryandbook.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"legal.lexisnexis.jp",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"lib.myilibrary.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"library.books24x7.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"library.pressdisplay.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"link.aps.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"link.springer-ny.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"link.springer.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"link.springer.de",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"links.springer.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"links.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ltp.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"mars.csa.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"mars.csis.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"mars2.csa.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"mars3.csa.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"mbe.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"mcb.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"md1.csa.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"md2.csa.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"minghouse.infolinker.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"mmbr.asm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"molehr.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"mollus.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"mutage.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"mydigitallibrary.lib.overdrive.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"nar.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ncl3web.hyweb.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ndt.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"new.cwk.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"newfirstsearch.global.oclc.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"newfirstsearch.oclc.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ntou.ebook.hyread.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ntou.koobe.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ntt1.hyweb.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"occmed.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"oep.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"oh1.csa.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"oh2.csa.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ojps.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ol.osa.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"oldweb.cqvip.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"omed.nuazure.info",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"online.sagepub.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"onlinelibrary.wiley.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ortho.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"oversea.cnki.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ovid.stic.gov.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ovidsp.ovid.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"oxfordjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"oxrep.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pa.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pan.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pao.chadwyck.co.uk",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pcp.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pcs.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pcs.webofknowledgev4com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pdn.sciencedirect.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"petrology.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"phr.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"physics.aps.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"physiolgenomics.physiology.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"plankt.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pm.nlx.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pm.nlx.com/xtf/search?browse-collections=true",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pof.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pop.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"portal.acm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"portal.isiknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pqdd.sinica.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pra.aps.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"prb.aps.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"prc.aps.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"prd.aps.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pre.aps.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"prl.aps.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pro-twfubao.infolinker.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"prola.aps.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"prola.library.cornell.edu",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"proquest.umi.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"proquest.uni.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"protein.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ptr.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pubmed.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pubs.acs.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pubs.rsc.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"pubs3.acs.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"qjmed.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"reading.udn.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"readopac.ncl.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"readopac2.ncl.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"readopac3.ncl.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"reference.kluweronline.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"refworks.reference-global.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"rfs.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"rheumatology.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"rmp.aps.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"rsi.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"rss.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"schiller.chadwyck.co.uk",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"sciencenow.sciencemag.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"scifinder.cas.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"scitation.aip.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"sdos.ejournal.ascc.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"search.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"search.epnet.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"search.isiknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"search.proquest.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"search.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ser.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"service.csa.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"service.flysheet.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"service.refworks.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"shmu.alexanderstreet.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"site.ebrary.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"soth.alexanderstreet.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"sp.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"springerlink.metapress.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ssjj.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"stfb.ntl.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"stfj.ntl.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"sub3.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"survival.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"sushi.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"swproxy.swetswise.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"taebc.ebook.hyread.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"taebc.etailer.dpsl.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"taebc.koobe.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"taebcmgh.sa.libraryandbook.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"tandf.msgfocus.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"tao.wordpedia.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"tbmcdb.infolinker.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"tcsd.lib.ntu.edu.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"tebko.infolinker.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"tie.tier.org.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"toc.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"toc.webofknowledgev4.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"tongji.oversea.cnki.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"toxsci.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"turs.infolinker.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"tw.magv.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"twu-ind.wisenews.net.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"udndata.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"udndata.com/library/fullpage",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ulej.stic.gov.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"vnweb.hwwilsonweb.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"wber.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"wbro.oupjournals.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"wcs.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"web.a.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"web.b.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"web.c.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"web.d.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"web.e.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"web.ebscohost.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"web.lexis-nexis.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"web17.epnet.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"webofknowledge.com&nbsp;",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"wok-ws.isiknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"wos.stic.gov.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"ws.isiknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.acm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.agu.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.airitiaci.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.airitiaci.com/",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.airitibooks.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.airitilibrary.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.airitinature.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.annualreviews.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.apabi.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.apabi.com/cec",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.ascelibrary.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.asme.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.astm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.atozmapsonline.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.atoztheworld.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.atozworldbusiness.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.atozworldculture.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.atozworldtrade.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.atozworldtravel.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.biolbull.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.bioone.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.blackwell-synergy.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.brepolis.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.bridgemaneducation.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.bssaonline.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.cairn.info",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.ceps.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.chinamaxx.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.classiques-garnier.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.cnsonline.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.cnsppa.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.crcnetbase.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.credoreference.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.csa.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.csa.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.dalloz.fr",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.dialogselect.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.discoverygate.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.duxiu.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.ebookstore.tandf.co.uk",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.ebsco.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.educationarena.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.ei.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.els.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.elsevier.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.emeraldinsight.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.engineeringvillage.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.engineeringvillage2.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.europaworld.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.europe.idealibrary.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.frantext.fr",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.genome.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.genomebiology.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.greeninfoonline.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.hepseu.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.icevirtuallibrary.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.idealibrary.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.igpublish.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.informaworld.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.ingenta.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.int-res.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.iop.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.iospress.nl",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.isihighlycited.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.jkn21.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.jstor.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.juris.de",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.kluwerlawonline.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.kluweronline.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.knovel.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.lawbank.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.lawdata.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.lexisnexis.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.lexisnexis.com/ap/academic",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.lexisnexis.com/ap/auth",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.lextenso.fr",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.mergentonline.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.mrw.interscience.wiley.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.munzinger.de",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.myendnoteweb.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.myilibrary.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.nature.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.netlibrary.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.nonlin-processes-geophys.net",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.nutrition.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.onesource.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.opticsexpress.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.osa-jon.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.osa-opn.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.oxfordreference.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.oxfordscholarship.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.palgrave-journals.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.palgraveconnect.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.proteinscience.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.read.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.reaxys.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.refworks.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.refworks.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.researcherid.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.rsc.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.sage-ereference.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.sciencedirect.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.sciencemag.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.scopus.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.springerlink.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.swetsnet.nl",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.swetswise.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.taebcnetbase.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.tandf.co.uk",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.tandfonline.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.tbmc.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.TeacherReference.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.tlemea.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.tls.psmedia.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.tumblebooks.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.tw-elsevier.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.universalis-edu.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.wanfangdata.com.hk",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.webofknowledge.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.webofknowledgev4.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.westlaw.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www.wkap.nl",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www2.astm.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www2.read.com.tw",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www3.electrochem.org",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www3.interscience.wiley.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"www3.oup.co.uk",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"wwwlib.global.umi.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
if(check(host,"yagi.jkn21.com",false,true))
        return "PROXY proxylib.ntou.edu.tw:3128";
return	"DIRECT";
}
function check(target,term,caseSens,wordOnly) {
if (!caseSens) {
term = term.toLowerCase();
target = target.toLowerCase();
}
if(target.indexOf(term) >= 0) {
return true;
}
return false;
}`,
			[]case_table{
				{"http://*.*.ebscohost.com/x", "*.*.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://*.ebsco-content.com/x", "*.ebsco-content.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://129.35.213.31/x", "129.35.213.31", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://129.35.248.48/x", "129.35.248.48", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://134.243.85.3/x", "134.243.85.3", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://134.243.85.4/x", "134.243.85.4", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://140.121.140.100/x", "140.121.140.100", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://140.121.140.102/x", "140.121.140.102", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://140.121.140.103/x", "140.121.140.103", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://140.121.180.109/x", "140.121.180.109", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://156.csis.com.tw/x", "156.csis.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://165.193.122./x", "165.193.122.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://165.193.141./x", "165.193.141.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://167.216.170./x", "167.216.170.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://167.216.171./x", "167.216.171.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://170.225.184.106/x", "170.225.184.106", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://170.225.184.107/x", "170.225.184.107", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://170.225.96.21/x", "170.225.96.21", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://170.225.99.9/x", "170.225.99.9", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://192.83.186.103/x", "192.83.186.103", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://192.83.186.70/x", "192.83.186.70", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://192.83.186.71/x", "192.83.186.71", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://192.83.186.72/x", "192.83.186.72", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://192.83.186.84/x", "192.83.186.84", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://199.4.154./x", "199.4.154.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://199.4.155./x", "199.4.155.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://202.70.173.2/x", "202.70.173.2", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://203.70.208.88/x", "203.70.208.88", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://203.74.36.75/x", "203.74.36.75", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://205.240.244./x", "205.240.244.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://205.240.245./x", "205.240.245.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://205.240.246./x", "205.240.246.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://205.240.247./x", "205.240.247.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://205.243.231./x", "205.243.231.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://210.243.166.93/x", "210.243.166.93", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://211.20.182.42/x", "211.20.182.42", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://211.79.206.2/x", "211.79.206.2", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://211.79.206.4/x", "211.79.206.4", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://211.79.506.4/x", "211.79.506.4", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://220.228.59.156/x", "220.228.59.156", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://63.240.105./x", "63.240.105.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://63.240.113./x", "63.240.113.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://63.84.162./x", "63.84.162.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://63.86.118./x", "63.86.118.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://63.86.119./x", "63.86.119.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://65.246.184./x", "65.246.184.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://65.246.185./x", "65.246.185.", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://aac.asm.org/x", "aac.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ac.els-cdn.com/x", "ac.els-cdn.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://admin-apps.webofknowledge.com/x", "admin-apps.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://admin-router.webofknowledge.com/x", "admin-router.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://admin.webofknowledge.com/x", "admin.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://aem.asm.org/x", "aem.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://afraf.oupjournals.org/x", "afraf.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ageing.oupjournals.org/x", "ageing.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://aje.oupjournals.org/x", "aje.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://alcalc.oupjournals.org/x", "alcalc.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://aler.oupjournals.org/x", "aler.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://annhyg.oupjournals.org/x", "annhyg.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://annonc.oupjournals.org/x", "annonc.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://antonio.ingentaselect.com/x", "antonio.ingentaselect.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ao.osa.org/x", "ao.osa.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://aob.oupjournals.org/x", "aob.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://aoip.osa.org/x", "aoip.osa.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://aolp.osa.org/x", "aolp.osa.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://aoot.osa.org/x", "aoot.osa.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ap.ejournal.ascc.net/x", "ap.ejournal.ascc.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://apl.aip.org/x", "apl.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://apollo.sinica.edu.tw/x", "apollo.sinica.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://apps.webofknowledge.com/x", "apps.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://apps.webofknowledgev4.com/x", "apps.webofknowledgev4.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://arjournals.annualreviews.org/x", "arjournals.annualreviews.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ascelibrary.aip.org/x", "ascelibrary.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://atoz.ebsco.com/x", "atoz.ebsco.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://beck-online.beck.de/x", "beck-online.beck.de", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://beheco.oupjournals.org/x", "beheco.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://bencao.infolinker.com.tw/x", "bencao.infolinker.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://big5.oversea.cnki.net/x", "big5.oversea.cnki.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://bioinformatics.oupjournals.org/x", "bioinformatics.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://biostatistics.oupjournals.org/x", "biostatistics.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://bizboard.nikkeibp.co.jp/x", "bizboard.nikkeibp.co.jp", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://bizboard.nikkeibp.co.jp/daigaku/x", "bizboard.nikkeibp.co.jp/daigaku", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://bja.oupjournals.org/x", "bja.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://bjc.oupjournals.org/x", "bjc.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://bjsw.oupjournals.org/x", "bjsw.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://bmb.oupjournals.org/x", "bmb.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://bmf.aip.org/x", "bmf.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://brain.oupjournals.org/x", "brain.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://brief-treatment.oupjournals.org/x", "brief-treatment.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://carcin.oupjournals.org/x", "carcin.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cco.cambridge.org/x", "cco.cambridge.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cdj.oupjournals.org/x", "cdj.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cdli.asm.org/x", "cdli.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cds1.webofknowledge.com/x", "cds1.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cds2.webofknowledge.com/x", "cds2.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cec.lib.apabi.com/x", "cec.lib.apabi.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cep.oupjournals.org/x", "cep.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cercor.oupjournals.org/x", "cercor.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://chaos.aip.org/x", "chaos.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://charts.webofknowledge.com/x", "charts.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://chemse.oupjournals.org/x", "chemse.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ci.nii.ac.jp/x", "ci.nii.ac.jp", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cje.oupjournals.org/x", "cje.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cjn.csis.com.tw/x", "cjn.csis.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://clipsy.oupjournals.org/x", "clipsy.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cm.webofknowledge.com/x", "cm.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cm.webofknowledgev4.com/x", "cm.webofknowledgev4.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cmr.asm.org/x", "cmr.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cnki.csis.com.tw/x", "cnki.csis.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cnki50.csis.com.tw/x", "cnki50.csis.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://collections.chadwyck.co.uk/x", "collections.chadwyck.co.uk", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://concert.wisenews.net.tw/x", "concert.wisenews.net.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://content.ebscohost.com/x", "content.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cornell.mirror.aps.org/x", "cornell.mirror.aps.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://cpe.oupjournals.org/x", "cpe.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://csa.e-lib.nctu.edu.tw/x", "csa.e-lib.nctu.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ct.oupjournals.org/x", "ct.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://database.yomiuri.co.jp/x", "database.yomiuri.co.jp", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://db.lib.ntou.edu.tw/x", "db.lib.ntou.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://deafed.oupjournals.org/x", "deafed.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://delivery.acm.org/x", "delivery.acm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://demomars.csis.com.tw/x", "demomars.csis.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://diipcs.webofknowledge.com/x", "diipcs.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://dlib.apabi.com/x", "dlib.apabi.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://download.springer.com/x", "download.springer.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ea.grolier.com/x", "ea.grolier.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://earthinteractions.org/x", "earthinteractions.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ebook01.koobe.com.tw/x", "ebook01.koobe.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ebooks.abc-clio.com/x", "ebooks.abc-clio.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ebooks.kluweronline.com/x", "ebooks.kluweronline.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ebooks.springerlink.com/x", "ebooks.springerlink.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ebooks.windeal.com.tw/x", "ebooks.windeal.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ec.asm.org/x", "ec.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://edo.tw/x", "edo.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://edo.tw/ocp.aspx?subs_no=20063/x", "edo.tw/ocp.aspx?subs_no=20063", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://eds.a.ebscohost.com/x", "eds.a.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://eds.b.ebscohost.com/x", "eds.b.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://eds.c.ebscohost.com/x", "eds.c.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://eds.d.ebscohost.com/x", "eds.d.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://eds.e.ebscohost.com/x", "eds.e.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://edu1.wordpedia.com/x", "edu1.wordpedia.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://eebo.chadwyck.com/x", "eebo.chadwyck.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ei.e-lib.nctu.edu.tw/x", "ei.e-lib.nctu.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ei.oupjournals.org/x", "ei.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ei.stic.gov.tw/x", "ei.stic.gov.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ej.iop.org/x", "ej.iop.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://elearning.webenglish.tv/x", "elearning.webenglish.tv", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://elib.infolinker.com.tw/x", "elib.infolinker.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://emboj.oupjournals.org/x", "emboj.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://engineer.windeal.com.tw/x", "engineer.windeal.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://enterprise.astm.org/x", "enterprise.astm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://epirev.oupjournals.org/x", "epirev.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://epubs.siam.org/x", "epubs.siam.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://erae.oupjournals.org/x", "erae.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://eric.lib.nccu.edu.tw/x", "eric.lib.nccu.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://es.oupjournals.org/x", "es.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://esi.webofknowledge.com/x", "esi.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://esr.oupjournals.org/x", "esr.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://estipub.isiknowledge.com/x", "estipub.isiknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ethesys.lib.ntou.edu.tw/x", "ethesys.lib.ntou.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://fampra.oupjournals.org/x", "fampra.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://g.wanfangdata.com.hk/x", "g.wanfangdata.com.hk", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://galenet.galegroup.com/x", "galenet.galegroup.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://gateway.webofknowledge.com/x", "gateway.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://german2.nccu.edu.tw/x", "german2.nccu.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://global.ebsco-content.com/x", "global.ebsco-content.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://global.umi.com/x", "global.umi.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://globalbb.onesource.com/x", "globalbb.onesource.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://glycob.oupjournals.org/x", "glycob.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://gme.grolier.com/x", "gme.grolier.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://go-passport.grolier.com/x", "go-passport.grolier.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://go.galegroup.com/x", "go.galegroup.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://go.grolier.com/x", "go.grolier.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://go.westlawjapan.com/x", "go.westlawjapan.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://haworthpress.com/x", "haworthpress.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://hbrtwn.infolinker.com.tw/x", "hbrtwn.infolinker.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://hcr.oupjournals.org/x", "hcr.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://hcr3.webofknowledge.com/x", "hcr3.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://heapol.oupjournals.org/x", "heapol.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://heapro.oupjournals.org/x", "heapro.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://her.oupjournals.org/x", "her.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://hjournals.cambridge.org/x", "hjournals.cambridge.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://hk.wanfangdata.com/x", "hk.wanfangdata.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://hmg.oupjournals.org/x", "hmg.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://http://infotrac.galegroup.com/x", "http://infotrac.galegroup.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://humrep.oupjournals.org/x", "humrep.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://hunteq.com/x", "hunteq.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://huso.stpi.narl.org.tw/x", "huso.stpi.narl.org.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://huso.stpi.org.tw/x", "huso.stpi.org.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://hyweb.ebook.hyread.com.tw/x", "hyweb.ebook.hyread.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://iai.asm.org/x", "iai.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://icc.oupjournals.org/x", "icc.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ieee.org/x", "ieee.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://igroup.ebrary.com/x", "igroup.ebrary.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ije.oupjournals.org/x", "ije.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ijpor.oupjournals.org/x", "ijpor.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ilibrary.com.tw/x", "ilibrary.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://imagebank.osa.org/x", "imagebank.osa.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://images.webofknowledge.com/x", "images.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://infotrac.galegroup.com/x", "infotrac.galegroup.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://infoweb.newsbank.com/x", "infoweb.newsbank.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://international.westlaw.com/x", "international.westlaw.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://intimm.oupjournals.org/x", "intimm.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://intqhc.oupjournals.org/x", "intqhc.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://iopscience.iop.org/x", "iopscience.iop.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://iospress.metapress.com/x", "iospress.metapress.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://irap.oupjournals.org/x", "irap.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://isi4.isiknowledge.com/x", "isi4.isiknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://isiknowledge.com/x", "isiknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jac.oupjournals.org/x", "jac.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jae.oupjournals.org/x", "jae.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jap.aip.org/x", "jap.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jb.asm.org/x", "jb.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jcm.asm.org/x", "jcm.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jcp.aip.org/x", "jcp.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jcr1.isiknowledge.com/x", "jcr1.isiknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jeg.oupjournals.org/x", "jeg.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jhered.oupjournals.org/x", "jhered.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jjco.oupjournals.org/x", "jjco.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jleo.oupjournals.org/x", "jleo.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jlt.osa.org/x", "jlt.osa.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jmicro.oupjournals.org/x", "jmicro.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jmp.aip.org/x", "jmp.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jn.physiology.org/x", "jn.physiology.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jncicancerspectrum.oupjournals.org/x", "jncicancerspectrum.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://joc.oupjournals.org/x", "joc.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://josaa.osa.org/x", "josaa.osa.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jot.osa.org/x", "jot.osa.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://journals.ametsoc.org/x", "journals.ametsoc.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://journals.asm.org/x", "journals.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://journals.cambridge.org/x", "journals.cambridge.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://journals.kluweronline.com/x", "journals.kluweronline.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://journals.wspc.com.sg/x", "journals.wspc.com.sg", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jpart.oupjournals.org/x", "jpart.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jpcrd.aip.org/x", "jpcrd.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jpepsy.oupjournals.org/x", "jpepsy.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jrse.aip.org/x", "jrse.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jurban.oupjournals.org/x", "jurban.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jvi.asm.org/x", "jvi.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://jxb.oupjournals.org/x", "jxb.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://klassiker.chadwyck.co.uk/x", "klassiker.chadwyck.co.uk", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://kmw.ctgin.com/x", "kmw.ctgin.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://lang.ntou.edu.tw/source.php/x", "lang.ntou.edu.tw/source.php", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://lb20.ah100.libraryandbook.net/x", "lb20.ah100.libraryandbook.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://lb20.botw.libraryandbook.net/x", "lb20.botw.libraryandbook.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://lb20.dummies.libraryandbook.net/x", "lb20.dummies.libraryandbook.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://lb20.tabf.libraryandbook.net/x", "lb20.tabf.libraryandbook.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://legal.lexisnexis.jp/x", "legal.lexisnexis.jp", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://lib.myilibrary.com/x", "lib.myilibrary.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://library.books24x7.com/x", "library.books24x7.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://library.pressdisplay.com/x", "library.pressdisplay.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://link.aps.org/x", "link.aps.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://link.springer-ny.com/x", "link.springer-ny.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://link.springer.com/x", "link.springer.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://link.springer.de/x", "link.springer.de", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://links.springer.com/x", "links.springer.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://links.webofknowledge.com/x", "links.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ltp.aip.org/x", "ltp.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://mars.csa.com/x", "mars.csa.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://mars.csis.com.tw/x", "mars.csis.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://mars2.csa.com/x", "mars2.csa.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://mars3.csa.com/x", "mars3.csa.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://mbe.oupjournals.org/x", "mbe.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://mcb.asm.org/x", "mcb.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://md1.csa.com/x", "md1.csa.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://md2.csa.com/x", "md2.csa.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://minghouse.infolinker.com.tw/x", "minghouse.infolinker.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://mmbr.asm.org/x", "mmbr.asm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://molehr.oupjournals.org/x", "molehr.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://mollus.oupjournals.org/x", "mollus.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://mutage.oupjournals.org/x", "mutage.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://mydigitallibrary.lib.overdrive.com/x", "mydigitallibrary.lib.overdrive.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://nar.oupjournals.org/x", "nar.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ncl3web.hyweb.com.tw/x", "ncl3web.hyweb.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ndt.oupjournals.org/x", "ndt.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://new.cwk.com.tw/x", "new.cwk.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://newfirstsearch.global.oclc.org/x", "newfirstsearch.global.oclc.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://newfirstsearch.oclc.org/x", "newfirstsearch.oclc.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ntou.ebook.hyread.com.tw/x", "ntou.ebook.hyread.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ntou.koobe.com.tw/x", "ntou.koobe.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ntt1.hyweb.com.tw/x", "ntt1.hyweb.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://occmed.oupjournals.org/x", "occmed.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://oep.oupjournals.org/x", "oep.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://oh1.csa.com/x", "oh1.csa.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://oh2.csa.com/x", "oh2.csa.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ojps.aip.org/x", "ojps.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ol.osa.org/x", "ol.osa.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://oldweb.cqvip.com/x", "oldweb.cqvip.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://omed.nuazure.info/x", "omed.nuazure.info", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://online.sagepub.com/x", "online.sagepub.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://onlinelibrary.wiley.com/x", "onlinelibrary.wiley.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ortho.oupjournals.org/x", "ortho.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://oversea.cnki.net/x", "oversea.cnki.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ovid.stic.gov.tw/x", "ovid.stic.gov.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ovidsp.ovid.com/x", "ovidsp.ovid.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://oxfordjournals.org/x", "oxfordjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://oxrep.oupjournals.org/x", "oxrep.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pa.oupjournals.org/x", "pa.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pan.oupjournals.org/x", "pan.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pao.chadwyck.co.uk/x", "pao.chadwyck.co.uk", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pcp.oupjournals.org/x", "pcp.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pcs.webofknowledge.com/x", "pcs.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pcs.webofknowledgev4com/x", "pcs.webofknowledgev4com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pdn.sciencedirect.com/x", "pdn.sciencedirect.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://petrology.oupjournals.org/x", "petrology.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://phr.oupjournals.org/x", "phr.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://physics.aps.org/x", "physics.aps.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://physiolgenomics.physiology.org/x", "physiolgenomics.physiology.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://plankt.oupjournals.org/x", "plankt.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pm.nlx.com/x", "pm.nlx.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pm.nlx.com/xtf/search?browse-collections=true/x", "pm.nlx.com/xtf/search?browse-collections=true", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pof.aip.org/x", "pof.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pop.aip.org/x", "pop.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://portal.acm.org/x", "portal.acm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://portal.isiknowledge.com/x", "portal.isiknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pqdd.sinica.edu.tw/x", "pqdd.sinica.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pra.aps.org/x", "pra.aps.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://prb.aps.org/x", "prb.aps.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://prc.aps.org/x", "prc.aps.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://prd.aps.org/x", "prd.aps.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pre.aps.org/x", "pre.aps.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://prl.aps.org/x", "prl.aps.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pro-twfubao.infolinker.com.tw/x", "pro-twfubao.infolinker.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://prola.aps.org/x", "prola.aps.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://prola.library.cornell.edu/x", "prola.library.cornell.edu", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://proquest.umi.com/x", "proquest.umi.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://proquest.uni.com/x", "proquest.uni.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://protein.oupjournals.org/x", "protein.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ptr.oupjournals.org/x", "ptr.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pubmed.oupjournals.org/x", "pubmed.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pubs.acs.org/x", "pubs.acs.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pubs.rsc.org/x", "pubs.rsc.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://pubs3.acs.org/x", "pubs3.acs.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://qjmed.oupjournals.org/x", "qjmed.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://reading.udn.com/x", "reading.udn.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://readopac.ncl.edu.tw/x", "readopac.ncl.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://readopac2.ncl.edu.tw/x", "readopac2.ncl.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://readopac3.ncl.edu.tw/x", "readopac3.ncl.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://reference.kluweronline.com/x", "reference.kluweronline.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://refworks.reference-global.com/x", "refworks.reference-global.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://rfs.oupjournals.org/x", "rfs.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://rheumatology.oupjournals.org/x", "rheumatology.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://rmp.aps.org/x", "rmp.aps.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://rsi.aip.org/x", "rsi.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://rss.webofknowledge.com/x", "rss.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://schiller.chadwyck.co.uk/x", "schiller.chadwyck.co.uk", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://sciencenow.sciencemag.org/x", "sciencenow.sciencemag.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://scifinder.cas.org/x", "scifinder.cas.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://scitation.aip.org/x", "scitation.aip.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://sdos.ejournal.ascc.net/x", "sdos.ejournal.ascc.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://search.ebscohost.com/x", "search.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://search.epnet.com/x", "search.epnet.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://search.isiknowledge.com/x", "search.isiknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://search.proquest.com/x", "search.proquest.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://search.webofknowledge.com/x", "search.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ser.oupjournals.org/x", "ser.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://service.csa.com.tw/x", "service.csa.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://service.flysheet.com.tw/x", "service.flysheet.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://service.refworks.com.tw/x", "service.refworks.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://shmu.alexanderstreet.com/x", "shmu.alexanderstreet.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://site.ebrary.com/x", "site.ebrary.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://soth.alexanderstreet.com/x", "soth.alexanderstreet.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://sp.oupjournals.org/x", "sp.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://springerlink.metapress.com/x", "springerlink.metapress.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ssjj.oupjournals.org/x", "ssjj.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://stfb.ntl.edu.tw/x", "stfb.ntl.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://stfj.ntl.edu.tw/x", "stfj.ntl.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://sub3.webofknowledge.com/x", "sub3.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://survival.oupjournals.org/x", "survival.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://sushi.webofknowledge.com/x", "sushi.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://swproxy.swetswise.com/x", "swproxy.swetswise.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://taebc.ebook.hyread.com.tw/x", "taebc.ebook.hyread.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://taebc.etailer.dpsl.net/x", "taebc.etailer.dpsl.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://taebc.koobe.com.tw/x", "taebc.koobe.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://taebcmgh.sa.libraryandbook.net/x", "taebcmgh.sa.libraryandbook.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://tandf.msgfocus.com/x", "tandf.msgfocus.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://tao.wordpedia.com/x", "tao.wordpedia.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://tbmcdb.infolinker.com.tw/x", "tbmcdb.infolinker.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://tcsd.lib.ntu.edu.tw/x", "tcsd.lib.ntu.edu.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://tebko.infolinker.com.tw/x", "tebko.infolinker.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://tie.tier.org.tw/x", "tie.tier.org.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://toc.webofknowledge.com/x", "toc.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://toc.webofknowledgev4.com/x", "toc.webofknowledgev4.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://tongji.oversea.cnki.net/x", "tongji.oversea.cnki.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://toxsci.oupjournals.org/x", "toxsci.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://turs.infolinker.com.tw/x", "turs.infolinker.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://tw.magv.com/x", "tw.magv.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://twu-ind.wisenews.net.tw/x", "twu-ind.wisenews.net.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://udndata.com/x", "udndata.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://udndata.com/library/fullpage/x", "udndata.com/library/fullpage", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ulej.stic.gov.tw/x", "ulej.stic.gov.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://vnweb.hwwilsonweb.com/x", "vnweb.hwwilsonweb.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://wber.oupjournals.org/x", "wber.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://wbro.oupjournals.org/x", "wbro.oupjournals.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://wcs.webofknowledge.com/x", "wcs.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://web.a.ebscohost.com/x", "web.a.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://web.b.ebscohost.com/x", "web.b.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://web.c.ebscohost.com/x", "web.c.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://web.d.ebscohost.com/x", "web.d.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://web.e.ebscohost.com/x", "web.e.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://web.ebscohost.com/x", "web.ebscohost.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://web.lexis-nexis.com/x", "web.lexis-nexis.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://web17.epnet.com/x", "web17.epnet.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://webofknowledge.com/x", "webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://wok-ws.isiknowledge.com/x", "wok-ws.isiknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://wos.stic.gov.tw/x", "wos.stic.gov.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://ws.isiknowledge.com/x", "ws.isiknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.acm.org/x", "www.acm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.agu.org/x", "www.agu.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.airitiaci.com/x", "www.airitiaci.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.airitiaci.com//x", "www.airitiaci.com/", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.airitibooks.com/x", "www.airitibooks.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.airitilibrary.com/x", "www.airitilibrary.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.airitinature.com/x", "www.airitinature.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.annualreviews.org/x", "www.annualreviews.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.apabi.com/x", "www.apabi.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.apabi.com/cec/x", "www.apabi.com/cec", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.ascelibrary.org/x", "www.ascelibrary.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.asme.org/x", "www.asme.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.astm.org/x", "www.astm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.atozmapsonline.com/x", "www.atozmapsonline.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.atoztheworld.com/x", "www.atoztheworld.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.atozworldbusiness.com/x", "www.atozworldbusiness.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.atozworldculture.com/x", "www.atozworldculture.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.atozworldtrade.com/x", "www.atozworldtrade.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.atozworldtravel.com/x", "www.atozworldtravel.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.biolbull.org/x", "www.biolbull.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.bioone.org/x", "www.bioone.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.blackwell-synergy.com/x", "www.blackwell-synergy.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.brepolis.net/x", "www.brepolis.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.bridgemaneducation.com/x", "www.bridgemaneducation.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.bssaonline.org/x", "www.bssaonline.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.cairn.info/x", "www.cairn.info", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.ceps.com.tw/x", "www.ceps.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.chinamaxx.net/x", "www.chinamaxx.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.classiques-garnier.com/x", "www.classiques-garnier.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.cnsonline.com.tw/x", "www.cnsonline.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.cnsppa.com.tw/x", "www.cnsppa.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.crcnetbase.com/x", "www.crcnetbase.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.credoreference.com/x", "www.credoreference.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.csa.com/x", "www.csa.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.csa.com.tw/x", "www.csa.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.dalloz.fr/x", "www.dalloz.fr", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.dialogselect.com/x", "www.dialogselect.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.discoverygate.com/x", "www.discoverygate.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.duxiu.com/x", "www.duxiu.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.ebookstore.tandf.co.uk/x", "www.ebookstore.tandf.co.uk", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.ebsco.com/x", "www.ebsco.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.educationarena.com/x", "www.educationarena.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.ei.org/x", "www.ei.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.els.net/x", "www.els.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.elsevier.com/x", "www.elsevier.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.emeraldinsight.com/x", "www.emeraldinsight.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.engineeringvillage.com/x", "www.engineeringvillage.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.engineeringvillage2.org/x", "www.engineeringvillage2.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.europaworld.com/x", "www.europaworld.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.europe.idealibrary.com/x", "www.europe.idealibrary.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.frantext.fr/x", "www.frantext.fr", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.genome.org/x", "www.genome.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.genomebiology.com/x", "www.genomebiology.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.greeninfoonline.com/x", "www.greeninfoonline.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.hepseu.com/x", "www.hepseu.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.icevirtuallibrary.com/x", "www.icevirtuallibrary.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.idealibrary.com/x", "www.idealibrary.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.igpublish.com/x", "www.igpublish.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.informaworld.com/x", "www.informaworld.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.ingenta.com/x", "www.ingenta.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.int-res.com/x", "www.int-res.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.iop.org/x", "www.iop.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.iospress.nl/x", "www.iospress.nl", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.isihighlycited.com/x", "www.isihighlycited.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.jkn21.com/x", "www.jkn21.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.jstor.org/x", "www.jstor.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.juris.de/x", "www.juris.de", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.kluwerlawonline.com/x", "www.kluwerlawonline.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.kluweronline.com/x", "www.kluweronline.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.knovel.com/x", "www.knovel.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.lawbank.com.tw/x", "www.lawbank.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.lawdata.com.tw/x", "www.lawdata.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.lexisnexis.com/x", "www.lexisnexis.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.lexisnexis.com/ap/academic/x", "www.lexisnexis.com/ap/academic", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.lexisnexis.com/ap/auth/x", "www.lexisnexis.com/ap/auth", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.lextenso.fr/x", "www.lextenso.fr", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.mergentonline.com/x", "www.mergentonline.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.mrw.interscience.wiley.com/x", "www.mrw.interscience.wiley.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.munzinger.de/x", "www.munzinger.de", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.myendnoteweb.com/x", "www.myendnoteweb.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.myilibrary.com/x", "www.myilibrary.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.nature.com/x", "www.nature.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.netlibrary.com/x", "www.netlibrary.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.nonlin-processes-geophys.net/x", "www.nonlin-processes-geophys.net", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.nutrition.org/x", "www.nutrition.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.onesource.com/x", "www.onesource.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.opticsexpress.org/x", "www.opticsexpress.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.osa-jon.org/x", "www.osa-jon.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.osa-opn.org/x", "www.osa-opn.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.oxfordreference.com/x", "www.oxfordreference.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.oxfordscholarship.com/x", "www.oxfordscholarship.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.palgrave-journals.com/x", "www.palgrave-journals.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.palgraveconnect.com/x", "www.palgraveconnect.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.proteinscience.org/x", "www.proteinscience.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.read.com.tw/x", "www.read.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.reaxys.com/x", "www.reaxys.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.refworks.com/x", "www.refworks.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.refworks.com.tw/x", "www.refworks.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.researcherid.com/x", "www.researcherid.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.rsc.org/x", "www.rsc.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.sage-ereference.com/x", "www.sage-ereference.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.sciencedirect.com/x", "www.sciencedirect.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.sciencemag.org/x", "www.sciencemag.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.scopus.com/x", "www.scopus.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.springerlink.com/x", "www.springerlink.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.swetsnet.nl/x", "www.swetsnet.nl", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.swetswise.com/x", "www.swetswise.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.taebcnetbase.com/x", "www.taebcnetbase.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.tandf.co.uk/x", "www.tandf.co.uk", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.tandfonline.com/x", "www.tandfonline.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.tbmc.com.tw/x", "www.tbmc.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.TeacherReference.com/x", "www.TeacherReference.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.tlemea.com/x", "www.tlemea.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.tls.psmedia.com/x", "www.tls.psmedia.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.tumblebooks.com/x", "www.tumblebooks.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.tw-elsevier.com/x", "www.tw-elsevier.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.universalis-edu.com/x", "www.universalis-edu.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.wanfangdata.com.hk/x", "www.wanfangdata.com.hk", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.webofknowledge.com/x", "www.webofknowledge.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.webofknowledgev4.com/x", "www.webofknowledgev4.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.westlaw.com/x", "www.westlaw.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www.wkap.nl/x", "www.wkap.nl", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www2.astm.org/x", "www2.astm.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www2.read.com.tw/x", "www2.read.com.tw", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www3.electrochem.org/x", "www3.electrochem.org", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www3.interscience.wiley.com/x", "www3.interscience.wiley.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://www3.oup.co.uk/x", "www3.oup.co.uk", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://wwwlib.global.umi.com/x", "wwwlib.global.umi.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://yagi.jkn21.com/x", "yagi.jkn21.com", "PROXY proxylib.ntou.edu.tw:3128"},
				{"http://google.com/x", "google.com", "DIRECT"},
			},
		},

		// pac2
		{`function FindProxyForURL(url, host) {
	// our local URLs from the domains below example.com don't need a proxy:
	if (shExpMatch(host, "*.example.com")) {
		return "DIRECT";
	}

	// URLs within this network are accessed through
	// port 8080 on fastproxy.example.com:
	if (isInNet(host, "10.0.0.0", "255.255.248.0")) {
		return "PROXY fastproxy.example.com:8080";
	}

	// All other requests go through port 8080 of proxy.example.com.
	// should that fail to respond, go directly to the WWW:
	return "PROXY proxy.example.com:8080; DIRECT";
}`,
			[]case_table{
				{"http://foobar.example.com/x", "foobar.example.com", "DIRECT"},
				{"http://10.0.0.10/x", "10.0.0.10", "PROXY fastproxy.example.com:8080"},
				{"http://129.35.213.31/x", "129.35.213.31", "PROXY proxy.example.com:8080; DIRECT"},
			},
		},

		// pac3
		{`function FindProxyForURL(url, host) {
    ip = dnsResolve(host);
    return "PROXY " + ip + ":8080";
}`,
			[]case_table{
				{"http://this.domain.does.not.exist/", "this.domain.does.not.exist", "PROXY :8080"},
			},
		},

		// pac4
		{`function FindProxyForURL(url, host) {
    throw 'testing error handling, url: ' + url + ' host: ' + host;
}`,
			[]case_table{
				{"http://foobar.example.com/x", "foobar.example.com", "testing error handling, url: http://foobar.example.com/x host: foobar.example.com"},
			},
		},

		// pac5
		{`function FindProxyForURL(url, host) {
    throw new Error('testing error handling, url: ' + url + ' host: ' + host);
}`,
			[]case_table{
				{"http://foobar.example.com/x", "foobar.example.com", "Error: testing error handling, url: http://foobar.example.com/x host: foobar.example.com"},
			},
		},
	}

	for _, pac := range pacs {
		for _, test := range pac.tests {
			if result, err := Find_proxy_sync(pac.pac, test.url, test.host); err == nil {
				if result != test.expect {
					t.Errorf("Got incorrect proxy: '%s', expected '%s'", result, test.expect)
				}
			} else {
				if err.Error() != test.expect {
					t.Errorf("Got incorrect ERROR returned: '%s', expected '%s'", err.Error(), test.expect)
				}
			}
		}
	}
}
