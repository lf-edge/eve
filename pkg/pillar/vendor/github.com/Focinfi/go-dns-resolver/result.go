package resolver

import (
	"github.com/miekg/dns"
	"strings"
	"time"
)

type Result struct {
	Server string
	ResMap map[string][]*ResultItem
}

type ResultItem struct {
	Record   string
	Type     string
	Ttl      time.Duration
	Priority uint16
	Content  string
}

func (resultItem *ResultItem) setTtl(rr dns.RR_Header) {
	resultItem.Ttl = time.Second * time.Duration(rr.Ttl)
}

func NewResultItemWithDnsRR(queryType QueryType, answer dns.RR) (resultItem *ResultItem) {
	resultItem = &ResultItem{Type: queryType.String()}
	switch queryType {
	case TypeA:
		if a, ok := answer.(*dns.A); ok {
			resultItem.setTtl(a.Hdr)
			resultItem.Content = a.A.String()
		}
	case TypeAAAA:
		if a, ok := answer.(*dns.AAAA); ok {
			resultItem.setTtl(a.Hdr)
			resultItem.Content = a.AAAA.String()
		}
	case TypeCNAME:
		if cname, ok := answer.(*dns.CNAME); ok {
			resultItem.setTtl(cname.Hdr)
			resultItem.Content = cname.Target
		}
	case TypeMX:
		if mx, ok := answer.(*dns.MX); ok {
			resultItem.setTtl(mx.Hdr)
			resultItem.Content = mx.Mx
			resultItem.Priority = mx.Preference
		}
	case TypeNS:
		if ns, ok := answer.(*dns.NS); ok {
			resultItem.setTtl(ns.Hdr)
			resultItem.Content = ns.Ns
		}
	case TypeTXT:
		if txt, ok := answer.(*dns.TXT); ok {
			resultItem.setTtl(txt.Hdr)
			resultItem.Content = strings.Join(txt.Txt, " ")
		}
	}
	return
}
