package resolver

import (
	"github.com/miekg/dns"
)

type QueryType uint16

const (
	TypeA     = QueryType(dns.TypeA)
	TypeAAAA  = QueryType(dns.TypeAAAA)
	TypeNS    = QueryType(dns.TypeNS)
	TypeMX    = QueryType(dns.TypeMX)
	TypeSOA   = QueryType(dns.TypeSOA)
	TypeCNAME = QueryType(dns.TypeCNAME)
	TypeTXT   = QueryType(dns.TypeTXT)
)

func (q QueryType) String() string {
	switch q {
	case TypeA:
		return "A"
	case TypeAAAA:
		return "AAAA"
	case TypeNS:
		return "NS"
	case TypeMX:
		return "MX"
	case TypeSOA:
		return "SOA"
	case TypeCNAME:
		return "CNAME"
	case TypeTXT:
		return "TXT"
	default:
		return "Unknown Type"
	}
}
