package resolver

import (
	"sync"

	"github.com/miekg/dns"
)

type Resolver struct {
	Server string
	Query  *Query
}

func NewResolver(server string) *Resolver {
	resolver := Resolver{Server: server + ":53"}
	return &resolver
}

func (r *Resolver) Targets(targets ...string) *Query {
	query := NewQueryWithTargets(targets...)
	r.Query = query
	return query
}

func (r *Resolver) Lookup() *Result {
	result := Result{Server: r.Server, ResMap: map[string][]*ResultItem{}}

	resultsChan := make(chan []*ResultItem, r.Query.Count())
	var wg sync.WaitGroup
	for _, queryItem := range r.Query.Items {
		target := queryItem.Target
		for _, t := range queryItem.Types {
			wg.Add(1)
			go func(queryType QueryType) {
				defer wg.Done()
				goExchange(target, r.Server, queryType, resultsChan)
			}(t)
		}
	}

	wg.Wait()
	close(resultsChan)

	for res := range resultsChan {
		if len(res) > 0 {
			target := res[0].Record
			result.ResMap[target] = append(result.ResMap[target], res...)
		}
	}
	return &result
}

func goExchange(target string, server string, queryType QueryType, resultsChan chan []*ResultItem) {
	for i := -1; i < int(Config.RetryTimes); i++ {
		if results, err := Exchange(target, server, queryType); err == nil {
			resultsChan <- results
			return
		}
	}
}

func Exchange(target string, server string, queryType QueryType) ([]*ResultItem, error) {
	var results []*ResultItem
	msg := &dns.Msg{}
	msg.SetQuestion(target+".", uint16(queryType))
	client := &dns.Client{DialTimeout: Config.Timeout}
	res, _, err := client.Exchange(msg, server)
	if err == nil && len(res.Answer) > 0 {
		for _, answer := range res.Answer {
			result := NewResultItemWithDnsRR(queryType, answer)
			result.Record = target
			results = append(results, result)
		}
	}
	return results, err
}
