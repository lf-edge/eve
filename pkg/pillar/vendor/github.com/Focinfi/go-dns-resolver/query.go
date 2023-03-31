package resolver

type QueryItem struct {
	Target string
	Types  []QueryType
}

type Query struct {
	Items []*QueryItem
}

func NewQueryWithTargets(targets ...string) *Query {
	query := Query{Items: make([]*QueryItem, len(targets), len(targets))}
	for i, target := range targets {
		query.Items[i] = &QueryItem{Target: target}
	}
	return &query
}

func (query *Query) Types(types ...QueryType) *Query {
	for _, queryItem := range query.Items {
		queryItem.Types = types
	}
	return query
}

func (query *Query) Count() int {
	if len(query.Items) == 0 {
		return 0
	}
	return len(query.Items) * len(query.Items[0].Types)
}
