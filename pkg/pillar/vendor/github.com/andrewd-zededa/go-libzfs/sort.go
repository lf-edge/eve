package zfs

import (
	"strconv"
)

type clonesCreateDesc []Dataset

func (list clonesCreateDesc) Less(i, j int) bool {
	_, oki := list[i].Properties[DatasetNumProps+1000]
	_, okj := list[i].Properties[DatasetNumProps+1000]
	if oki && okj {
		unixti, err := strconv.ParseInt(
			list[i].Properties[DatasetNumProps+1000].Value, 10, 64)
		if err != nil {
			panic(err)
		}
		unixtj, err := strconv.ParseInt(
			list[j].Properties[DatasetNumProps+1000].Value, 10, 64)
		if err != nil {
			panic(err)
		}
		if unixti != unixtj {
			return unixti > unixtj
		}
	}

	// if we have two datasets created from same snapshot
	// any of them will do, but we will go for most recent
	unixti, err := strconv.ParseInt(
		list[i].Properties[DatasetPropCreateTXG].Value, 10, 64)
	if err != nil {
		panic(err)
	}
	unixtj, err := strconv.ParseInt(
		list[j].Properties[DatasetPropCreateTXG].Value, 10, 64)
	if err != nil {
		panic(err)
	}

	return unixti > unixtj
}

func (list clonesCreateDesc) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

func (list clonesCreateDesc) Len() int {
	return len(list)
}
