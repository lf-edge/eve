// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package generics

// EqualLists returns true if the two slices representing lists (i.e. order dependent)
// are equal in size and items they contain.
// This function can be used if slice items are comparable
// (operator "==" can be used).
func EqualLists[Type comparable](list1, list2 []Type) bool {
	return EqualListsFn(list1, list2, func(a, b Type) bool {
		return a == b
	})
}

// EqualListsFn returns true if the two slices representing lists (i.e. order dependent)
// are equal in size and items they contain.
// Two slice items are compared using the provided "equal" callback.
func EqualListsFn[Type any](list1, list2 []Type, equal func(a, b Type) bool) bool {
	if len(list1) != len(list2) {
		return false
	}
	for i := range list1 {
		if !equal(list1[i], list2[i]) {
			return false
		}
	}
	return true
}

// EqualSets returns true if the two slices that represent sets (i.e. order independent)
// are equal in size and items they contain.
// This function can be used if slice items are comparable
// (operator "==" can be used).
func EqualSets[Type comparable](set1, set2 []Type) bool {
	return EqualSetsFn(set1, set2, func(a, b Type) bool {
		return a == b
	})
}

// EqualSetsFn returns true if the two slices that represent sets (i.e. order independent)
// are equal in size and items they contain.
// Two slice items are compared using the provided "equal" callback.
func EqualSetsFn[Type any](set1, set2 []Type, equal func(a, b Type) bool) bool {
	if len(set1) != len(set2) {
		return false
	}
	for _, item1 := range set1 {
		var found bool
		for _, item2 := range set2 {
			if equal(item1, item2) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// DiffSets returns slice with items that are present in the first slice
// but not in the second and vice versa.
// This function can be used if slice items are comparable
// (operator "==" can be used).
func DiffSets[Type comparable](set1, set2 []Type) (onlyInSet1, onlyInSet2 []Type) {
	return DiffSetsFn(set1, set2, func(a, b Type) bool {
		return a == b
	})
}

// DiffSetsFn returns slice with items that are present in the first slice
// but not in the second and vice versa.
// Two slice items are compared using the provided "equal" callback.
func DiffSetsFn[Type any](set1, set2 []Type, equal func(a, b Type) bool) (
	onlyInSet1, onlyInSet2 []Type) {
	for _, item1 := range set1 {
		var found bool
		for _, item2 := range set2 {
			if equal(item1, item2) {
				found = true
				break
			}
		}
		if !found {
			onlyInSet1 = append(onlyInSet1, item1)
		}
	}
	for _, item2 := range set2 {
		var found bool
		for _, item1 := range set1 {
			if equal(item2, item1) {
				found = true
				break
			}
		}
		if !found {
			onlyInSet2 = append(onlyInSet2, item2)
		}
	}
	return
}

// FilterList return a new slice with items that pass the "keep" callback.
func FilterList[Type any](list []Type, keep func(a Type) bool) (filtered []Type) {
	for _, item := range list {
		if keep(item) {
			filtered = append(filtered, item)
		}
	}
	return
}

// FilterDuplicates return a new slice with duplicate entries removed.
// This function can be used if slice items are comparable
// (operator "==" can be used).
func FilterDuplicates[Type comparable](list []Type) (filtered []Type) {
	return FilterDuplicatesFn(list, func(a, b Type) bool {
		return a == b
	})
}

// FilterDuplicatesFn return a new slice with duplicate entries removed.
// Two slice items are compared using the provided "equal" callback.
func FilterDuplicatesFn[Type any](list []Type, equal func(a, b Type) bool) (filtered []Type) {
	for _, item := range list {
		var duplicate bool
		for _, prevItem := range filtered {
			if equal(item, prevItem) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			filtered = append(filtered, item)
		}
	}
	return
}

// ContainsItem returns true if the slice contains the given item.
// This function can be used if slice items are comparable
// (operator "==" can be used).
func ContainsItem[Type comparable](list []Type, item Type) bool {
	for i := range list {
		if list[i] == item {
			return true
		}
	}
	return false
}

// ContainsItemFn returns true if the slice contains the given item.
// Two slice items are compared using the provided "equal" callback.
func ContainsItemFn[Type any](list []Type, item Type, equal func(a, b Type) bool) bool {
	for i := range list {
		if equal(list[i], item) {
			return true
		}
	}
	return false
}

// AppendIfNotDuplicate adds item into list if the list does not yet contain the item.
func AppendIfNotDuplicate[Type comparable](list []Type, item Type) []Type {
	if !ContainsItem(list, item) {
		return append(list, item)
	}
	return list
}
