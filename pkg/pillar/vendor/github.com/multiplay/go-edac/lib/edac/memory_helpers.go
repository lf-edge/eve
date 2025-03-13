package edac

// HasMemoryErrors returns true if there are any memory errors, false otherwise.
func HasMemoryErrors() (bool, error) {
	mcs, err := MemoryControllers()
	if err != nil {
		return false, err
	}

	for _, mc := range mcs {
		i, err := mc.Info()
		if err != nil {
			return false, err
		} else if i.HasErrors() {
			return true, nil
		}
	}

	return false, nil
}
