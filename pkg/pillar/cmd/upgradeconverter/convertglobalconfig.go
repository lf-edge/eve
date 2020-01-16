package upgradeconverter

func handleUpgradeGlobalConfig(action ConverterAction) error {
	switch action {
	case Convert:
		convert()
	case CleanupNew:
		cleanupNew()
	case CleanupOld:
		cleanupOld()
	case NoAction:
		break
	}
	return nil
}

func convert() error {
	var err error
	oldVersionExists := fileExists(OLDVERSION)
	newVersionExists := fileExists(NEWVERSION)
	if newVersionExists {
		if oldVersionExists {
			oldVersionTime, _ := fileTimeStamp(OLDVERSION)
			newVersionTime, _ := fileTimeStamp(NEWVERSION)
			if oldVersionTime.After(newVersionTime) {
				err = deleteFile(NEWVERSION)
			} else {
				err = deleteFile(OLDVERSION)
				return err
			}
		} else {
			return nil
		}
	}

	if oldVersionExists {
		// Convert
	}
	return err
}

func cleanupNew()  {

}

func cleanupOld()  {

}


