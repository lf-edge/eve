// build +darwin

// Only the definations needed for compilation on MacOs are added here.
// When adding the definitions, copy the corresponding ones from
//	link_linux.go

package netlink

// LinkUpdate is used to pass information back from LinkSubscribe()
type LinkUpdate struct {
	Link
}
