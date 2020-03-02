package domainmgr

// MountPoint - represents mountpoints of an app
type MountPoint struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	ReadOnly bool   `json:"readOnly,omitempty"`
}

// RktAppInstance describes an application instance referenced in a PodManifest
type RktAppInstance struct {
	Exec []string `json:"exec"`
	// EventHandlers     []EventHandler  `json:"eventHandlers,omitempty"`
	User  string `json:"user"`
	Group string `json:"group"`
	// SupplementaryGIDs []int           `json:"supplementaryGIDs,omitempty"`
	WorkDir string       `json:"workingDirectory,omitempty"`
	Env     []KeyValue   `json:"environment,omitempty"`
	Mounts  []MountPoint `json:"mountPoints,omitempty"`
	// Ports             []Port          `json:"ports,omitempty"`
	// Isolators         Isolators       `json:"isolators,omitempty"`
	// UserAnnotations   UserAnnotations `json:"userAnnotations,omitempty"`
	// UserLabels        UserLabels      `json:"userLabels,omitempty"`
}

// RktApp describes an application referenced in a PodManifest
type RktApp struct {
	Name string `json:"name"`
	// Image       RuntimeImage      `json:"image"`
	App RktAppInstance `json:"app,omitempty"`
	// ReadOnlyRootFS bool              `json:"readOnlyRootFS,omitempty"`
	// Mounts         []Mount           `json:"mounts,omitempty"`
	// Annotations    types.Annotations `json:"annotations,omitempty"`
}

// RktPodManifest represents a rkt pod manifest
type RktPodManifest struct {
	ACVersion string   `json:"acVersion"`
	ACKind    string   `json:"acKind"`
	Apps      []RktApp `json:"apps"`
	// Volumes         []types.Volume        `json:"volumes"`
	// Isolators       []KeyValue      `json:"isolators"`
	// Annotations     []KeyValue      `json:"annotations"`
	// Ports           []exposedPort   `json:"ports"`
	// UserAnnotations []KeyValue      `json:"userAnnotations,omitempty"`
	// UserLabels      []KeyValue      `json:"userLabels,omitempty"`
}
