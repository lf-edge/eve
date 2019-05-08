package owntpm

import "fmt"
import "github.com/google/go-tpm/tpm2"

var (
	TpmDevicePath = "/dev/tpm0"
)

func owntpm() error {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer rw.Close()
	//Put an info print for now.
	fmt.Println("Successfully opened handle to tpm device")
	return nil
}

func Run() {
	owntpm()
}
