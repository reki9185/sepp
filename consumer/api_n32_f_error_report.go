package consumer

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/yangalan0903/openapi/N32_Handshake"
	"github.com/yangalan0903/openapi/models"
)

func SendN32fErrorReport(seppUri string, n32fErrorInfo models.N32fErrorInfo) {
	configuration := N32_Handshake.NewConfiguration()
	configuration.SetBasePath(seppUri)
	client := N32_Handshake.NewAPIClient(configuration)

	var res *http.Response
	for {

		rsp, err := client.N32FErrorReportApi.PostN32fError(context.TODO(), n32fErrorInfo)
		if err != nil {
			fmt.Println(fmt.Errorf("SEPP connect to remote sepp Error[%v]", err))
			time.Sleep(2 * time.Second)
			continue
		} else {
			res = rsp
		}
		status := res.StatusCode
		if status == http.StatusNoContent {
			break
		} else {
			fmt.Println(fmt.Errorf("handler returned wrong status code %d", status))
			fmt.Println(fmt.Errorf("remote sepp return wrong status code %d", status))
		}
	}
}
