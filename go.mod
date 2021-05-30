module github.com/yangalan0903/sepp

go 1.14

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20210208195552-ff826a37aa15 // indirect
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/buger/jsonparser v1.1.1
	github.com/calee0219/fatal v0.0.1
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575 // indirect
	github.com/free5gc/CommonConsumerTestData v1.0.0
	github.com/free5gc/MongoDBLibrary v1.0.0
	github.com/free5gc/http2_util v1.0.0
	github.com/free5gc/http_wrapper v1.0.0
	github.com/free5gc/logger_conf v1.0.0
	github.com/free5gc/logger_util v1.0.0
	github.com/free5gc/path_util v1.0.0
	github.com/free5gc/version v1.0.0
	github.com/gin-gonic/gin v1.7.1
	github.com/go-openapi/jsonpointer v0.19.5
	github.com/go-playground/validator/v10 v10.5.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/stamp/go-openssl v0.0.0-20151130221228-b5cda0941b72
	github.com/stamp/go-openvpn v0.0.0-20170402154221-4b07208dbd53
	github.com/ugorji/go v1.2.5 // indirect
	github.com/urfave/cli v1.22.5
	github.com/yangalan0903/openapi v0.0.0-20210414173423-ec2e658ec5f7
	go.mongodb.org/mongo-driver v1.5.2
	golang.org/x/crypto v0.0.0-20210421170649-83a5a9bb288b
	golang.org/x/net v0.0.0-20210423184538-5f58ad60dda6
	golang.org/x/sys v0.0.0-20210426080607-c94f62235c83 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/square/go-jose.v2 v2.5.1
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/yangalan0903/openapi => /home/alan/files/thesis/openapi

replace github.com/yangalan0903/sepp/jsonhandler => /home/alan/files/thesis/free5gc/NFs/sepp/jsonhandler

// replace github.com/yangalan0903/sepp/factory => ./factory
