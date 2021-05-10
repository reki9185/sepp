module github.com/yangalan0903/sepp

go 1.14

require (
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/free5gc/http2_util v1.0.0
	github.com/free5gc/http_wrapper v1.0.0
	github.com/free5gc/logger_conf v1.0.0
	github.com/free5gc/logger_util v1.0.0
	github.com/free5gc/path_util v1.0.0
	github.com/free5gc/version v1.0.0
	github.com/gin-gonic/gin v1.7.1
	github.com/go-playground/validator/v10 v10.5.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/ugorji/go v1.2.5 // indirect
	github.com/urfave/cli v1.22.5
	github.com/yangalan0903/openapi v0.0.0-20210414173423-ec2e658ec5f7
	golang.org/x/crypto v0.0.0-20210421170649-83a5a9bb288b
	golang.org/x/net v0.0.0-20210423184538-5f58ad60dda6 // indirect
	golang.org/x/sys v0.0.0-20210426080607-c94f62235c83 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/yangalan0903/openapi => /home/alan/files/thesis/openapi

// replace github.com/yangalan0903/sepp/factory => ./factory
