package logger_util

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type Middleware func(http.HandlerFunc) http.HandlerFunc

type FileHook struct {
	file      *os.File
	flag      int
	chmod     os.FileMode
	formatter *logrus.TextFormatter
}

func NewFileHook(file string, flag int, chmod os.FileMode) (*FileHook, error) {
	plainFormatter := &logrus.TextFormatter{DisableColors: true}
	logFile, err := os.OpenFile(file, flag, chmod)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to write file on filehook %v", err)
		return nil, err
	}

	return &FileHook{logFile, flag, chmod, plainFormatter}, err
}

// Fire event
func (hook *FileHook) Fire(entry *logrus.Entry) error {
	var line string
	if plainformat, err := hook.formatter.Format(entry); err != nil {
		log.Printf("Formatter error: %+v", err)
		return err
	} else {
		line = string(plainformat)
	}
	if _, err := hook.file.WriteString(line); err != nil {
		fmt.Fprintf(os.Stderr, "unable to write file on filehook(entry.String)%v", err)
		return err
	}

	return nil
}

func (hook *FileHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	}
}

//NewGinWithLogrus - returns an Engine instance with the ginToLogrus and Recovery middleware already attached.
func NewMuxWithLogrus(log *logrus.Entry) *mux.Router {
	engine := mux.NewRouter()
	engine.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path    // path := c.Request.URL.Path
			raw := r.URL.RawQuery // raw := c.Request.URL.RawQuery

			// Process request
			next.ServeHTTP(w, r) // c.Next()

			clientIP := r.RemoteAddr //clientIP := c.ClientIP()
			method := r.Method       //method := c.Request.Method
			// statusCode := r.Response.StatusCode
			// errorMessage := r.Response. //errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

			if raw != "" {
				path = path + "?" + raw
			}

			log.Infof("| %15s | %-7s | %s",
				clientIP, method, path)

		})
	})
	// engine.Use(MuxToLogrus(log))
	return engine
}
