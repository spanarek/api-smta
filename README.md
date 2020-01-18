# API-SMTA

### REST API, written on Golang for management Postfix and Amavis.
Name of api parameters matched postfix main.cf and amavisd.conf

Full documentation for allowed API-methods and parameters see in [Swagger UI](https://editor.swagger.io/) files by location in [./swagger](swagger/)

### API description:
 - [/general](swagger/general.yaml): management MTA based parameters (double_bounce_sender, message_size_limit, etc..)
 - [/transport](swagger/transport.yaml): transport parameters (mynetworks, relay_domains, etc..)
 - [/contentfilter](swagger/contentfilter.yaml): contentfilter parameters and working with quarantine
 - [/acl](swagger/acl.yaml): tables\rules based on postfix access tables, amavis maps and amavis policy banks

#### Configuration:
 - resources/conf/smta/config.yaml

#### Security files:
 - resources/security/ssl/

#### Building binary in golang docker container:
```
#initial for make golang image
$ bash build.sh init
#next
$ bash build.sh
```
#### Manual building:
```
$ cd /path/to/cloned/project
$ export GOPATH=`pwd`
$ go build -o bin/smta src/app.go
```

#### References:
##### Libraries:
 - [julienschmidt/httprouter](https://github.com/julienschmidt/httprouter) BSD
 - [go-yaml/yaml](https://github.com/go-yaml/yaml) Apache 2.0
 - [fatih/structs](https://github.com/fatih/structs) MIT
 - [gijsbers/go-pcre](https://github.com/gijsbers/go-pcre) BSD
 - [gopkg.in/validator.v2](https://gopkg.in/validator.v2) Apache 2.0
