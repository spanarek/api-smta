//Http request handlers package
package api

import ("github.com/julienschmidt/httprouter"
        "net/http"
        "log"
        "api/general"
        "api/transport"
        "api/acl"
        "api/contentfilter")

//Basic authentication handler
func basicAuth(h httprouter.Handle, requiredUser, requiredPassword string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Get the Basic Authentication credentials
		user, password, hasAuth := r.BasicAuth()
    header := w.Header()
    header.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
    header.Set("Access-Control-Allow-Origin", "*")
    header.Set("Access-Control-Allow-Credentials", "true")
    header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if hasAuth && user == requiredUser && password == requiredPassword {
			// Delegate request to the given handle
			h(w, r, ps)
		} else {
			// Request Basic Authentication otherwise
			header.Set("WWW-Authenticate", "Basic realm=Restricted")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}
	}
}

//Initialization http server
func RouterInit(appConfig map[string]string, SMTA_VERSION string) {
  //Initialization requests config:
  router := httprouter.New()
  basicPath := "/smta/v"+SMTA_VERSION+"/"
  if appConfig["cors"] == "enabled" {
      router.GlobalOPTIONS = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Set CORS headers
        header := w.Header()
        header.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        header.Set("Access-Control-Allow-Origin", "*")
        header.Set("Access-Control-Allow-Credentials", "true")
        header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
      // Adjust status code to 204
      w.WriteHeader(http.StatusNoContent)
     })
  }

  router.GET(basicPath+"general/:name",
    basicAuth(general.GetHandler(appConfig["postfix_configs_path"]),
    appConfig["api_user"],
    appConfig["api_password"],))
  router.POST(basicPath+"general/:name",
    basicAuth(general.PostHandler(appConfig["postfix_configs_path"]),
    appConfig["api_user"],
    appConfig["api_password"],))
  router.GET(basicPath+"transport/:name",
    basicAuth(transport.GetHandler(appConfig["postfix_configs_path"]),
    appConfig["api_user"],
    appConfig["api_password"],))
  router.POST(basicPath+"transport/:name",
    basicAuth(transport.PostHandler(appConfig["postfix_configs_path"]),
    appConfig["api_user"],
    appConfig["api_password"],))
  router.GET(basicPath+"acl/:name",
    basicAuth(acl.GetHandler(appConfig["postfix_configs_path"], appConfig["amavisd_configs_path"]),
    appConfig["api_user"],
    appConfig["api_password"],))
  router.POST(basicPath+"acl/:name",
    basicAuth(acl.PostHandler(appConfig["postfix_configs_path"], appConfig["amavisd_configs_path"]),
    appConfig["api_user"],
    appConfig["api_password"],))
  router.GET(basicPath+"contentfilter/:name",
    basicAuth(contentfilter.GetHandler(appConfig["amavisd_configs_path"]),
    appConfig["api_user"],
    appConfig["api_password"],))
  router.POST(basicPath+"contentfilter/:name",
    basicAuth(contentfilter.PostHandler(appConfig["amavisd_configs_path"]),
    appConfig["api_user"],
    appConfig["api_password"],))

  log.Print("SMTA started.....")
  //Running service:
  switch appConfig["api_protocol"] {
  default:
    log.Fatal("Unsupported api protocol")
  case "http":
    log.Fatal(http.ListenAndServe(
    ":"+appConfig["api_port"],
    router))
  case "https":
    log.Fatal(http.ListenAndServeTLS(
      ":"+appConfig["api_port"],
      "/etc/ssl/certs/smta.crt",
      "/etc/ssl/private/smta.key",
      router))
  }
}
