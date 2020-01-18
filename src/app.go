package main

import ("conf"
        "api")

//Get application configuration and run server
func main() {
  const SMTA_VERSION = "1"
  //Get global SMTA configuration from file config.yaml:
  appConfig := conf.GetApp()
  //Running api service:
  api.RouterInit(appConfig, SMTA_VERSION)
}
