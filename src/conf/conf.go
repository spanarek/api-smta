//Working whith application configurations
package conf

import ("io/ioutil"
        "github.com/go-yaml/yaml"
        "log")

//Get main configurations from config.yaml file
func GetApp() map[string]string {
  //Read file from config file to buffer:
  content, err := ioutil.ReadFile("/etc/smta/config.yaml")
  if err != nil {
    log.Fatal(err)
  }
  //Create configuration map from buffer via yaml:
  configs := map[string]string{}
  err = yaml.Unmarshal(content, configs)
  if err !=nil {
    log.Fatal(err)
  }

  return configs
}
