package amavis

import "os/exec"
import "log"

//Working with amavisd service via systemd
func OsService(action string) error{
  cmd := exec.Command("sudo", "amavisd", "-c", "/etc/amavisd/amavisd.conf", action)
  err := cmd.Run()
  if err!=nil{
    log.Print("Amavisd service "+action+" error: "+err.Error())
  }
  return err
}

//Working with amavisd-release
func AmavisdRelease(id, alt_recipients string)  error{
  cmd := exec.Command("sudo", "amavisd-release", id, alt_recipients)
  err := cmd.Run()
  log.Print(cmd)
  if err!=nil{
    log.Print("Amavisd-release error: "+err.Error())
  }
  return err
}
