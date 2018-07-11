# eLitex
eLitex Service - HTTP Traffic Port Extension <br>
The service requires the deployment of eLitet DNS. 

# Install
- Refer to the binary [release](https://github.com/PantherJohn/eLitex/releases).
- Copy files in the archive to `%SystemRoot%\System32\`
- Create a local service with administrator privileges. 
```
sc create eLitex binpath= %SystemRoot%\System32\elitex.exe type= own start= auto DisplayName= "eLitex HTTP extension" 
sc description eLitex "DNS Based port forwarder for eLitet Insiders. If disabled, http:// access to subscribed websites will be refused."
``` 
- All set! Run a test if necessary
```
curl http://google.com
```

# Dependencies
- [Windivert](https://github.com/basil00/Divert)
- [curl](https://github.com/curl/curl) (optional)
- [eLitet DNS service](https://github.com/PantherJohn/eLitetDeployed)'s being configured. <br> Start off immediately [`here`](https://eltdpl.roycreatif.com/configure)

**&copy; Copyright eLitet Inc.**

