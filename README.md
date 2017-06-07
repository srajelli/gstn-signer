```bash
usage: java -jar signer.jar <command> 
 -aspid <arg>       ASPID or CLIENTID provided from GSP
 -jks <arg>         your jks file path
 -new <arg>         will return new signed content
 -pass <arg>        password for jks file
 -timestamp <arg>   date + "%d%m%Y%H%M%S%N" | cut -b1-20
 -verify <arg>      verify previously generated signed content
```
