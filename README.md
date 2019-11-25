# HTTP Request Smuggler Scanner

This is an extension for Burp Suite designed to help you launch [HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling) attacks, originally created during [HTTP Desync Attacks](https://portswigger.net/blog/http-desync-attacks-request-smuggling-reborn) research. It supports scanning for Request Smuggling vulnerabilities, and also aids exploitation by handling cumbersome offset-tweaking for you.

This extension should not be confused with [Burp Suite HTTP Smuggler](https://github.com/nccgroup/BurpSuiteHTTPSmuggler), which uses similar techniques but is focused exclusively bypassing WAFs.

### Install
If you prefer to load the jar manually, in Burp Suite (community or pro), use `Extender -> Extensions -> Add` to load `build/libs/http-request-smuggle-scanner.jar`

### Compile
* Build with `gradle fatJar`

