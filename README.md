# BurningDogs

Tool to create OTX Pulse entries from honeypot logs

## Supported honeypots

BurningDogs reads honeypot logs and determines attacking client IPs, malicious URLs, and hashes of downloaded files, and then uploads that to [AlienVault OTX](https://otx.alienvault.com/browse/pulses/).   

### SSH honeypots

BurningDogs supports Kippo and Cowrie logfiles to detect malicious client IPs, downloaded files, and malicious URLs. 

### Apache 

BurningDogs uses the "wwwids" logfile analyzer to detect signs of web application abuse attempts. This is based in part on the principles in the SANS paper [Detecting Attacks on Web Applications from Log Files](https://www.sans.org/reading-room/whitepapers/logging/detecting-attacks-web-applications-log-files-2074). 

### phpMySqlAdmin

BurningDogs uses a custom PHP scipt (see the [ShoppingLeague repository](https://github.com/paralax/ShoppingLeague)) to detect abuse attempts of phpMySqlAdmin. Client IPs, URLs, and files are characterized. 

### Wordpot

BurningDogs uses a custom set of PHP scripts (see the [ShoppingLeague repository](https://github.com/paralax/ShoppingLeague)) to detect abuse attempts of Wordpress installations, including brute force intrusions and DDoS attempts via `xmlrpc.php` script abuse.

### Redispot

BurningDogs uses the Redis honeypot from [NoSQLpot](https://github.com/torque59/nosqlpot) to detect brute force authentication abuse attempts. Client IPs and URLs are characterized.

### VncLowPot

BurningDogs uses the VNC honeypot from [vnclowpot](https://github.com/magisterquis/vnclowpot) to detect brute force authentication attempts.

### Pghoney

BurningDocs uses the PostgreSQL honeypot from [pghoney](https://github.com/betheroot/pghoney) to detect brute force authentication attempts. 

# Dependencies

You'll need to [sign up at OTX](https://otx.alienvault.com/api/) to get an API key to upload pulses.

BurningDogs depends on FAKE to build and NewtonSoft.Json for serialization. Use Paket to manage those via the `paket.dependencies` file.

# Building

BurningDogs uses FAKE to manage the build, simply issue a `fake` once dependencies are downloaded. 

# Running

I run BurningDogs via `cron` every night near midnight. 

# Modifying

Use the `application.config` file to manage paths, and you may have to edit code to address some of my local specifics (e.g. log file format).   
