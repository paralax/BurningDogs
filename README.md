# BurningDogs

Tool to create OTX Pulse entries from honeypot logs

## Supported honeypots

BurningDogs reads honeypot logs and determines attacking client IPs, malicious URLs, and hashes of downloaded files, and then uploads that to [AlienVault OTX](https://otx.alienvault.com/browse/pulses/).   

### SSH honeypots

BurningDogs supports Kippo and Cowrie logfiles to detect malicious client IPs, downloaded files, and malicious URLs. 

### Apache 

BurningDogs uses the "wwwids" logfile analyzer to detect signs of web application abuse attempts. This is based in part on the principles in the SANS paper [Detecting Attacks on Web Applications from Log Files](https://www.sans.org/reading-room/whitepapers/logging/detecting-attacks-web-applications-log-files-2074). 

### phpMySqlAdmin

BurningDogs uses a custom PHP scipt (not included here) to detect abuse attempts of phpMySqlAdmin. Client IPs, URLs, and files are characterized. 

### Wordpot

BurningDogs uses a custom set of PHP scripts (not included here) to detect abuse attempts of Wordpress installations, including brute force intrusions and DDoS attempts via `xmlrpc.php` script abuse.

# Dependencies

BurningDogs depends on FAKE to build and NewtonSoft.Json for serialization. Use Paket to manage those via the `paket.dependencies` file.

# Building

BurningDogs uses FAKE to manage the build, simply issue a `fake` once dependencies are downloaded. 

# Running

I run BurningDogs via `cron` every night near midnight. 

# Modifying

Use the `application.config` file to manage paths, and you may have to edit code to address some of my local specifics (e.g. log file format).   