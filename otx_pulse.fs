// #I "Json80r3/Bin/Net40/"
// #r "Newtonsoft.Json.dll"
open System
open System.IO
open System.Security.Cryptography
open System.Text

open Newtonsoft.Json
open Newtonsoft.Json.Linq

type OtxIndicator = {
     Type : string; 
     indicator : string; 
     description : string
}

type OtxPulse = {
     name : string;
     description : string;
     Public : bool;
     TLP : string;
     indicators : OtxIndicator list;
     tags : string list;
     references : string list;
}

type WwwidsRule = {
    ref : string;
    cve : string;
    pat : string;
    checkurl: int;
    name : string;
}

// from http://www.fssnip.net/8j
/// Log levels.
let Error = 0
let Warning = 1
let Information = 2
let Debug = 3

let LevelToString level =
  match level with
    | 0 -> "Error"
    | 1 -> "Warning"
    | 2 -> "Information"
    | 3 -> "Debug"
    | _ -> "Unknown"

/// The current log level.
let mutable current_log_level = Debug

/// The inteface loggers need to implement.
type ILogger = abstract Log : int -> Printf.StringFormat<'a,unit> -> 'a

/// Writes to console.
let ConsoleLogger = { 
  new ILogger with
    member __.Log level format =
      Printf.kprintf (printfn "[%s][%A] %s" (LevelToString level) System.DateTime.Now) format
 }

/// Defines which logger to use.
let mutable DefaultLogger = ConsoleLogger

/// Logs a message with the specified logger.
let logUsing (logger: ILogger) = logger.Log

/// Logs a message using the default logger.
let log level message = logUsing DefaultLogger level message

// https://github.com/threatcrowd/ApiV2

type ThreatCrowdHashReport =  {
   response_code: string;
   md5: string;
   sha1: string;
   scans: string list;
   ips: string list;
   domains: string list;
   references: string list;
   permalink: string;}

type ThreatCrowdIpResolution = {
    last_resolved: string;
    domain: string;}

type ThreatCrowdIpReport = {
   response_code: string;
   resolutions: ThreatCrowdIpResolution list;
   hashes : string list;
   references: string list;
   votes: int;
   permalink: string;}

type ThreatCrowdEmailReport = {
   response_code: string;
   domains: string list;
   references: string list;
   permalink: string;}

type ThreatCrowdDomainResolution = {
    last_resolved: string;
    ip_address: string;}

type ThreatCrowdDomainReport = {
   response_code: string;
   resolutions: ThreatCrowdDomainResolution list;
   hashes: string list;
   emails: string list;
   subdomains: string list;
   references: string list;
   votes: int;
   permalink: string;}

type ThreatCrowdAVReport = {
   response_code: string;
   hashes: string list;
   references: string list;
   permalink: string;}

let downloadJson (url : string ) : string =
    let p = new Diagnostics.Process()
    p.StartInfo.FileName <- "/usr/bin/curl"
    p.StartInfo.Arguments <- String.Format("-s -k {0}", url)
    p.StartInfo.RedirectStandardOutput <- true
    p.StartInfo.UseShellExecute <- false
    p.Start() |> ignore
    p.StandardOutput.ReadToEnd()

let dataByHash(hash: string): ThreatCrowdHashReport = 
    let url = String.Format("https://www.threatcrowd.org/searchApi/v2/file/report/?resource={0}", hash)
    log 3 "%s" url
    let res = downloadJson url
    JsonConvert.DeserializeObject<ThreatCrowdHashReport>(res)

let dataByEmail(email: string) : ThreatCrowdEmailReport = 
    let url = String.Format("https://www.threatcrowd.org/searchApi/v2/email/report/?email={0}", email)
    log 3 "%s" url
    let res = downloadJson url
    JsonConvert.DeserializeObject<ThreatCrowdEmailReport>(res)

let dataByDomain(domain: string) : ThreatCrowdDomainReport = 
    let url = String.Format("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={0}", domain)
    log 3 "%s" url
    let res = downloadJson url
    JsonConvert.DeserializeObject<ThreatCrowdDomainReport>(res)

let dataByIp(ip: string) : ThreatCrowdIpReport = 
    let url = String.Format("https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={0}", ip)
    log 3 "%s" url
    let res = downloadJson url
    JsonConvert.DeserializeObject<ThreatCrowdIpReport>(res)

let dataByAntivirus(avname: string) : ThreatCrowdAVReport = 
    let url = String.Format("https://www.threatcrowd.org/searchApi/v2/antivirus/report/?antivirus={0}", avname)
    log 3 "%s" url
    let res = downloadJson url
    JsonConvert.DeserializeObject<ThreatCrowdAVReport>(res)


let config = File.ReadAllLines("application.config") 
             |> Array.map(fun x -> x.Split(':') |> Array.map (fun y -> y.Trim()))  
             |> Array.map(fun x -> (x.[0], x.[1]))
             |> Map.ofArray

let md5 (data : byte array) : string =
    use md5 = MD5.Create()
    (StringBuilder(), md5.ComputeHash(data))
    ||> Array.fold (fun sb b -> sb.Append(b.ToString("x2")))
    |> string

let sha1 (data : byte array) : string =
    use sha1 = SHA1.Create()
    (StringBuilder(), sha1.ComputeHash(data))
    ||> Array.fold (fun sb b -> sb.Append(b.ToString("x2")))
    |> string

let sha256 (data : byte array) : string =
    use sha256 = SHA256.Create()
    (StringBuilder(), sha256.ComputeHash(data))
    ||> Array.fold (fun sb b -> sb.Append(b.ToString("x2")))
    |> string

let urlpat = RegularExpressions.Regex("(ftp://[^ ;\"]*[ \"]|http://[^ ;\"]*)[ \";$>)&]?")
let matchToUrl (urlMatch : RegularExpressions.Match) = urlMatch.Value.Trim().Replace("\"", "").Replace(";", "").Replace(")", "").Replace(">", "")
let getUrl (row : string) : seq<string> = 
    let matches = urlpat.Matches(row)
    Seq.map matchToUrl (Seq.cast matches)

let ippat = RegularExpressions.Regex("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
let matchToIp (ipMatch: RegularExpressions.Match) = ipMatch.Value.Trim()
let getIp (code : string) : seq<string> =
    let matches = ippat.Matches(code)
    Seq.map matchToIp (Seq.cast matches)

let ipToIndicator (ipstr: string) (description: string) : OtxIndicator =
    let ip = Net.IPAddress.Parse(ipstr)
    match ip.AddressFamily.ToString() with
    | "InterNetworkV6" -> {Type = "IPv6"; indicator = ip.ToString(); description = description}
    | "InterNetwork"   -> {Type = "IPv4"; indicator = ip.ToString(); description = description}

let isIrcBot(code: string) : bool =
    code.Contains("NICK") && code.Contains("JOIN")

let botToServer(code: string) : seq<string> =
    code.Split(' ')                                                     // tokenize 
    |> Seq.windowed 5 
    |> Seq.filter(fun x -> (String.concat " " x).Contains("server"))    // find things near the server specification
    |> Seq.concat 
    |> Set.ofSeq 
    |> Seq.map getIp 
    |> Seq.filter (fun x -> Seq.length x > 0) 
    |> Seq.concat

let botToIndicator(code: byte array) : OtxIndicator list =
    match isIrcBot (Encoding.ASCII.GetString code) with
    | false -> []
    | true  -> Encoding.ASCII.GetString code 
               |> botToServer 
               |> Seq.map(fun x -> ipToIndicator x ("Possible IRC server for " + (md5 code))) 
               |> List.ofSeq

let fileToIndicator (data: byte array) (description: string) : OtxIndicator list =
    [(md5, "FileHash-MD5"); (sha1, "FileHash-SHA1"); (sha256, "FileHash-SHA256")] 
    |> List.map (fun (fn, fntype) -> (fn data, fntype)) 
    |> List.map (fun (ind, indtype) -> {Type = indtype; indicator = ind; description = description})

let tryDownload(url : string) : byte [] option =
    try
        let client = new System.Net.WebClient()
        Some(client.DownloadData(url))
    with 
    | :? System.Net.WebException as ex -> None

let createDir(dirname: string) : DirectoryInfo = 
    let p = new Diagnostics.Process()
    p.StartInfo.FileName <- "/bin/mkdir"
    p.StartInfo.Arguments <- String.Format("-p {0}", dirname)
    p.StartInfo.RedirectStandardOutput <- true
    p.StartInfo.UseShellExecute <- false
    p.Start() |> ignore
    p.StandardOutput.ReadToEnd() |> ignore
    new DirectoryInfo(dirname)

let storeMalware(data : byte []) : string = 
    let h = sha256 data
    let a = h.ToCharArray()
    let dir = createDir(String.Format("{0}/{1}/{2}/{3}/{4}", config.["malwaredir"], a.[0], a.[1], a.[2], a.[3]))
    let filename = String.Format("{0}/{1}", dir.FullName, h)
    use f = StreamWriter(filename)
    f.Write(data)
    f.Close()
    filename

let urlToIndicators (urlstr: string) (description: string) : OtxIndicator list =
    let url = new Uri(urlstr)
    let domainToIndicator (uri: Uri) : OtxIndicator list =
        { Type = "hostname"; indicator = uri.Host; description = ("Hostname associated with " + description)}::( Array.map (fun x -> ipToIndicator (x.ToString()) ("IP address associated with " + description)) (Net.Dns.GetHostAddresses(uri.Host)) |> List.ofArray)
    let netlocToIndicator (uri: Uri) : OtxIndicator list = 
        match uri.HostNameType.ToString() with
        | "Dns" -> domainToIndicator uri
        | _     -> [ ipToIndicator uri.Host ("IP addresses associated with " + description) ]
    {Type = "URL"; indicator = url.ToString(); description = description}::(netlocToIndicator url)

let kippologs : OtxPulse = 
    let today = DateTime.Today.ToString("yyyy-MM-dd")
    // 2016-06-17 13:29:13-0400 [kippo.core.honeypot.HoneyPotSSHFactory] New connection: 211.94.188.90:9224 (192.168.1.144:2222) [session: 4159]
    let a = File.ReadAllLines(config.["kippolog"])
            |> Array.filter(fun x -> x.StartsWith(today))
    let b = File.ReadAllLines(config.["kippolog1"]) 
            |> Array.filter(fun x -> x.StartsWith(today))
    let lines = [a;b] |> Array.concat
    let ips = lines
              |> Array.filter(fun x -> x.Contains("New connection"))
              |> Array.map(fun x -> x.Split(' ').[4])
              |> Array.map(fun x -> x.Split(':').[0])
              |> Set.ofArray
              |> Set.map(fun x -> ipToIndicator x "SSH bruteforce client IP")
              |> Set.toList
    let urls = lines
               |> Array.map getUrl 
               |> Seq.concat 
               |> Set.ofSeq
               |> Seq.toList
               |> List.map (fun x -> urlToIndicators x "URL injected into SSH honeypot") 
               |> List.concat
               |> Set.ofList
               |> Set.toList
    let dir = new DirectoryInfo(config.["kippodldir"])
    let today = DateTime.Today.ToString("M/d/yyyy")
    let files  = dir.GetFiles() 
                 |> Array.filter(fun x -> x.LastWriteTime.ToString().StartsWith(today))
                 |> Array.map(fun x -> System.IO.File.ReadAllBytes(x.FullName))
    let filehashes = files 
                     |> Array.map(fun x -> fileToIndicator x "SSH honeypot downloaded file")
                     |> Seq.concat
                     |> Seq.toList
                     |> Set.ofList
                     |> Set.toList
    let ircservers = files 
                     |> Array.map botToIndicator 
                     |> Seq.concat
                     |> Set.ofSeq
                     |> Set.toList
    {name = "SSH honeypot logs for " + today; 
     Public = true; 
     tags = ["SSH"; "bruteforce"; "honeypot"]; 
     references = []; 
     TLP = "green"; 
     description = "SSH honeypot logs for brute force attackers from a US /32";
     indicators = ips @ filehashes @ urls @ ircservers}

let pmalogs : OtxPulse = 
    let today = DateTime.Today.ToString("yyyy-MM-dd")
    let lines = File.ReadAllLines(config.["phpmyadminlog"])
                |> Array.filter(fun x -> x.StartsWith(today))
                |> Array.filter(fun x -> x.Length > 100)
                |> Array.map(fun x -> x.Replace("\\", ""))
    let ips  = lines
               |> Array.map(fun x -> x.Split(' ').[1])
               |> Set.ofArray
               |> Set.map(fun x -> ipToIndicator x "phpMyAdmin attacker client IP")
               |> Set.toList
    let urls = lines
               |> Array.map(fun x -> getUrl x)
               |> Seq.concat
               |> Set.ofSeq
               |> Set.map(fun x -> {Type = "URL"; indicator = x; description = "phpMyAdmin injected URL"})
               |> Set.toList
    let contents = urls
                 |> List.map(fun x -> tryDownload x.indicator)
                 |> List.choose id
    let _ = contents 
            |> List.map storeMalware
    let filehashes = contents 
                     |> List.map(fun x -> fileToIndicator x "phpMyAdmin injected malware hash")
                     |> Seq.concat
                     |> Seq.toList
                     |> Set.ofList
                     |> Set.toList
    let ircservers = contents 
                     |> List.map botToIndicator 
                     |> List.concat
                     |> Set.ofList
                     |> Set.toList
    {name = "phpMyAdmin honeypot logs for " + today;
     Public = true;
     tags = ["phpMyAdmin"; "honeypot"];
     references = [];
     TLP = "green";
     description = "phpMyAdmin honeypot logs from a US /32";
     indicators = ips @ urls @ filehashes @ ircservers}                

let wordpotlogs : OtxPulse = 
    let today = DateTime.Today.ToString("yyyy-MM-dd")
    let lines = File.ReadAllLines(config.["wordpotlog"])
                |> Array.filter(fun x -> x.StartsWith(today))
    let ips = lines 
              |> Array.map(fun x -> x.Split(' ').[1])
              |> Set.ofArray
              |> Set.map(fun x -> ipToIndicator x "WordPress bruteforce login client IP")
              |> Set.toList
    let lines = File.ReadAllLines(config.["xmlrpc_ddoslog"])
                |> Array.filter(fun x -> x.StartsWith(today))
    let ddosips = lines 
                  |> Array.map(fun x -> x.Split(' ').[1])
                  |> Set.ofArray
                  |> Set.map(fun x -> ipToIndicator x "WordPress xmlrpc.php DDoS client IP")
                  |> Set.toList
    let ddosvictims = lines
                      |> Array.map(fun x -> x.Split(' ').[4])
                      |> Array.map(fun x -> urlToIndicators x "Wordpress xmlrpc.php DDoS victim" )
                      |> List.concat
                      |> Set.ofList
                      |> Set.toList
    {name = "WordPress honeypot logs for " + today;
     Public = true;
     tags = ["wordpress"; "honeypot"; "bruteforce"];
     references = [];
     TLP = "green";
     description = "WordPress honeypot logs for DDoS tracking and authentcation brute force from a US /32";
     indicators = ips @ ddosips @ ddosvictims}     

let apachelogs : OtxPulse =     
    let today = DateTime.Today.ToString("dd/MMM/yyyy")
    let lines = File.ReadAllLines(config.["accesslog"])
                |> Array.filter(fun x -> x.Contains("[" + today))
    let rules_json = File.ReadAllText(config.["wwwids_rules"])
    let rules = JsonConvert.DeserializeObject<WwwidsRule list>(rules_json)
    let checkOneRule(rule:WwwidsRule) (row:string []) : (WwwidsRule * string []) option = 
        match row.[6].Contains(rule.pat) || row.[11].Contains(rule.pat) with
        | true  -> Some(rule, row)
        | false -> None
    let checkRules (rules:WwwidsRule list) (row:string []) : (WwwidsRule * string []) option list =
        List.map(fun x -> checkOneRule x row) rules
    let checkedRowToIndicator(rule:WwwidsRule, row:string []) : OtxIndicator =
        ipToIndicator row.[0] (rule.name + " attempt client IP")
    let rulehits = lines
                   |> Array.map(fun x -> x.Split([|' '|], 12)) 
                   |> Array.filter (fun x -> x.[8].StartsWith("40"))
                   |> Array.map(fun x -> checkRules rules x) 
                   |> Seq.concat
                   |> Seq.choose id
    let indicators = rulehits
                     |> Seq.map checkedRowToIndicator
                     |> Set.ofSeq
                     |> Set.toList
    let unwind rule urls = Seq.map (fun x -> (rule, x)) urls                      
    let urls = rulehits
                |> Seq.filter(fun (rule, _) -> rule.checkurl > -1)
                |> Seq.map(fun (rule, row) -> (rule, getUrl row.[rule.checkurl])) 
                |> Seq.map(fun (rule, urls) -> unwind rule urls) 
                |> Seq.concat 
                |> Set.ofSeq                 
                |> Set.toList
                |> List.map(fun (rule, x) ->  urlToIndicators x ("Injected URL - " + rule.name))
                |> List.concat
                |> Set.ofList
                |> Seq.toList
    let contents = urls
                    |> List.map(fun x -> tryDownload x.indicator)
                    |> List.choose id
    let _ = contents 
            |> List.map storeMalware
    let fileindicators = contents
                         |> Seq.map(fun x -> fileToIndicator x "Injected URL file hash")
                         |> Seq.concat
                         |> Set.ofSeq
                         |> Set.toList
    let ircservers = contents 
                     |> List.map botToIndicator 
                     |> List.concat                         
    {name = "Apache honeypot logs for " + today;
     Public = true;
     tags = ["apache"; "honeypot"; "exploits"];
     references = [];
     TLP = "green";
     description = "Apache honeypot logs for common exploit attempts from a US /32";
     indicators = indicators @ fileindicators @ ircservers @ urls}

let upload (otx: OtxPulse) = 
    log 2 "uploading ..."
    let json = JsonConvert.SerializeObject(otx).Replace("Type", "type").Replace("Public", "public")
    log 3 "%s" json
    use wc = new Net.WebClient()
    wc.Headers.Add("X-OTX-API-KEY", config.["apikey"])
    wc.Headers.Set("User-Agent", "OTX .Net SDK")
    wc.Headers.Set("Content-Type", "application/json")
    try
        let reply = wc.UploadString("https://otx.alienvault.com:443/api/v1/pulses/create", json)
        log 3 "%A" reply
    with
    | :? System.Net.WebException as ex -> log 0 "%A" ex
    ()

[<EntryPoint>]
let main args =
    let results = [kippologs; pmalogs; wordpotlogs; apachelogs;]
                  |> List.filter (fun x -> List.length (x.indicators) > 0)
    match Array.tryFind (fun x -> x = "-d") args with
    | None    -> List.map (fun x -> upload x) results |> ignore
    | Some(_) -> List.iter (fun x -> printfn "%A" x) results |> ignore
    0
