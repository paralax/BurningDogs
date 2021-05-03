open System
open System.IO
open System.Net
open System.Security.Cryptography
open System.Text
open System.Web

open Newtonsoft.Json
open Newtonsoft.Json.Linq

open Log

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

type CowrieRecord = {
    dst_ip : string;
    dst_port : int;
    eventid : string;
    isError : int;
    message : string;
    outfile : string;
    sensor : string;
    session : string;
    shasum : string;
    mutable src_ip : string;
    src_port : int;
    mutable system : string;
    timestamp : string;
    url : string;
}

type WwwidsRule = {
    ref : string;
    cve : string;
    pat : string;
    checkurl: int;
    name : string;
}

type PghoneyRecord = {
  level : string;
  msg : string;
  source_ip : string;
  source_port : int;
  time : string;
  username: string;
}

type BackdoorRecordPayload = {
  timestamp : string;
  client_ip : string;
  user_agent : string;
  headers : Map<string, string>;
  payload : Map<string, string>;
}

let config = File.ReadAllLines("application.config")
             |> Array.map(fun x -> x.Split(':') |> Array.map (fun y -> y.Trim()))
             |> Array.map(fun x -> (x.[0], x.[1]))
             |> Map.ofArray

let exemptions = File.ReadAllLines(config.["exemptions"])
                 |> Set.ofArray

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
    let matches = urlpat.Matches(HttpUtility.UrlDecode(row))
    Seq.map matchToUrl (Seq.cast matches)

let ippat = RegularExpressions.Regex("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
let getMatches (ipMatch: RegularExpressions.Match) = ipMatch.Value.Trim()
let getIp (code : string) : seq<string> =
    let matches = ippat.Matches(code)
    Seq.map getMatches (Seq.cast matches)

let ipportpat = RegularExpressions.Regex("([0-9]{1,3}\.){3}[0-9]{1,3}:\d+")
let getIpPort (code: byte []) : seq<string> =
    let matches = ipportpat.Matches(Encoding.ASCII.GetString(code))
    Seq.map getMatches (Seq.cast matches)

let ipToIndicator (ipstr: string) (description: string) : OtxIndicator option =
    try
        let ip = Net.IPAddress.Parse(ipstr)
        match ip.AddressFamily.ToString() with
        | "InterNetworkV6" -> Some({Type = "IPv6"; indicator = ipstr; description = description})
        | "InterNetwork"   -> Some({Type = "IPv4"; indicator = ipstr; description = description})
    with
    | :? FormatException as ex -> None
    | :? System.ArgumentNullException as ex -> None

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
               |> Seq.choose id
               |> List.ofSeq

let fileToIndicator (data: byte array) (description: string) : OtxIndicator list =
    [(md5, "FileHash-MD5"); (sha1, "FileHash-SHA1"); (sha256, "FileHash-SHA256")]
    |> List.map (fun (fn, fntype) -> (fn data, fntype))
    |> List.map (fun (ind, indtype) -> {Type = indtype; indicator = ind; description = description})

(* 
let tryDownload(url : string) : byte [] option =
    try
        let client = new Net.WebClient()
        Some(client.DownloadData(url))
    with
    | :? Net.WebException as ex -> None
*)

(* 
// try this instead http://furuya02.hatenablog.com/entry/20111121/1321834314 
let myCallback (reader:IO.BinaryReader) url = 
    let rec loop (sofar: byte []) : byte [] =
         let data = reader.ReadBytes(1024)
         match data.Length with
         | 0 -> data
         | _ -> loop (Array.append sofar data)
    loop (reader.ReadBytes(1024))
*)
        
let tryDownload(url : string) : byte [] option =
    let doFetch callback url =
        let req = WebRequest.Create(Uri(url))
        req.Timeout <- 5000    
        use resp = req.GetResponse()
        use stream = resp.GetResponseStream()
        use reader = new IO.BinaryReader(stream)
        callback reader (resp.ContentLength) url

    let myCallback (reader:IO.BinaryReader) len url = reader.ReadBytes(int len)
    let fetchUrl = doFetch myCallback
    
    log 3 ">>>> tryDownload %s" url

    try
        Some(fetchUrl url)
    with
    | :? Net.WebException as ex -> None  
    | :? System.UriFormatException as ex -> None  
    | :? System.ArgumentNullException as ex -> None
    | :? System.ArgumentOutOfRangeException as ex -> None
    
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
    File.WriteAllBytes(filename, data)
    filename

let urlToIndicators (urlstr: string) (description: string) : OtxIndicator list =
    log 3 ">>>> urlToIndicators - %s" urlstr
    try
        let url = new Uri(urlstr.Split('\n').[0])
        let domainToIndicator (uri: Uri) : OtxIndicator list =
            try
                { Type = "hostname"; indicator = uri.Host; description = ("Hostname associated with " + description)}::( Array.map (fun x -> ipToIndicator (x.ToString()) ("IP address associated with " + description)) (Net.Dns.GetHostAddresses(uri.Host)) |> Array.choose id |> List.ofArray)
            with
            | :? Net.Sockets.SocketException as ex -> [{ Type = "hostname"; indicator = uri.Host; description = ("Hostname associated with " + description)}]
            | :? StackOverflowException as ex -> []
        let netlocToIndicator (uri: Uri) : OtxIndicator list =
            match uri.HostNameType.ToString() with
            | "Dns" -> domainToIndicator uri
            | _     -> List.choose id [ ipToIndicator uri.Host ("IP addresses associated with " + description) ]
        match Set.contains (url.Host) exemptions with
        | true  -> []
        | false -> {Type = "URL"; indicator = urlstr; description = description}::(netlocToIndicator url)        
    with
    | :? UriFormatException as ex -> []
    | :? StackOverflowException as ex -> []
    | :? System.ArgumentNullException as ex -> []

    
let getKippoRecords (system : string): CowrieRecord list =
    let convertLine (line:string) : CowrieRecord = JsonConvert.DeserializeObject<CowrieRecord>(line)
    (* we have to do this because records that show downloads don't have the system field, wtf *)
    let rewriteNullSystem (r : CowrieRecord) : CowrieRecord =
        match r.system with
        | null -> { r with system = ""}
        | _    -> r
    let rewriteSrcIp (r : CowrieRecord) : CowrieRecord = 
        {r with src_ip = r.src_ip.Replace("::ffff:", "") }
    let records = File.ReadAllLines(config.["kippojson"])
                    |> Array.map convertLine
                    |> List.ofArray
                    |> List.map rewriteNullSystem
                    |> List.map rewriteSrcIp
                    |> List.filter (fun x -> x.system.Contains(system) || x.eventid.Contains("cowrie.session.file_download"))
    let sessions = records 
                   |> List.map (fun x -> x.session)
                   |> Set.ofList
                   |> Set.filter (fun x -> x <> null)
    records
    |> List.filter (fun x -> Set.contains x.session sessions = true)

(* we do it this way to make sure we don't block on fetching 
    content from websites that causes a delay, and logs roll over.
    *)
let telnets = getKippoRecords "Telnet"
let sshs = getKippoRecords "SSH"

let telnetlogs (date:DateTime): OtxPulse =
    log 3 ">>> telnetlogs"
    let today = date.ToString("yyyy-MM-dd")
    let records = telnets
    let ips = records
              |> List.map (fun x -> x.src_ip)
              |> Set.ofList
              |> Set.map(fun x -> ipToIndicator x "Telnet bruteforce client IP")
              |> Set.toList
              |> List.choose id
    log 3 ">>> read IPs"
    let urls = records 
               |> List.map (fun x -> x.url)
               |> List.filter (fun x -> x <> null && x <> "redir")
               |> Set.ofList
               |> Set.toSeq
               |> Seq.map (fun x -> urlToIndicators x "URL injected into Telnet honeypot")
               |> List.concat
               |> Set.ofList
               |> Set.toList
    log 3 ">>> read urls"
    let contents = urls
                 |> List.map(fun x -> tryDownload x.indicator)
                 |> List.choose id
    log 3 ">>> read first contents"
    let extraurls = contents
                    |> List.map (fun x -> Encoding.ASCII.GetString x)
                    |> List.map getUrl
                    |> Seq.concat
                    |> Set.ofSeq
                    |> Set.toSeq
                    |> Seq.map (fun x -> urlToIndicators x "URL injected into Telnet honeypot")
                    |> List.concat
    log 3 ">>> read extraurls"
    let contents = extraurls
                     |> List.map(fun x -> tryDownload x.indicator)
                     |> List.choose id
    log 3 ">>> read second contents"
    let _ = contents
            |> List.map storeMalware
    log 3 ">>> stored contents"
    let filehashes = contents
                     |> List.map(fun x -> fileToIndicator x "Telnet honeypot downloaded file")
                     |> Seq.concat
                     |> Set.ofSeq
                     |> Set.toList
    log 3 ">>> hashed files"
    let c2indicators = contents
                       |> List.map getIpPort
                       |> Seq.concat
                       |> Seq.distinct
                       |> Seq.map (fun x -> x.Split(':'))
                       |> Seq.map (fun [|x; y|] -> ipToIndicator x ("Suspected malware C2 on port " + y))
                       |> Seq.toList
                       |> List.choose id
    log 3 ">>> got c2 indicators"
    let allurls = urls @ extraurls
                  |> Set.ofList
                  |> Set.toList
    GC.Collect()
    {name = "Telnet honeypot logs for " + today;
     Public = true;
     tags = ["Telnet"; "bruteforce"; "honeypot"];
     references = [];
     TLP = "green";
     description = "Telnet honeypot logs for brute force attackers from a US /32";
     indicators = List.filter (fun x -> Set.contains x.indicator exemptions <> true) (ips @ allurls @ filehashes @ c2indicators)}

let kippologs (date:DateTime): OtxPulse =
    log 3 ">>> kippologs"
    let today = date.ToString("yyyy-MM-dd")
    // 2016-11-03T09:21:29-0400 [cowrie.ssh.factory.CowrieSSHFactory] New connection: 42.114.236.213:63526 (::ffff:192.168.1.50:2222) [session: a4f8ed71]
    let records = sshs
    let ips = records
              |> List.map (fun x -> x.src_ip)
              |> Set.ofList
              |> Set.map(fun x -> ipToIndicator x "SSH bruteforce client IP")
              |> Set.toList
              |> List.choose id
    log 3 ">>> read IPs"
    let urls = records 
               |> List.map (fun x -> x.url)
               |> List.filter (fun x -> x <> null && x <> "redir")
               |> Set.ofList
               |> Set.toSeq
               |> Seq.map (fun x -> urlToIndicators x "URL injected into SSH honeypot")
               |> List.concat
               |> Set.ofList
               |> Set.toList
    let contents = urls
                    |> List.map(fun x -> tryDownload x.indicator)
                    |> List.choose id
    log 3 ">>>> now calling fileToIndicator on downloaded content"
    let dlfilehashes = contents
                        |> List.map(fun x -> fileToIndicator x "SSH honeypot downloaded file")
                        |> Seq.concat
                        |> Set.ofSeq
                        |> Set.toList
    let dir = new DirectoryInfo(config.["kippodldir"])
    let todaystr = date.ToString("yyyyMMdd*")
    log 3 ">>>> gathering today's files for analysis"
    let files  = dir.EnumerateFiles(todaystr)
                 |> Seq.toList
                 |> List.filter(fun x -> x.FullName.Contains("-redir__var") <> true && x.Length > 0L)
                 |> List.map(fun x -> File.ReadAllBytes(x.FullName))
    log 3 ">>>> now hashing today's files"
    let filehashes = files
                     |> List.map(fun x -> fileToIndicator x "SSH honeypot downloaded file")
                     |> Seq.concat
                     |> Set.ofSeq
                     |> Set.toList
    log 3 ">>>> now looking for today's IRC servers"
    let ircservers = files
                     |> List.map botToIndicator
                     |> Seq.concat
                     |> Set.ofSeq
                     |> Set.toList
    GC.Collect()
    {name = "SSH honeypot logs for " + date.ToString("yyyy-MM-dd");
     Public = true;
     tags = ["SSH"; "bruteforce"; "honeypot"];
     references = [];
     TLP = "green";
     description = "SSH honeypot logs for brute force attackers from a US /32";
     indicators = List.filter (fun x -> Set.contains x.indicator exemptions <> true) (ips @ filehashes @ dlfilehashes @ urls @ ircservers)}

let pmalogs (date:DateTime): OtxPulse =
    log 3 ">>> pmalogs"
    let today = date.ToString("yyyy-MM-dd")
    let lines = File.ReadAllLines(config.["phpmyadminlog"])
                |> Array.filter(fun x -> x.StartsWith(today))
                |> Array.filter(fun x -> x.Length > 100)
                |> Array.map(fun x -> x.Replace("\\", ""))
    let ips  = lines
               |> Array.map(fun x -> x.Split(' ').[1])
               |> Set.ofArray
               |> Set.toList
               |> List.map(fun x -> ipToIndicator x "phpMyAdmin attacker client IP")
               |> List.choose id
    let urls = lines
               |> Array.map getUrl
               |> Seq.concat
               |> Seq.distinct
               |> Seq.map(fun x -> urlToIndicators x "URL injected into phpMyAdmin page")
               |> Seq.toList
               |> List.concat
    let contents = urls
                 |> List.map(fun x -> tryDownload x.indicator)
                 |> List.choose id
    let _ = contents
            |> List.map storeMalware
    let filehashes = contents
                     |> List.map(fun x -> fileToIndicator x "phpMyAdmin injected malware hash")
                     |> Seq.concat
                     |> Seq.distinct
                     |> Seq.toList
    let ircservers = contents
                     |> List.collect botToIndicator
                     |> Set.ofList
                     |> Set.toList
    GC.Collect()
    {name = "phpMyAdmin honeypot logs for " + today;
     Public = true;
     tags = ["phpMyAdmin"; "honeypot"];
     references = [];
     TLP = "green";
     description = "phpMyAdmin honeypot logs from a US /32";
     indicators = List.filter (fun x -> Set.contains x.indicator exemptions <> true) (ips @ urls @ filehashes @ ircservers)}

let wordpotlogs (date:DateTime): OtxPulse =
    log 3 ">>> wordpotlogs"
    let today = date.ToString("yyyy-MM-dd")
    let lines = File.ReadAllLines(config.["wordpotlog"])
                |> Array.filter(fun x -> x.StartsWith(today))
    let ips = lines
              |> Array.map(fun x -> x.Split(' ').[1])
              |> Set.ofArray
              |> Set.toList
              |> List.map(fun x -> ipToIndicator x "WordPress bruteforce login client IP")
              |> List.choose id
    let lines = File.ReadAllLines(config.["xmlrpc_ddoslog"])
                |> Array.filter(fun x -> x.StartsWith(today))
    let ddosips = lines
                  |> Array.map(fun x -> x.Split(' ').[1])
                  |> Set.ofArray
                  |> Set.toList
                  |> List.map(fun x -> ipToIndicator x "WordPress xmlrpc.php DDoS client IP")
                  |> List.choose id
    let ddosvictims = lines
                      |> Array.map(fun x -> x.Split(' ').[4])
                      |> Array.map(fun x -> urlToIndicators x "Wordpress xmlrpc.php DDoS victim" )
                      |> List.concat
                      |> Set.ofList
                      |> Set.toList
    GC.Collect()
    {name = "WordPress honeypot logs for " + today;
     Public = true;
     tags = ["wordpress"; "honeypot"; "bruteforce"];
     references = [];
     TLP = "green";
     description = "WordPress honeypot logs for DDoS tracking and authentcation brute force from a US /32";
     indicators = List.filter (fun x -> Set.contains x.indicator exemptions <> true) (ips @ ddosips @ ddosvictims)}

let apachelogs (date:DateTime): OtxPulse =
    log 3 ">>> apachelogs"
    let today = date.ToString("dd/MMM/yyyy")
    let a = File.ReadAllLines(config.["accesslog"])
            |> Array.filter(fun x -> x.Contains("[" + today))
    let b = File.ReadAllLines(config.["accesslog"] + ".0")
            |> Array.filter(fun x -> x.Contains("[" + today))
    let lines = [| a; b |] |> Array.concat
    let rules_json = File.ReadAllText(config.["wwwids_rules"])
    let rules = JsonConvert.DeserializeObject<WwwidsRule list>(rules_json)
    let checkOneRule(rule:WwwidsRule) (row:string []) : (WwwidsRule * string []) option =
        match Web.HttpUtility.UrlDecode(row.[6]).Contains(rule.pat) || Web.HttpUtility.UrlDecode(row.[11]).Contains(rule.pat) with
        | true  -> Some(rule, row)
        | false -> None
    let checkRules (rules:WwwidsRule list) (row:string []) : (WwwidsRule * string []) option list =
        List.map(fun x -> checkOneRule x row) rules
    let checkedRowToIndicator(rule:WwwidsRule, row:string []) : OtxIndicator option =
        try
            let ip = Net.IPAddress.Parse(row.[0])
            ipToIndicator (ip.ToString()) (rule.name + " attempt client IP")
        with
        | :? StackOverflowException as ex -> None
    let rulehits = lines
                   |> Array.map(fun x -> x.Split([|' '|], 12))
                   |> Array.filter (fun x -> x.[8].StartsWith("40"))
                   |> Array.map(fun x -> checkRules rules x)
                   |> Seq.concat
                   |> Seq.choose id
    let indicators = rulehits
                     |> Seq.map checkedRowToIndicator
                     |> Seq.choose id
                     |> Set.ofSeq
                     |> Set.toList
    let unwind rule urls = Seq.map (fun x -> (rule, x)) urls
    let urls = rulehits
                |> Seq.filter(fun (rule, _) -> rule.checkurl > -1)
                |> Seq.map(fun (rule, row) -> (rule, getUrl (Uri.UnescapeDataString(row.[rule.checkurl]))))
                |> Seq.collect (fun (rule, urls) -> unwind rule urls)
                |> Set.ofSeq
                |> Set.toList
                |> List.collect (fun (rule, x) ->  urlToIndicators x ("Injected URL - " + rule.name))
                |> Set.ofList
                |> Seq.toList
    let contents = urls
                    |> List.map(fun x -> tryDownload x.indicator)
                    |> List.choose id
    let _ = contents
            |> List.map storeMalware
    let fileindicators = contents
                         |> Seq.collect (fun x -> fileToIndicator x "Injected URL file hash")
                         |> Set.ofSeq
                         |> Set.toList
    let ircservers = contents
                     |> List.collect botToIndicator
    let errorclients = lines
                       |> Array.map(fun x -> x.Split([|' '|], 12))
                       |> Array.filter (fun x -> x.[8].StartsWith("20") <> true)
                       |> Array.map (fun x -> x.[0])
                       |> Array.sort
                       |> Seq.groupBy (fun x -> x)
                       |> Map.ofSeq
                       |> Map.map (fun _ v -> Seq.length v)
                       |> Map.filter (fun _ v -> v > int(config.["httperrorrate"]))
                       |> Map.toList
                       |> List.map (fun (x,_) -> ipToIndicator x "Excessive errors - possible probe activity" )
                       |> List.choose id
    GC.Collect()
    {name = "Apache honeypot logs for " + today;
     Public = true;
     tags = ["apache"; "honeypot"; "exploits"];
     references = [];
     TLP = "green";
     description = "Apache honeypot logs for common exploit attempts from a US /32";
     indicators = List.filter (fun x -> Set.contains x.indicator exemptions <> true) (indicators @ fileindicators @ ircservers @ urls @ errorclients)}

let redislogs (date:DateTime): OtxPulse =
    log 3 ">>> redislogs"
    let today = date.ToString("yyyy-MM-dd")
    let lines = File.ReadAllLines(config.["redispotlog"])
                |> Array.filter(fun x -> x.StartsWith(today))
    let clients = lines
                  |> Array.filter(fun x -> x.Contains("[redispot.redisdeploy.RedisServerFactory] New connection"))
                  |> Array.map(fun x -> x.Split() |> Array.rev |> Array.toList |> List.head)
                  |> Set.ofArray
                  |> Set.map (fun x -> ipToIndicator x "Redis brute force authentication activity")
                  |> Set.toList
                  |> List.choose id
    let urls = lines
               |> Array.filter(fun x -> x.Contains("[RedisServer"))
               |> Array.map getUrl
               |> Seq.concat
               |> Set.ofSeq
               |> Set.map (fun x -> urlToIndicators x "URL injected into Redis honeypot")
               |> Set.toSeq
               |> Seq.concat
               |> Set.ofSeq
               |> Set.toList

    {name = "Redis honeypot logs for " + today;
     Public = true;
     tags = ["redis"; "honeypot"];
     references = [];
     TLP = "green";
     description = "Redis honeypot authentication attempts from a US /32";
     indicators = List.filter(fun x -> Set.contains x.indicator exemptions <> true) (clients @ urls)}

let vnclogs (date:DateTime): OtxPulse =
    log 3 ">>> vnclogs"
    let today = date.ToString("yyyy/MM/dd")
    let lines = File.ReadAllLines(config.["vncpotlog"])
                |> Array.filter(fun x -> x.StartsWith(today))
    let clients = lines
                  |> Array.filter (fun x -> x.Contains("uth response:") || x.Contains("bad version"))
                  |> Array.map (fun x -> x.Split().[2].Split(':').[0])
                  |> Set.ofArray
                  |> Set.map (fun x -> ipToIndicator x "VNC brute force authentication activity")
                  |> Set.toList
                  |> List.choose id
    {name = "VNC honeypot logs for " + today;
     Public = true;
     tags = ["vnc"; "honeypot"];
     references = [];
     TLP = "green";
     description = "VNC honeypot authentication attempts from a US /32";
     indicators = List.filter(fun x -> Set.contains x.indicator exemptions <> true) clients}

let psqllogs (date:DateTime): OtxPulse =
    log 3 ">>> psqllogs"
    let today = date.ToString("yyyy-MM-dd")
    let convertLine (line:string) : PghoneyRecord =  JsonConvert.DeserializeObject<PghoneyRecord>(line)
    let lines = File.ReadAllLines(config.["pghoneylog"])
                |> Array.map convertLine
                |> Array.filter(fun x -> x.time.StartsWith(today))
    let clients = lines
                  |> Array.filter (fun x -> x.level = "info")
                  |> Array.map (fun x -> x.source_ip)
                  |> Set.ofArray
                  |> Set.map (fun x -> ipToIndicator x "PostgresQL brute force authentication activity")
                  |> Set.toList
                  |> List.choose id
    {name = "PostgresQL honeypot logs for " + today;
     Public = true;
     tags = ["postgres"; "honeypot"];
     references = [];
     TLP = "green";
     description = "PostgresQL honeypot authentication attempts from a US /32";
     indicators = List.filter(fun x -> Set.contains x.indicator exemptions <> true) clients}

let rdplogs (date:DateTime): OtxPulse =
    log 3 ">>> rdplogs"
    let today = date.ToString("yyyy/MM/dd")
    let clients = File.ReadAllLines(config.["rdppotlog"])
                |> Array.filter(fun x -> x.StartsWith(today))
                |> Array.filter(fun x -> x.Contains("Connection received from"))
                |> Array.map (fun x -> x.Split().[6].Split(':').[0])
                |> Set.ofArray
                |> Set.map (fun x -> ipToIndicator x "RDP brute force authentication activity")
                |> Set.toList
                |> List.choose id
    {name = "RDP honeypot logs for " + today;
     Public = true;
     tags = ["RDP"; "honeypot"];
     references = [];
     TLP = "green";
     description = "RDP honeypot authentication attempts from a US /32";
     indicators = List.filter(fun x -> Set.contains x.indicator exemptions <> true) clients}

let webshellbackdoorlogs (date:DateTime): OtxPulse =
    log 3 ">>> webshellbackdoorlogs"
    let today = date.ToString("yyyy/MM/dd")

    let convertLine (line: string) : BackdoorRecordPayload =
      try
        JsonConvert.DeserializeObject<BackdoorRecordPayload>(line)
      with
        | :? Newtonsoft.Json.JsonSerializationException -> JsonConvert.DeserializeObject<BackdoorRecordPayload>(line.Replace(":[]}", ":{}}"))
        | :? System.InvalidOperationException -> JsonConvert.DeserializeObject<BackdoorRecordPayload>("{}")

    let lines  = File.ReadAllLines(config.["backdoorlog"])

    let clients = lines
                |> Array.map (fun x -> x.Replace(":[]}", ":{}}"))
                |> Array.map convertLine
                |> Array.map (fun x -> x.client_ip)
                |> Set.ofArray
                |> Set.map (fun x -> ipToIndicator x "Webshell backdoor injection activity client")
                |> Set.toList
                |> List.choose id

    {name = "Webshell backdoor honeypot logs for " + today;
         Public = true;
         tags = ["webshell"; "backdoor"; "honeypot"];
         references = [];
         TLP = "green";
         description = "Webshell backdoor injection attempts from a US /32";
         indicators = List.filter(fun x -> Set.contains x.indicator exemptions <> true) clients}

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
    | :? Net.WebException as ex -> log 0 "%A" ex
    otx

let symlink (source:string) (dest:string) =
    log 2 "symlinking ..."
    let p = new Diagnostics.Process()
    p.StartInfo.FileName <- "/bin/ln"
    p.StartInfo.Arguments <- String.Format("-fs {0} {1}", source, dest)
    p.StartInfo.RedirectStandardOutput <- true
    p.StartInfo.UseShellExecute <- false
    p.Start() |> ignore
    p.StandardOutput.ReadToEnd() |> ignore
    ()

let store (date:DateTime) (doSymlink: bool) (otx: OtxPulse) =
    log 2 "storing ..."
    let json = JsonConvert.SerializeObject(otx).Replace("Type", "type").Replace("Public", "public")
    let today = date.ToString("yyyyMMdd")
    let dir = createDir("/Library/WebServer/Documents/data/" + otx.name.Split(' ').[0])
    let filename = dir.FullName + "/" + today + ".txt"
    File.WriteAllText(filename, json)
    match doSymlink with
    | true -> symlink (FileInfo(filename).Name) (dir.FullName + "/" + "latest.txt")
    | _    -> ()

[<EntryPoint>]
let main args =
    let today = DateTime.Today
    let results = [pmalogs; wordpotlogs; apachelogs; redislogs; vnclogs; psqllogs; rdplogs; webshellbackdoorlogs; kippologs; telnetlogs; ]
                  |> List.map (fun fn -> fn today)
                  |> List.filter (fun x -> not (List.isEmpty (x.indicators)))
    match Array.tryFind (fun x -> x = "-d") args with
    | None    -> List.map (fun x -> upload x) results
                 |> List.iter (fun x -> store today true x)
                 |> ignore
    | Some(_) -> List.iter (fun x -> log 3 "%A" x) results |> ignore
                 results
                 |> List.iter (fun x -> store today false x)
                 |> ignore
    0
