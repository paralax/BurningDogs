open System
open System.IO
open System.Text

open Newtonsoft.Json
open Newtonsoft.Json.Linq


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
