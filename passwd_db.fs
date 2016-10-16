open System
open System.Net
open System.Text

type PasswordRecord = {
    Manufactor: string; 
    Product: string; 
    Revision: string; 
    Protocol: string; 
    User: string; 
    Password: string;
    Access: string; 
    Validated: string;}

let tagData (tag:string) (html:string): string list =
    [ for m in RegularExpressions.Regex.Matches(html.Replace("\n", "").Trim().Replace("\r", ""),
                                                String.Format("<{0}.*?>(.*?)</{0}>", tag, tag),
                                                RegularExpressions.RegexOptions.IgnoreCase) 
                                                    -> m.Groups.Item(1).Value ]

let tables(html:string): string list =
    tagData "table" html

let rows(html:string):string list =
    tagData "tr" html

let cells(html:string): string list = 
    tagData "td" html

let stripHtml(html:string): string =
    RegularExpressions.Regex.Replace(html, "<[^>]*>", "")

let getData : seq<PasswordRecord> = 
    let wc = new WebClient()
    let html = wc.DownloadString("http://www.defaultpassword.com/")                                                    
    let data = html |> tables |> List.map (fun x -> rows x |>  List.map(fun x -> cells x |> List.map stripHtml)) |> List.concat  
    let cols = Seq.skip 2 data |> Seq.head 
    Seq.skip 3 data 
    |> Seq.map Array.ofList 
    |> Seq.map (fun x -> {Manufactor=x.[0].Trim(); Product=x.[1].Trim(); 
                          Revision=x.[2].Trim(); Protocol=x.[3].Trim(); 
                          User=x.[4].Trim(); Password=x.[5].Trim(); 
                          Access=x.[6].Trim(); Validated=x.[7].Trim()})