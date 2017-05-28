// http://accord-framework.net/docs/html/T_Accord_Statistics_Models_Markov_Learning_BaumWelchLearning.htm

open System

open Accord.Math
open Accord.Statistics.Models.Markov.Learning
open Accord.Statistics.Models.Markov

(*
    idea
    - train on a batch of honeypot log files, look for the sequence of commands
        - first build a set of commands
        - then turn it into an array
        - for each log file, turn it into a sequence like "[|3;5;10;2;3;2|]" indexed by commands for each session id
        - train an hmm like above on that data set
    - examine new log files
        - for each session id, build a sequence of commands like "[|10;4;1;16;3;2;3|]"
        - hmm.LogLikelihood() that sequence and look for improbable ones
*)

let parse_one(logfile: string) : (string [] * Map<string, string list>) = 
    let getcmd(line: string) : string = 
        // 2017-01-10T21:35:31-0500 [CowrieTelnetTransport,68691,::ffff:39.167.7.160] CMD: sh
        line.Split(' ').[3]
    let getsessionid(line: string) : string = 
        line.Split(' ').[1].Split(',').[1]
    let addcmd(sessionid: string) (cmd: string) (sessions: Map<string,string list>) : Map<string,string list> =
        match Map.containsKey sessionid sessions with
        | true  -> Map.add sessionid (sessions.[sessionid] @ [cmd]) sessions
        | false -> Map.add sessionid [cmd] sessions
    let rec parselines (cmds: Set<string>) (sessions: Map<string, string list>) (lines: string list) = 
        match lines with
        | h::t -> parselines (Set.add (getcmd h) cmds) (addcmd (getsessionid h) (getcmd h) sessions) t
        | []   -> (cmds |> Set.toArray, sessions)
    System.IO.File.ReadAllLines logfile 
    |> Array.toList 
    |> List.filter (fun x -> x.Contains("[CowrieTelnetTransport") && x.Contains("CMD: "))
    |> parselines Set.empty Map.empty

let parse(logfiles: string list): (string [] * int [] []) = 
    // from http://stackoverflow.com/questions/3974758/in-f-how-do-you-merge-2-collections-map-instances
    let join (p:Map<'a,'b>) (q:Map<'a,'b>) = 
        Map(Seq.concat [ (Map.toSeq p) ; (Map.toSeq q) ])
    let results = List.map parse_one logfiles 
    let cmds = results 
               |> List.map fst
               |> Array.concat
               |> Set.ofArray
               |> Set.toArray
    let sessions = results 
                   |> List.map snd
                   |> List.fold join Map.empty<string, string list>                   
    let sequences = Map.toArray sessions 
                    |> Array.map (fun (_, x) -> List.toArray x 
                                                |> Array.map (fun x -> Array.findIndex (fun y -> x = y) cmds ))
    (cmds, sequences)

(* build the HMM model based on previous data
*)
let train(logfiles: string list) : (string [] * HiddenMarkovModel) = 
    let cmds, sequences = parse logfiles
    let states =  Array.map (fun x -> Array.length x) sequences
                  |> Array.max
    let symbols = 1 + (Array.concat sequences |> Array.max)
    let hmm = new HiddenMarkovModel(states, symbols)
    let teacher = new BaumWelchLearning(hmm)
    teacher.Tolerance <- 0.0001
    teacher.Iterations <- 0 
    teacher.Learn(sequences) |> ignore
    (cmds, hmm)

(* now take a logfile and find the interesting sequences 
   yields a map of interesting sessions keyed by session ID -> sequence of commands
*)
let unusual (hmm: HiddenMarkovModel) (cmds: string []) (threshold: float) (logfile: string) : Map<string,string list> = 
    let tryFindCmd (cmds : string []) (cmd : string) : int = 
        let res = Array.tryFindIndex (fun x -> x = cmd) cmds
        match res with
        | Some i -> i
        | None   -> -1
    let session_to_sequence (cmds: string []) (session: string list) : int [] =
        List.map (fun x -> tryFindCmd cmds x) session |> Array.ofList
    let probability (sequence : int []) : float =
        Math.Exp(hmm.LogLikelihood(sequence))
    parse_one logfile
    |> snd 
    |> Map.map (fun _ v -> (v, probability (session_to_sequence cmds v))) 
    |> Map.filter (fun _ (_,p) -> p < threshold)
    |> Map.map (fun _ (v,_) -> v)

type CommandLineOptions = {
    threshold: float        // -t F
}
let defaultOptions = {
    threshold= 0.001
}

let usage =
    printfn "hmm_honeypot.exe ARGS"
    printfn "arguments and options:"
    printfn "  -t F    set the threshold for reporting to F (default:%f)" defaultOptions.threshold
    printfn "  -h      this text"

// inspired via https://fsharpforfunandprofit.com/posts/pattern-matching-command-line/
let rec parseCommandLine args soFar : CommandLineOptions = 
    match args with
    | [] -> soFar    
    | "-t"::xs ->
        let t = float (List.head xs)
        let rem = List.tail xs
        parseCommandLine rem { soFar with threshold=t}
    | "-h"::xs -> 
        usage
        failwith ""
    | x::xs ->
        printfn "WARNING option %s is not understood" x
        parseCommandLine xs soFar


[<EntryPoint>]
let main args = 
    let options = parseCommandLine (List.ofArray args) defaultOptions
    let cmds, hmm = System.IO.Directory.GetFiles("/Users/jose/honeynet/src/third-party/cowrie/log", "*.log.??")
                    |> List.ofArray
                    |> train
    System.IO.Directory.GetFiles("/Users/jose/honeynet/src/third-party/cowrie/log", "*.log.?")
    |> Array.map (fun x -> unusual hmm cmds options.threshold x)
    |> Array.iter (fun x -> printfn "%A" x)
    0