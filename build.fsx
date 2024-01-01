// include Fake lib
#r @"/Users/jose/dotnet/FAKE.3.5.4/tools/FakeLib.dll"
open Fake
open Fake.FscHelper

Target "otx_pulse.exe" (fun _ ->
    ["log.fs"; "otx_pulse.fs"]
    |> Fsc (fun p ->
        {p with References =
            ["packages/Newtonsoft.Json/lib/net40/Newtonsoft.Json.dll"
             ]}
    )
)

Target "otx_pulse2.exe" (fun _ ->
    ["log.fs"; "otx_pulse2.fs"]
    |> Fsc (fun p ->
        {p with References =
            ["packages/Newtonsoft.Json/lib/net40/Newtonsoft.Json.dll"
             ]}
    )
)

Target "backdoor_test.exe" (fun _ ->
    ["log.fs"; "backdoor_test.fs"]
    |> Fsc (fun p ->
        {p with References =
            ["packages/Newtonsoft.Json/lib/net40/Newtonsoft.Json.dll"
             ]}
    )
)

Target "hmm_honeypot.exe" (fun _ ->
    ["log.fs"; "hmm_honeypot.fs"]
    |> Fsc (fun p ->
        {p with References =
            ["packages/Accord/lib/net40/Accord.dll";
             "packages/Accord.Statistics/lib/net40/Accord.Statistics.dll";
             "packages/Accord.Math/lib/net40/Accord.Math.dll"
            ]}
    )
)


Target "canary_pulse.exe" (fun _ ->
    ["canary_pulse.fs"; ]
    |> Fsc (fun p ->
        {p with References =
            ["packages/Newtonsoft.Json/lib/net40/Newtonsoft.Json.dll"
             ]}
    )
)

Target "owa_pulse.exe" (fun _ ->
    ["log.fs"; "owa_pulse.fs"; ]
    |> Fsc (fun p ->
        {p with References =
            ["packages/Newtonsoft.Json/lib/net40/Newtonsoft.Json.dll"
             ]}
    )
)

Target "c2_pulse.exe" (fun _ ->
    ["log.fs"; "c2_pulse.fs"; ]
    |> Fsc (fun p ->
        {p with References =
            ["packages/Newtonsoft.Json/lib/net40/Newtonsoft.Json.dll"
             ]}
    )
)

RunTargetOrDefault "otx_pulse.exe"