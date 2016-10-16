<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width" /> 
    
  <title>Logging | F# Snippets</title>
  
  <meta name="keywords" content="fsharp, f#, f-sharp, " />

    <!--Style Sheets always on top - Vendor-->
    <link href="/lib/bootstrap.min.css" rel="stylesheet"> <!--As it is tought to find fallback for css. It is loaded from local only-->
    <!--Standard page design-->
    <link href="/content/style.css" rel="stylesheet" />
    <link href="/content/snippets.css" rel="stylesheet" />
    <link href="/lib/chosen.css" rel="stylesheet">
    <link href="/favicon.ico" rel="icon" />

    <!-- Rss Feed -->
    <link rel="alternate" type="application/rss+xml" title="Recent F# snippets" href="/rss" />
</head>

<body>
    <div class="container">
        <div class="row">
            <div class="col-lg-1"></div>
            <div id="heading" class="col-md-12 col-lg-10">
                <img src="/img/fswebsnippets.png" />
            </div>
            <div class="col-lg-1"></div>
        </div>
        <div class="row">
            <div class="col-lg-1"></div>
            <div id="links" class="col-md-12 col-lg-10">
                <a href="/">Home</a>
                <a href="/pages/insert">Insert</a>
                <div id="search">
                    <form id="searchForm">
                        <input type="text" name="query" id="searchbox" placeholder="search..." />
                        <a href="javascript:document.getElementById('searchForm').submit()"><span class="glyphicon glyphicon-search"></span></a>
                    </form>
                </div>
            </div>
            <div class="col-lg-1"></div>
        </div>
        <div class="row">
            <div class="col-lg-1"></div>
            <div class="container main content col-md-12 col-lg-10">
                

<div id="linkModal" class="modal fade" role="dialog">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal">&times;</button>
        <h4 class="modal-title">Link to Snippet</h4>
      </div>
      <div class="modal-body">
        <p>Press <kbd>CTRL+C</kbd> or <kbd>CMD+C</kbd> to copy the selected text and close this dialog.</p>
        <div class="modal-body-inner">

        </div>
      </div>
    </div>
  </div>
</div>

<div class="row">
<div class="col-md-12" id="xxx">
  <p class="snip-tweet">
    <a href="https://twitter.com/share" class="twitter-share-button" data-via="tomaspetricek">Tweet</a>
    <script>!function (d, s, id) { var js, fjs = d.getElementsByTagName(s)[0], p = /^http:/.test(d.location) ? 'http' : 'https'; if (!d.getElementById(id)) { js = d.createElement(s); js.id = id; js.src = p + '://platform.twitter.com/widgets.js'; fjs.parentNode.insertBefore(js, fjs); } }(document, 'script', 'twitter-wjs');</script>
  </p>
  <p class="snip-like">
    <span class="likeCount">2</span> people like it.<br />
    <a href="javascript:;" class="likeLink" data-snippetid="8j">Like the snippet!</a>
  </p>

  <h1>Logging</h1>
  <p></p>

  <table class="pre"><tr><td class="lines"><pre class="fssnip"><span class="l"> 1: </span>
<span class="l"> 2: </span>
<span class="l"> 3: </span>
<span class="l"> 4: </span>
<span class="l"> 5: </span>
<span class="l"> 6: </span>
<span class="l"> 7: </span>
<span class="l"> 8: </span>
<span class="l"> 9: </span>
<span class="l">10: </span>
<span class="l">11: </span>
<span class="l">12: </span>
<span class="l">13: </span>
<span class="l">14: </span>
<span class="l">15: </span>
<span class="l">16: </span>
<span class="l">17: </span>
<span class="l">18: </span>
<span class="l">19: </span>
<span class="l">20: </span>
<span class="l">21: </span>
<span class="l">22: </span>
<span class="l">23: </span>
<span class="l">24: </span>
<span class="l">25: </span>
<span class="l">26: </span>
<span class="l">27: </span>
<span class="l">28: </span>
<span class="l">29: </span>
<span class="l">30: </span>
<span class="l">31: </span>
<span class="l">32: </span>
<span class="l">33: </span>
<span class="l">34: </span>
<span class="l">35: </span>
<span class="l">36: </span>
<span class="l">37: </span>
<span class="l">38: </span>
<span class="l">39: </span>
</pre></td>
<td class="snippet"><pre class="fssnip highlighted"><code lang="fsharp"><span class="k">module</span> <span onmouseout="hideTip(event, 'fs1', 1)" onmouseover="showTip(event, 'fs1', 1)" class="t">Logging</span>

<span class="k">open</span> <span onmouseout="hideTip(event, 'fs2', 2)" onmouseover="showTip(event, 'fs2', 2)" class="i">System</span>

<span class="c">/// Log levels.</span>
<span class="k">let</span> <span onmouseout="hideTip(event, 'fs3', 3)" onmouseover="showTip(event, 'fs3', 3)" class="i">Error</span> <span class="o">=</span> <span class="n">0</span>
<span class="k">let</span> <span onmouseout="hideTip(event, 'fs4', 4)" onmouseover="showTip(event, 'fs4', 4)" class="i">Warning</span> <span class="o">=</span> <span class="n">1</span>
<span class="k">let</span> <span onmouseout="hideTip(event, 'fs5', 5)" onmouseover="showTip(event, 'fs5', 5)" class="i">Information</span> <span class="o">=</span> <span class="n">2</span>
<span class="k">let</span> <span onmouseout="hideTip(event, 'fs6', 6)" onmouseover="showTip(event, 'fs6', 6)" class="i">Debug</span> <span class="o">=</span> <span class="n">3</span>

<span class="k">let</span> <span onmouseout="hideTip(event, 'fs7', 7)" onmouseover="showTip(event, 'fs7', 7)" class="f">LevelToString</span> <span onmouseout="hideTip(event, 'fs8', 8)" onmouseover="showTip(event, 'fs8', 8)" class="i">level</span> <span class="o">=</span>
  <span class="k">match</span> <span onmouseout="hideTip(event, 'fs8', 9)" onmouseover="showTip(event, 'fs8', 9)" class="i">level</span> <span class="k">with</span>
    | <span class="n">0</span> <span class="k">-&gt;</span> <span class="s">&quot;Error&quot;</span>
    | <span class="n">1</span> <span class="k">-&gt;</span> <span class="s">&quot;Warning&quot;</span>
    | <span class="n">2</span> <span class="k">-&gt;</span> <span class="s">&quot;Information&quot;</span>
    | <span class="n">3</span> <span class="k">-&gt;</span> <span class="s">&quot;Debug&quot;</span>
    | _ <span class="k">-&gt;</span> <span class="s">&quot;Unknown&quot;</span>

<span class="c">/// The current log level.</span>
<span class="k">let</span> <span class="k">mutable</span> <span onmouseout="hideTip(event, 'fs9', 10)" onmouseover="showTip(event, 'fs9', 10)" class="v">current_log_level</span> <span class="o">=</span> <span onmouseout="hideTip(event, 'fs6', 11)" onmouseover="showTip(event, 'fs6', 11)" class="i">Debug</span>

<span class="c">/// The inteface loggers need to implement.</span>
<span class="k">type</span> <span onmouseout="hideTip(event, 'fs10', 12)" onmouseover="showTip(event, 'fs10', 12)" class="t">ILogger</span> <span class="o">=</span> <span class="k">abstract</span> <span onmouseout="hideTip(event, 'fs11', 13)" onmouseover="showTip(event, 'fs11', 13)" class="f">Log</span> <span class="o">:</span> <span onmouseout="hideTip(event, 'fs12', 14)" onmouseover="showTip(event, 'fs12', 14)" class="t">int</span> <span class="k">-&gt;</span> <span onmouseout="hideTip(event, 'fs13', 15)" onmouseover="showTip(event, 'fs13', 15)" class="t">Printf</span><span class="o">.</span><span onmouseout="hideTip(event, 'fs14', 16)" onmouseover="showTip(event, 'fs14', 16)" class="t">StringFormat</span><span class="o">&lt;</span><span class="o">&#39;</span><span class="i">a</span>,<span onmouseout="hideTip(event, 'fs15', 17)" onmouseover="showTip(event, 'fs15', 17)" class="t">unit</span><span class="o">&gt;</span> <span class="k">-&gt;</span> <span class="o">&#39;</span><span class="i">a</span>

<span class="c">/// Writes to console.</span>
<span class="k">let</span> <span onmouseout="hideTip(event, 'fs16', 18)" onmouseover="showTip(event, 'fs16', 18)" class="i">ConsoleLogger</span> <span class="o">=</span> { 
  <span class="k">new</span> <span onmouseout="hideTip(event, 'fs10', 19)" onmouseover="showTip(event, 'fs10', 19)" class="t">ILogger</span> <span class="k">with</span>
    <span class="k">member</span> <span class="i">__</span><span class="o">.</span><span class="f">Log</span> <span onmouseout="hideTip(event, 'fs8', 20)" onmouseover="showTip(event, 'fs8', 20)" class="i">level</span> <span onmouseout="hideTip(event, 'fs17', 21)" onmouseover="showTip(event, 'fs17', 21)" class="i">format</span> <span class="o">=</span>
      <span onmouseout="hideTip(event, 'fs13', 22)" onmouseover="showTip(event, 'fs13', 22)" class="t">Printf</span><span class="o">.</span><span onmouseout="hideTip(event, 'fs18', 23)" onmouseover="showTip(event, 'fs18', 23)" class="f">kprintf</span> (<span onmouseout="hideTip(event, 'fs19', 24)" onmouseover="showTip(event, 'fs19', 24)" class="f">printfn</span> <span class="s">&quot;[</span><span class="pf">%s</span><span class="s">][</span><span class="pf">%A</span><span class="s">] </span><span class="pf">%s</span><span class="s">&quot;</span> (<span onmouseout="hideTip(event, 'fs7', 25)" onmouseover="showTip(event, 'fs7', 25)" class="f">LevelToString</span> <span onmouseout="hideTip(event, 'fs8', 26)" onmouseover="showTip(event, 'fs8', 26)" class="i">level</span>) <span onmouseout="hideTip(event, 'fs2', 27)" onmouseover="showTip(event, 'fs2', 27)" class="i">System</span><span class="o">.</span><span onmouseout="hideTip(event, 'fs20', 28)" onmouseover="showTip(event, 'fs20', 28)" class="t">DateTime</span><span class="o">.</span><span onmouseout="hideTip(event, 'fs21', 29)" onmouseover="showTip(event, 'fs21', 29)" class="i">Now</span>) <span onmouseout="hideTip(event, 'fs17', 30)" onmouseover="showTip(event, 'fs17', 30)" class="i">format</span>
 }

<span class="c">/// Defines which logger to use.</span>
<span class="k">let</span> <span class="k">mutable</span> <span onmouseout="hideTip(event, 'fs22', 31)" onmouseover="showTip(event, 'fs22', 31)" class="v">DefaultLogger</span> <span class="o">=</span> <span onmouseout="hideTip(event, 'fs16', 32)" onmouseover="showTip(event, 'fs16', 32)" class="i">ConsoleLogger</span>

<span class="c">/// Logs a message with the specified logger.</span>
<span class="k">let</span> <span onmouseout="hideTip(event, 'fs23', 33)" onmouseover="showTip(event, 'fs23', 33)" class="f">logUsing</span> (<span onmouseout="hideTip(event, 'fs24', 34)" onmouseover="showTip(event, 'fs24', 34)" class="i">logger</span><span class="o">:</span> <span onmouseout="hideTip(event, 'fs10', 35)" onmouseover="showTip(event, 'fs10', 35)" class="t">ILogger</span>) <span class="o">=</span> <span onmouseout="hideTip(event, 'fs24', 36)" onmouseover="showTip(event, 'fs24', 36)" class="i">logger</span><span class="o">.</span><span onmouseout="hideTip(event, 'fs25', 37)" onmouseover="showTip(event, 'fs25', 37)" class="f">Log</span>

<span class="c">/// Logs a message using the default logger.</span>
<span class="k">let</span> <span onmouseout="hideTip(event, 'fs26', 38)" onmouseover="showTip(event, 'fs26', 38)" class="f">log</span> <span onmouseout="hideTip(event, 'fs8', 39)" onmouseover="showTip(event, 'fs8', 39)" class="i">level</span> <span onmouseout="hideTip(event, 'fs27', 40)" onmouseover="showTip(event, 'fs27', 40)" class="i">message</span> <span class="o">=</span> <span onmouseout="hideTip(event, 'fs23', 41)" onmouseover="showTip(event, 'fs23', 41)" class="f">logUsing</span> <span onmouseout="hideTip(event, 'fs22', 42)" onmouseover="showTip(event, 'fs22', 42)" class="v">DefaultLogger</span> <span onmouseout="hideTip(event, 'fs8', 43)" onmouseover="showTip(event, 'fs8', 43)" class="i">level</span> <span onmouseout="hideTip(event, 'fs27', 44)" onmouseover="showTip(event, 'fs27', 44)" class="i">message</span>
</code></pre></td>
</tr>
</table>
<div class="tip" id="fs1">module Logging</div>
<div class="tip" id="fs2">namespace System</div>
<div class="tip" id="fs3">val Error : int<br /><br />Full name: Logging.Error<br /><em><br /><br />&#160;Log levels.</em></div>
<div class="tip" id="fs4">val Warning : int<br /><br />Full name: Logging.Warning</div>
<div class="tip" id="fs5">val Information : int<br /><br />Full name: Logging.Information</div>
<div class="tip" id="fs6">val Debug : int<br /><br />Full name: Logging.Debug</div>
<div class="tip" id="fs7">val LevelToString : level:int -&gt; string<br /><br />Full name: Logging.LevelToString</div>
<div class="tip" id="fs8">val level : int</div>
<div class="tip" id="fs9">val mutable current_log_level : int<br /><br />Full name: Logging.current_log_level<br /><em><br /><br />&#160;The current log level.</em></div>
<div class="tip" id="fs10">type ILogger =<br />&#160;&#160;interface<br />&#160;&#160;&#160;&#160;abstract member Log : int -&gt; StringFormat&lt;&#39;a,unit&gt; -&gt; &#39;a<br />&#160;&#160;end<br /><br />Full name: Logging.ILogger<br /><em><br /><br />&#160;The inteface loggers need to implement.</em></div>
<div class="tip" id="fs11">abstract member ILogger.Log : int -&gt; Printf.StringFormat&lt;&#39;a,unit&gt; -&gt; &#39;a<br /><br />Full name: Logging.ILogger.Log</div>
<div class="tip" id="fs12">Multiple items<br />val int : value:&#39;T -&gt; int (requires member op_Explicit)<br /><br />Full name: Microsoft.FSharp.Core.Operators.int<br /><br />--------------------<br />type int = int32<br /><br />Full name: Microsoft.FSharp.Core.int<br /><br />--------------------<br />type int&lt;&#39;Measure&gt; = int<br /><br />Full name: Microsoft.FSharp.Core.int&lt;_&gt;</div>
<div class="tip" id="fs13">module Printf<br /><br />from Microsoft.FSharp.Core</div>
<div class="tip" id="fs14">type StringFormat&lt;&#39;T,&#39;Result&gt; = Format&lt;&#39;T,unit,string,&#39;Result&gt;<br /><br />Full name: Microsoft.FSharp.Core.PrintfModule.StringFormat&lt;_,_&gt;</div>
<div class="tip" id="fs15">type unit = Unit<br /><br />Full name: Microsoft.FSharp.Core.unit</div>
<div class="tip" id="fs16">val ConsoleLogger : ILogger<br /><br />Full name: Logging.ConsoleLogger<br /><em><br /><br />&#160;Writes to console.</em></div>
<div class="tip" id="fs17">val format : Printf.StringFormat&lt;&#39;a,unit&gt;</div>
<div class="tip" id="fs18">val kprintf : continutation:(string -&gt; &#39;Result) -&gt; format:Printf.StringFormat&lt;&#39;T,&#39;Result&gt; -&gt; &#39;T<br /><br />Full name: Microsoft.FSharp.Core.Printf.kprintf</div>
<div class="tip" id="fs19">val printfn : format:Printf.TextWriterFormat&lt;&#39;T&gt; -&gt; &#39;T<br /><br />Full name: Microsoft.FSharp.Core.ExtraTopLevelOperators.printfn</div>
<div class="tip" id="fs20">Multiple items<br />type DateTime =<br />&#160;&#160;struct<br />&#160;&#160;&#160;&#160;new : ticks:int64 -&gt; DateTime + 10 overloads<br />&#160;&#160;&#160;&#160;member Add : value:TimeSpan -&gt; DateTime<br />&#160;&#160;&#160;&#160;member AddDays : value:float -&gt; DateTime<br />&#160;&#160;&#160;&#160;member AddHours : value:float -&gt; DateTime<br />&#160;&#160;&#160;&#160;member AddMilliseconds : value:float -&gt; DateTime<br />&#160;&#160;&#160;&#160;member AddMinutes : value:float -&gt; DateTime<br />&#160;&#160;&#160;&#160;member AddMonths : months:int -&gt; DateTime<br />&#160;&#160;&#160;&#160;member AddSeconds : value:float -&gt; DateTime<br />&#160;&#160;&#160;&#160;member AddTicks : value:int64 -&gt; DateTime<br />&#160;&#160;&#160;&#160;member AddYears : value:int -&gt; DateTime<br />&#160;&#160;&#160;&#160;...<br />&#160;&#160;end<br /><br />Full name: System.DateTime<br /><br />--------------------<br />DateTime()<br />&#160;&#160;&#160;<em>(+0 other overloads)</em><br />DateTime(ticks: int64) : unit<br />&#160;&#160;&#160;<em>(+0 other overloads)</em><br />DateTime(ticks: int64, kind: DateTimeKind) : unit<br />&#160;&#160;&#160;<em>(+0 other overloads)</em><br />DateTime(year: int, month: int, day: int) : unit<br />&#160;&#160;&#160;<em>(+0 other overloads)</em><br />DateTime(year: int, month: int, day: int, calendar: Globalization.Calendar) : unit<br />&#160;&#160;&#160;<em>(+0 other overloads)</em><br />DateTime(year: int, month: int, day: int, hour: int, minute: int, second: int) : unit<br />&#160;&#160;&#160;<em>(+0 other overloads)</em><br />DateTime(year: int, month: int, day: int, hour: int, minute: int, second: int, kind: DateTimeKind) : unit<br />&#160;&#160;&#160;<em>(+0 other overloads)</em><br />DateTime(year: int, month: int, day: int, hour: int, minute: int, second: int, calendar: Globalization.Calendar) : unit<br />&#160;&#160;&#160;<em>(+0 other overloads)</em><br />DateTime(year: int, month: int, day: int, hour: int, minute: int, second: int, millisecond: int) : unit<br />&#160;&#160;&#160;<em>(+0 other overloads)</em><br />DateTime(year: int, month: int, day: int, hour: int, minute: int, second: int, millisecond: int, kind: DateTimeKind) : unit<br />&#160;&#160;&#160;<em>(+0 other overloads)</em></div>
<div class="tip" id="fs21">property DateTime.Now: DateTime</div>
<div class="tip" id="fs22">val mutable DefaultLogger : ILogger<br /><br />Full name: Logging.DefaultLogger<br /><em><br /><br />&#160;Defines which logger to use.</em></div>
<div class="tip" id="fs23">val logUsing : logger:ILogger -&gt; (int -&gt; Printf.StringFormat&lt;&#39;a,unit&gt; -&gt; &#39;a)<br /><br />Full name: Logging.logUsing<br /><em><br /><br />&#160;Logs a message with the specified logger.</em></div>
<div class="tip" id="fs24">val logger : ILogger</div>
<div class="tip" id="fs25">abstract member ILogger.Log : int -&gt; Printf.StringFormat&lt;&#39;a,unit&gt; -&gt; &#39;a</div>
<div class="tip" id="fs26">val log : level:int -&gt; message:Printf.StringFormat&lt;&#39;a,unit&gt; -&gt; &#39;a<br /><br />Full name: Logging.log<br /><em><br /><br />&#160;Logs a message using the default logger.</em></div>
<div class="tip" id="fs27">val message : Printf.StringFormat&lt;&#39;a,unit&gt;</div>



  <div class="btn-group" role="group" aria-label="..." id="snip-tools">
    
	
	
    <button class="btn btn-default" data-action="show-link" data-snippetid="8j" data-toggle="modal" data-target="#linkModal" >Copy link</button>
    <button class="btn btn-default" data-action="show-source" data-snippetid="8j" data-toggle="modal" data-target="#linkModal" >Copy source</button>
    <a class="btn btn-default" href="/raw/8j">Raw view</a>
    <div class="btn-group" role="group">
      <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
        Load in
        <span class="caret"></span>
      </button>
      <ul class="dropdown-menu">
        <li><a href="http://tsunami.io/cloud_tsunami.html?initurl=http://fssnip.net/raw/8j">tsunami.io</a></li>
        <li><a href="http://www.tryfsharp.org/Create?codeUrl=http://fssnip.net/raw/8j">tryfsharp.org</a></li>
        <li><a href="http://tryfs.net/snippets/snippet-8j">tryfs.net</a></li>
      </ul>
    </div>
    <a class="btn btn-default" href="/8j/update">New version</a>
  </div>

  <br />
  <h3>More information</h3>

  <table class="detail-table">
    <tr><td class="detail-lbl">Link:</td><td><a href="http://fssnip.net/8j">http://fssnip.net/8j</a></td></tr>
    <tr><td class="detail-lbl">Posted:</td><td>4 years ago</td></tr>
    <tr><td class="detail-lbl">Author:</td><td><a href="/authors/"></a></td></tr>
    <tr><td class="detail-lbl">Tags:</td><td>
      
      
    </td></tr>
  </table>
  
</div>
</div>

            </div>
            <div class="col-lg-1"></div>
        </div>
        <div class="row">
            <div class="col-lg-1"></div>
            <div class="col-lg-10 footer">
                <div class="row">
                    <div class="col-sm-4">
                        <p>
                            This web site is created using <a href="http://www.fsharp.org">F#</a> and <a href="http://suave.io/">Suave</a>                            web server. It is hosted on
                            <a href="http://www.hanselman.com/blog/RunningSuaveioAndFWithFAKEInAzureWebAppsWithGitAndTheDeployButton.aspx">Azure</a>                            and the source code is on <a href="https://github.com/tpetricek/FsSnip.Website">GitHub</a>. Contributions
                            are welcome!
                        </p>
                    </div>
                    <div class="col-sm-4">
                        <p>The first version of <a href="http://www.fssnip.net">fssnip.net</a> has been created by
                            <a href="https://twitter.com/tomaspetricek">@tomaspetricek</a> back <a href="http://tomasp.net/blog/fssnip-website.aspx/">in 2010</a>.
                            This web site is a new, open-source and contribution-friendly version.
                        </p>
                    </div>
                    <div class="col-sm-4">
                        <ul>
                            <li>Check out the <a href="https://github.com/tpetricek/FsSnip.Website">source code</a> and contribute!</li>
                            <li>See the list of <a href="https://github.com/tpetricek/FsSnip.Website/issues">issues and suggestions</a></li>
                            <li>The syntax highlighting uses <a href="http://tpetricek.github.io/FSharp.Formatting/">F# Formatting</a></li>
                        </ul>
                    </div>
                </div>
            </div>
            <div class="col-lg-1"></div>
        </div>
    </div>

    <!--All js at bottom of page so it will not block page loading-->
    <div>
    <script>
      (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
      (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
      m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
      })(window,document,'script','//www.google-analytics.com/analytics.js','ga');
    
      ga('create', 'UA-1561220-4', 'auto');
      ga('send', 'pageview');
    
    </script>      
    <script src="https://www.google.com/recaptcha/api.js"></script>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/2.2.0/jquery.min.js"></script>
    <script>
        window.jQuery || document.write('<script src="/lib/jquery-2.2.0.min.js"><\/script>')
    </script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js" integrity="sha384-0mSbJDEHialfmuBBQP6A4Qrprq5OVfW37PRR3j5ELqxss1yVqOtnepnHVP9aJ7xS" crossorigin="anonymous"></script>
    <script>
        if ((typeof $().emulateTransitionEnd == 'function') === false) {
            document.write('<script src="/lib/bootstrap.min.js"><\/script>');
        }
    </script>
    <script src="/lib/chosen.jquery.min.js"></script>

    <!-- Standard page design and scripts -->
    <script src="/content/dist/tips.min.js"></script>
    <script src="/content/dist/search.min.js"></script>
    
  <script src="/content/dist/copycontent.min.js"></script>
  <script src="/content/dist/likes.min.js"></script>

    </div>
</body>

</html>