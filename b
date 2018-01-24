<html>
    <title>Snorpy 2.0 - Web Based Snort Rule Creator</title>
    <link rel='stylesheet' href='./css/snorpy.css' type='text/css'></link>
    <link rel="stylesheet" href="./css/jquery-ui.css"></link>
    <meta charset="UTF-8">
    <meta name="description" content="Free web based snort rule creator, maker, with jquery">
    <meta name="keywords" content="web,based,snort,rule,creator,maker,builder">
    <meta name="author" content="Christopher Davis">

    <body>

    

<form method="post" action="./rule.php">  
  Name: <input type="text" name="name">
  <div class="rulebody mainsquares">
  <br><br>
    <select name="action" >
                        <option value="">Action</option>
                        <option value="alert">alert</option>
                        <option value="log">log</option>
                        <option value="pass">pass</option>
                        <option value="activate">activate</option>
                        <option value="dynamic">dynamic</option>
                        <option value="drop">drop</option>
                        <option value="reject">reject</option>
                        <option value="sdrop">sdrop</option>
                    </select>
                    <select name="protocol">
                        <option value="">Protocol</option>
                        <option value="tcp">tcp</option>
                        <option value="icmp">icmp</option>
                        <option value="udp">udp</option>
                        <option value="ip">ip</option>
                    </select>
                    <input name="sourceip" placeholder="source ip"></input>
                    <input name="srcport" placeholder="source port"></input>
                    <input name="dstip"  placeholder="dest ip"></input>
                    <input name="dstport"  placeholder="dest port"></input>
                    <input name="sid"  placeholder="sid"></input>
                    <input name="rev" placeholder="rev num"></input>

                    <input  name="headermessage" placeholder="Rule Message ( \ Escape special characters)"></input>
                    <input  name="classtype" placeholder="Class-Type"></input>
    <select name="priority">
                        <option value="">Priority</option>
                        <option value="priority:1;">1</option>
                        <option value="priority:2;">2</option>
                        <option value="priority:3;">3</option>
                        <option value="priority:4;">4</option>
                        <option value="priority:5;">5</option>
    </select>
                    <input  name="gid" placeholder="gid">

                    
</div> 
  <br><br>
  <!-- Gender:
  <input type="radio" name="gender" value="female">Female
  <input type="radio" name="gender" value="male">Male
  <br><br>
  <input type="checkbox" name="ch" value="ch"></input> -->
  <input type="submit" name="submit" value="Submit">  
</form>

<!-- ========================================================================================================================== -->




        <!-- Main Container Holding Everything -->
        <div id="globalcontainer">
            <h1><span class="SNORPY">SNORPY</span></h1>
            <p style="z-index: 1;">A Web Based Snort Rule Creator / Maker for Building Simple Snort Rules</p>
            <div id="particles-js"></div>

            <!-- This is the rule header section -->
            <div class="rulebody mainsquares">
                <!-- This is the top line in the header starting with action -->
                <div id="headerInner1">
                    <select id="actionForm">
                        <option value="">Action</option>
                        <option value="alert">alert</option>
                        <option value="log">log</option>
                        <option value="pass">pass</option>
                        <option value="activate">activate</option>
                        <option value="dynamic">dynamic</option>
                        <option value="drop">drop</option>
                        <option value="reject">reject</option>
                        <option value="sdrop">sdrop</option>
                    </select>
                    <select id="protoForm">
                        <option ''value="">Protocol</option>
                        <option ''value="tcp">tcp</option>
                        <option ''value="icmp">icmp</option>
                        <option ''value="udp">udp</option>
                        <option ''value="ip">ip</option>
                    </select>
                    <input class="headerelement" id="srcip" placeholder="source ip"></input>
                    <input class="headerelement" id="srcport" placeholder="source port"></input>
                    &nbsp<strong id="rightarrow">&#xbb;</strong>&nbsp
                    <input class="headerelement" id="dstip"  placeholder="dest ip"></input>
                    <input class="headerelement" id="dstport"  placeholder="dest port"></input>
                    <input class="headerelement" id="sid"  placeholder="sid"></input>
                    <input class="headerelement" id="rev" placeholder="rev num"></input>
                </div>
                <!-- Second line -->
                <div id="headerInner2">
                    <input  class="headerelement" id="headermessage" placeholder="Rule Message ( \ Escape special characters)"></input>
                    <input  class="headerelement" id="classtype" placeholder="Class-Type"></input>
                    <select  class="headerelement" id="priority">
                        <option value="">Priority</option>
                        <option value="priority:1;">1</option>
                        <option value="priority:2;">2</option>
                        <option value="priority:3;">3</option>
                        <option value="priority:4;">4</option>
                        <option value="priority:5;">5</option>
                    </select>
                    <input  class="headerelement" id="gid" placeholder="gid"></input>
                </div>
            </div>

            <!-- This is the LEFT Main box holind protocol option box -->
            <div class="protoOptions mainsquares">
                <div id="ip" class="selectedProtoOptions">
                    </br></br></br><h2>IP</h2>
                    </br></br></br>
                    <select class="ttlevaluator tcpinputs" id="ttlevaluator" >
                        <option value="&gt;">&gt;</option>
                        <option value="&lt;">&lt;</option>
                        <option value="=">=</option>
                        <option selected="selected" value="">TTL</option>
                    </select>

                    <input class="ttlfield tcpinputs" id="ttl" type="text" />
                    </br></br></br>
                    <select class="ipprotoevaluator tcpinputs" id="ipprotoevaluator" size="1">
                        <option value="&gt;">&gt;</option>
                        <option value="&lt;">&lt;</option>
                        <option value="=">=</option>
                        <option selected="selected" value="">IP PROTOCOL</option>
                    </select>
                    <input class="ipprotofield tcpinputs" id="ipprotofield" type="text" />
                </div>
                <!-- TCP Options -->
                <div id="tcp" class="selectedProtoOptions">
                    <h2>TCP</h2>
                    <select class="tcpinputs" id="httpmethodForm" >
                        <option value='content:"GET"; http_method;'>GET</option>
                        <option value='content:"POST"; http_method;'>POST</option>
                        <option value='content:"HEAD"; http_method;'>HEAD</option>
                        <option value='content:"TRACE"; http_method;'>TRACE</option>
                        <option value='content:"PUT"; http_method;'>PUT</option>
                        <option value='content:"DELETE"; http_method;'>DELETE</option>
                        <option value='content:"CONNECT"; http_method;'>CONNECT</option>
                        <option selected="selected" value="">HTTP REQUEST METHOD</option>
                    </select>
                &nbsp<select  class="tcpinputs" style="border-radius:5px; background-color:#f2f2f2; padding:3px;" id="httpstatuscode">
                    <option value="100">100</option>
                    <option value="101">101</option>
                    <option value="200">200</option>
                    <option value="201">201</option>
                    <option value="202">202</option>
                    <option value="203">203</option>
                    <option value="204">204</option>
                    <option value="205">205</option>
                    <option value="206">206</option>
                    <option value="300">300</option>
                    <option value="301">301</option>
                    <option value="302">302</option>
                    <option value="303">303</option>
                    <option value="304">304</option>
                    <option value="305">305</option>
                    <option value="306">306</option>
                    <option value="307">307</option>
                    <option value="400">400</option>
                    <option value="401">401</option>
                    <option value="402">402</option>
                    <option value="403">403</option>
                    <option value="404">404</option>
                    <option value="405">405</option>
                    <option value="406">406</option>
                    <option value="407">407</option>
                    <option value="408">408</option>
                    <option value="409">409</option>
                    <option value="410">410</option>
                    <option value="411">411</option>
                    <option value="412">412</option>
                    <option value="413">413</option>
                    <option value="415">415</option>
                    <option value="416">416</option>
                    <option value="417">417</option>
                    <option value="500">500</option>
                    <option value="501">501</option>
                    <option value="502">502</option>
                    <option value="503">503</option>
                    <option value="504">504</option>
                    <option value="505">505</option>
                    <option selected="selected" value="">HTTP RESPONSE CODE</option>
                    </select></br>
                    </br></br>
                    ACK
                    <input style="border-radius:5px; background-color:#f2f2f2; padding:3px;" id="ACK" class=" check2 opflags opflags" type="checkbox" value="A" />&nbsp;SYN<input id="SYN"  class=" check2 opflags" type="checkbox" value="S" />&nbsp;PSH<input id="PSH"  class=" check2 opflags" type="checkbox" value="P" />&nbsp;RST<input id="RST"  class=" check2 opflags" type="checkbox" value="R" />&nbsp;FIN<input id="FIN"  class=" check2 opflags" type="checkbox" value="F" />&nbsp;URG<input id="URG"  class=" check2 opflags" type="checkbox" value="U" />&nbsp;+<input id="flagplus" class=" check2 opflags flagoptions" type="checkbox" value="+" />&nbsp;*<input id="wildcard" class=" check2 opflags flagoptions" type="checkbox" value="*" /></br>
                    </br></br>
                    <select class="tcpinputs" id="tcpdirectionForm">
                        <option value="FROM_SERVER">FROM_SERVER</option>
                        <option value="TO_SERVER">TO_SERVER</option>
                        <option value="TO_CLIENT">TO_CLIENT</option>
                        <option value="FROM_CLIENT">FROM_CLIENT</option>
                        <option selected="selected" value="">DIRECTION</option>
                    </select>
                    &nbsp
                    <select  class="tcpinputs" id="tcpstateForm">
                        <option value="established">established</option>
                        <option value="stateless">stateless</option>
                        <option value="not_established">not_established</option>
                        <option selected="selected" value="">TCP STATE</option>
                    </select>
                </div>
                <!-- UDP Options -->
                <div id="udp" class="selectedProtoOptions">
                    </br></br></br><h2>UDP</h2>
                    </br></br></br>
                    <select style="width: 90%;" id="udpdirectionForm">
                        <option value="FROM_SERVER">FROM_SERVER</option>
                        <option value="TO_SERVER">TO_SERVER</option>
                        <option value="TO_CLIENT">TO_CLIENT</option>
                        <option value="FROM_CLIENT">FROM_CLIENT</option>
                        <option selected="selected" value="">DIRECTION</option>
                    </select>
                </div>
                <!-- ICMP Options -->
                <div id="icmp" class="selectedProtoOptions">
                    </br></br></br><h2>ICMP</h2>
                    <select  class="tcpinputs" id="icmptypeevaluator">
                    <option value="&gt;">&gt;</option>
                    <option value="&lt;">&lt;</option>
                    <option value="=">=</option>
                    <option selected="selected" value="">ICMP TYPE</option>
                    </select>
                        <input  class="tcpinputs" id="icmptype" type="text" />
                        </br>
                    </br></br></br>
                    <select  class="tcpinputs" id="icmpcodeevaluator">
                        <option value="&gt;">&gt;</option>
                        <option value="&lt;">&lt;</option>
                        <option value="=">=</option>
                        <option selected="selected" value="">ICMP CODE</option>
                    </select>
                    <input  class="tcpinputs" id="icmpcode" type="text" />
                </div>
                <!-- Horozontal Line -->
                <hr class="style1">
                <!-- This holds the threshold tracking and reference input -->
                <div id="miscOptions">
                    <select id="datasizeEval" style="width: 30%;">
                        <option value="&gt;">&gt;</option>
                        <option value="&lt;">&lt;</option>
                        <option value="=">=</option>
                        <option selected="selected" value="">Data Size</option>
                    </select>
                    &nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
                    <input style="width: 50%;" id="datasize"type="text" /></p>
                    <select id="reftype" style="width: 30%;">
                        <option value="URL">URL</option>
                        <option value="CVE">CVE</option>
                        <option value="BUG">BUG</option>
                        <option value="MSB">MSB</option>
                        <option value="NESS">NESS</option>
                        <option value="ARAC">ARAC</option>
                        <option value="OSVD">OSVD</option>
                        <option value="MCAF">MCAF</option>
                        <option selected="selected" value="">Reference</option>
                    </select>
                    &nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
                    <input  style="width: 50%;" id="referencetext" size="40" type="text" /><div style="position: relative; height: 20px; width: 20px;"></div>
                    <select style="width: 180px" id="thresholdtype"><option value="limit">limit</option><option value="threshold">threshold</option><option value="both">both</option><option selected="selected" value="">Threshold Tracking Type</option></select>&nbsp<select style="width: 80px" id="trackby"><option value="by_src">by_src</option><option value="by_dst">by_dst</option><option selected="selected" value="">TRK BY</option></select>&nbsp<input style="width: 70px" id="count" placeholder="Count #"/>&nbsp<input style="width: 70px" id="seconds" placeholder="Seconds"/><div style="position: relative; height: 20px; width: 20px;"></div>
                </div>
            </div>
            
            <!-- This holds the content and Regex matching -->
            <div class="contentMatch mainsquares">
                <!-- The content plus image -->
                <div id="contentplus" class="item contentpluses">
                    <p class="contentHeaders">Add Content Match</p>
                    <img  class="plusexplode" id="contentArrow1" src="./images/green_plus.png" width="30" height="30">
                    <div class="item-overlay top"></div>
                </div>
                <!-- This appears when you click the green plus image -->
                <div id="contentdiv">
                        <input id="thecontent" placeholder="Content Match"></input></br>
                        <input class="diditinput" id="theoffset" placeholder="Offset"></input>
                        <input class="diditinput" id="thedepth" placeholder="Depth"></input>
                        <text class="check" style="top: 78px; left: 59%;">nocase</text><input id="content1nocase" class="check" style="left: 70%;" type="checkbox" value="nocase" />
                        <text class="check" style="top: 78px; left: 76%;">uri</text><input id="content1uri" class="check" style="left: 80.3%;" type="checkbox" value="uri" />
                        <text class="check" style="top: 78px; left: 86.5%;">not</text><input id="content1not" class="check" style="left: 91.5%;" type="checkbox" value="not" />
                    <div style="left: 23px; top: 108;" id="contentcheck" class="item contentpluses">
                        <img id="" src="./images/accept.png" width="25" height="25">
                    </div>
                    <div style="left: 84px; top: 111;" id="contentcancel" class="item contentpluses">
                        <img style="" id="contentcancel" src="./images/cancel.png" width="20" height="20">
                    </div>
                    <div style="left: 55px; top: 109;" id="contentundo" class="item contentpluses">
                        <img style="" id="contentundo2" src="./images/undo.png" width="26" height="26">
                    </div>
                </div>
                <!-- Horozontal line -->
                <hr class="style1">
                <!-- Regex gree plus symbol -->
                <div  id="preplus" style="top: 245px;"  class="item contentpluses">
                    <p class="contentHeaders">Add Regex Match</p>
                    <img class="plusexplode" id="contentArrow2" src="./images/green_plus.png"  width="30" height="30">
                    <div class="item-overlay top"></div>
                </div>
                <!-- The regex panel appears when green plus symbol is clicked -->
                <div id="pcrediv">
                        <input id="theregex" placeholder="Regular Expression"></input></br>
                        <text class="check" style="top: 78px; left: 5%;">dotal /s</text><input id="redotal" class="check" style="left: 13.5%;" type="checkbox" value="nocase" />
                        <text class="check" style="top: 78px; left: 20%;">nocase</text><input id="renocase" class="check" style="left: 28.5%;" type="checkbox" value="uri" />
                        <text class="check" style="top: 78px; left: 35%;">greedy /G</text><input id="regreedy" class="check" style="left: 46.5%;" type="checkbox" value="not" />
                        <text class="check" style="top: 78px; left: 53%;">newline /m</text><input id="renewline" class="check" style="left: 66%;" type="checkbox" value="not" />
                        <text class="check" style="top: 78px; left: 73%;">whitespace /x</text><input id="rewhitespace" class="check" style="left: 89.5%;" type="checkbox" value="not" />
                    <div style="left: 23px; top: 108;" id="pcrecheck" class="item contentpluses">
                        <img id="" src="./images/accept.png" width="25" height="25">
                    </div>
                    <div style="left: 84px; top: 111;" id="pcrecancel" class="item contentpluses">
                        <img id="" src="./images/cancel.png" width="20" height="20">
                    </div>
                    <div style="left: 55px; top: 109;" id="pcreundo" class="item contentpluses">
                        <img id="pcreundo2" src="./images/undo.png" width="26" height="26">
                    </div>
                </div>
                
            </div>

            <!-- Bottom Panel Where the rule displays -->
            <div class="ruleOutput mainsquares">
                <div id="innerRuleOutput" onclick="CopyToClipboard('innerRuleOutput')">

<!-- THIS BEGINS ALL OF THE OUTPUTS TO MAKE THE RULE -->

                    <text id="opaction"></text> <!-- Action -->
                    <text id="opprotocol"></text> <!-- Protocol -->
                    <text id="opsrcip"></text> <!-- Source IP -->
                    <text id="opsrcport"></text> <!-- Source Port -->
                    <text>
                        ->
                    </text>
                    <text id="opdstip"></text>
                    <text id="opdstport"></text>
                    <text>
                        (
                    </text>
                    <text id="opmessage"></text>
                    <text id="opProtocols">  
                        <text id="optcp">
                            <text id="opHttp"></text>

                            <text id="flagscombined"></text>
                            
                            <text id="optcpdirection"></text>                    

                        </text>

                        <text id="opimcp">
                            <text id="optype"></text>
                            <text id="opcode"></text>
                        </text>

                        
                        <text id="opudp"></text>
                        
                        <text id="opip">
                            <text id="opttl"></text>
                            <text id="opipprotocol"></text>
                        </text>
                    </text>
                    <!-- CONTENT -->
                    <text id="opcontentContainer"></text>
                    <!-- PCRE -->
                    <text id="oppcre"></text>

                    <!-- MISC -->
                    <text id="opmisc">
                        <text id="opdatasize"></text>
                        <text id="opreference"></text>
                        <text id="opthreshold"></text>
                    </text>
                    

                    <!-- End of Header -->

                    <text id="opclasstype"></text>
                    <text id="oppriority"></text>
                    <text id="opgid"></text>
                    <text id="opsid"></text>
                    <text id="oprevnum"></text>

                    <text>
                        )
                    </text>

                </div>
            </div>
        </div>
        <p></p>
        <p></p>
    <h2 id="GlobalResults">Test</h2>

    </body>
    <script src="./js/particles.js"></script>
    <script src="./js/part.js"></script>
    <script src="./js/jquery.min.js"></script>
    <script src="./js/jquery-ui.js"></script>
    <script src="./js/snorpy.js"></script>

</html>