using CommandLine;
using CommandLine.Text;

namespace RtspNmosRelay
{
    internal class Options
    {
        [Option('u', "url", Required = true,
            HelpText = "RTSP Url to read from")]
        public string RtspUrl { get; set; }

        [Option('a', "inputadapter", Required = false,
            HelpText = "IP address of the adapter that will receive video")]
        public string AdapterAddress { get; set; }

        [Option('b', "outputadapter", Required = false,
            HelpText = "IP address of the adapter to write the RTP stream to (has a random guess if left blank).")]
        public string OutputAdapterAddress { get; set; }

        [Option('m', "multicastaddress", Required = true,
            HelpText = "Output multicast address to write to.")]
        public string MulticastAddress { get; set; }

        [Option('g', "mulicastgroup", Required = true,
            HelpText = "Output multicast group port to write to.")]
        public int MulticastGroup { get; set; }
        
        [Option('q', "quiet", Required = false, DefaultValue = false,
            HelpText = "Run in quiet mode - print nothing to console.")]
        public bool Quiet { get; set; }

        [Option('v', "verbose", Required = false, DefaultValue = false,
            HelpText = "Run in verbose mode.")]
        public bool Verbose { get; set; }

        [Option('r', "record", Required = false,
            HelpText = "Record output stream to a specified file.")]
        public string RecordFile { get; set; }

        [Option('n', "username", Required = false,
          HelpText = "Username for any RTSP login (if authentication required")]
        public string Username { get; set; }

        [Option('p', "password", Required = false,
        HelpText = "Password for any RTSP login (if authentication required")]
        public string Password { get; set; }
       
        [Option('t', "forcedtrack", Required = false, DefaultValue = -1,
        HelpText = "Forces the selection of an specific SDP track selection (debugging).")]
        public int OverrideTrackSelection { get; set; }
        
        [ParserState]
        public IParserState LastParserState { get; set; }

        [HelpOption]
        public string GetUsage()
        {
            var msg = HelpText.AutoBuild(this,
                current => HelpText.DefaultParsingErrorsHandler(this, current));

            return msg;
        }

    }
}