/*
 * Copyright 2016 Cinegy GmbH

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using CommandLine;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static System.String;

namespace RtspNmosRelay
{
    /// <summary>
    /// RtspNmosRelay - for taking RTSP streams, decorating with NMOS headers / packets, and re-emitting as multicast
    /// 
    /// This code is *very* not production - the purpose was to create a simple tool which worked with a camera on my desk to make 'real' NMOS compressed streams :-)
    /// 
    /// Originally created by Lewis, so direct complaints his way...
    /// </summary>
    class Program
    {
        private enum ExitCodes
        {
            NullOutputWriter = 100,
            AuthenticationError = 401,
            UnknownError = 2000
        }

        private static bool _receiving;

        private static Options _options;
        private static UdpClient _outputClient;
        
        private static StreamWriter _logFileStreamWriter;
        private static BinaryWriter _elemFileBinaryWriter;
        private static BinaryWriter _rtpFileBinaryWriter;

        private static string _sdp = Empty;
        private static byte[] _spsData;
        private static byte[] _ppsData;

        private static ushort _lastRtpSequenceNumber;
        
        private static readonly RtpReorderBuffer RtpInputReorderBuffer = new RtpReorderBuffer();
        
        static void Main(string[] args)
        {
            Console.SetWindowSize(120, 40);
            
            _options = new Options();
            
            if (Parser.Default.ParseArguments(args, _options))
            {
                PrintToConsole("Cinegy RTSP to NMOS Multicast Relay");
                PrintToConsole($"v1.0.0 - {File.GetCreationTime(Assembly.GetExecutingAssembly().Location)})\n");

                if (!IsNullOrEmpty(_options.RecordFile))
                    PrepareOutputFiles(_options.RecordFile);

                PrepareRtpPacketizer();

                _outputClient = PrepareOutputClient(_options.MulticastAddress, _options.MulticastGroup);

                var rtpPort = StartListeningToNetwork();
                
                SendRtspSetup(new Uri( _options.RtspUrl), rtpPort);

                Console.WriteLine("\nHit q to quit");

                var doExit = false;

                while (!doExit)
                {
                    var keypress = Console.ReadKey();

                    if (keypress.KeyChar == 'q')
                    {
                        doExit = true;
                    }
                }

                PrintToConsole("Terminating Rtsp NMOS Relay");
                _receiving = false;

            }
            else
            {
                //if arguments are screwed up, this will print to screen (via the CommandLine library conventions) - then this waits for exit
                PrintToConsole("Press enter to exit");
                Console.ReadLine();
            }
        }
        
        private static void SendRtspSetup(Uri rtspUrl, int rtpPort)
        {
            //this method is just a mess - it was left 'simple' but brittle because this made intial debugging clearer.
            //it should be refactored into a cleaner subroutine.
            //Also, it should be split out to a thread, since it blocks (RTSP control messages must be sent at least
            //every 60 seconds, or RTP timesout).
            //Clean quit should be set up to issue 'TEARDOWN' request to for stopping RTP data unicast.

            PrintToConsole($"Accessing RTSP from URL {rtspUrl}");

            var cseq = 1;
            var rtspControlClient = new TcpClient { ExclusiveAddressUse = false };

            rtspControlClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            rtspControlClient.ExclusiveAddressUse = false;
            rtspControlClient.Client.ReceiveBufferSize = 1024 * 256;
            rtspControlClient.Connect(rtspUrl.Host,554);
            var strippedUri = rtspUrl.ToString(); //= RtspUrl.Scheme + "://" + RtspUrl.Authority + RtspUrl.AbsolutePath;
           
            try
            {
                var auth = Empty;
                var msg =
                    $"OPTIONS {strippedUri} RTSP/1.0\r\nCSeq: {cseq++}\r\nUser-Agent: Cinegy RTSP Relay\r\n\r\n";

                PrintToConsole(msg, true);

                var ascii = Encoding.ASCII.GetBytes(msg);
                rtspControlClient.Client.Send(ascii);
                var buf = new byte[1024];
                var recvSize = rtspControlClient.Client.Receive(buf, 1024, SocketFlags.None);

                msg = Encoding.ASCII.GetString(buf, 0, recvSize);
                PrintToConsole(msg, true);

                if (msg.Contains("401"))
                {
                    auth = GenerateAuthHeader(msg, rtspUrl);

                    msg =
                        $"OPTIONS {strippedUri} RTSP/1.0\r\nCSeq: {cseq++}\r\n{auth}User-Agent: Cinegy RTSP Relay\r\n\r\n";

                    PrintToConsole(msg, true);

                    ascii = Encoding.ASCII.GetBytes(msg);
                    rtspControlClient.Client.Send(ascii);

                    recvSize = rtspControlClient.Client.Receive(buf, 1024, SocketFlags.None);

                    msg = Encoding.ASCII.GetString(buf, 0, recvSize);
                    PrintToConsole(msg, true);
                }

                if (msg.Contains("401"))
                {
                    PrintToConsole("Authentication failed! Hit any key to quit");
                    Console.ReadLine();
                    Environment.Exit((int)ExitCodes.AuthenticationError);
                }

                msg =
                    $"DESCRIBE {strippedUri} RTSP/1.0\r\nCSeq: {cseq++}\r\n{auth}User-Agent: Cinegy RTSP Relay\r\nAccept: application/sdp\r\n\r\n";

                PrintToConsole(msg, true);

                ascii = Encoding.ASCII.GetBytes(msg);
                rtspControlClient.Client.Send(ascii);

                recvSize = rtspControlClient.Client.Receive(buf, 1024, SocketFlags.None);

                _sdp = Encoding.ASCII.GetString(buf, 0, recvSize);

                
                if (_sdp.Contains("401"))
                {
                    auth = GenerateAuthHeader(_sdp, new Uri(strippedUri));

                    msg =
                        $"DESCRIBE {strippedUri} RTSP/1.0\r\nCSeq: {cseq++}\r\n{auth}User-Agent: Cinegy RTSP Relay\r\nAccept: application/sdp\r\n\r\n";

                    PrintToConsole(msg, true);

                    ascii = Encoding.ASCII.GetBytes(msg);
                    rtspControlClient.Client.Send(ascii);

                    recvSize = rtspControlClient.Client.Receive(buf, 1024, SocketFlags.None);

                    _sdp = Encoding.ASCII.GetString(buf, 0, recvSize);
                }

                var sdpParts = _sdp.Split('\n');

                foreach (var sdpPart in sdpParts.Where(part => part.Contains("a=fmtp:96")))
                {
                    var fmptParts = sdpPart.Split(';');
                    foreach (var fmptPart in fmptParts.Where(fmptPart => fmptPart.Contains("sprop-parameter-sets=")))
                    {
                        var spropData = fmptPart.Replace("sprop-parameter-sets=", Empty);
                        var spsBase64Data = spropData.Split(',')[0].Trim();
                        var ppsBase64Data = spropData.Split(',')[1].Trim();
                        _spsData = Convert.FromBase64String(spsBase64Data);
                        _ppsData = Convert.FromBase64String(ppsBase64Data);
                    }
                }

                PrintToConsole(_sdp, true);

                var clientPort = $"{rtpPort}-{rtpPort + 1}";

                //TODO: this should be calculated from SDP and set - not just hardcoded to 0, or overridden by argument :-)
                var trackId = 0; 

                if (_options.OverrideTrackSelection > -1)
                {
                    trackId = _options.OverrideTrackSelection;
                }

                msg =
                  $"SETUP {strippedUri}/trackID={trackId} RTSP/1.0\r\nCSeq: {cseq++}\r\n{auth}Transport: RTP/AVP;unicast;client_port={clientPort}\r\nUser-Agent: Cinegy RTSP Relay\r\n\r\n";

                PrintToConsole(msg, true);

                ascii = Encoding.ASCII.GetBytes(msg);
                rtspControlClient.Client.Send(ascii);

                recvSize = rtspControlClient.Client.Receive(buf, 1024, SocketFlags.None);

                msg = Encoding.ASCII.GetString(buf, 0, recvSize);
                var session = "0";

                var parts = msg.Split('\n');
                foreach (var part in parts.Where(part => part.Contains("Session")))
                {
                    session = part.Split(':')[1].Trim();
                    if (session.Contains(';'))
                    {
                        session = session.Substring(0, session.IndexOf(';'));
                    }
                }

                PrintToConsole(msg, true);

                msg =
                      $"PLAY {strippedUri} RTSP/1.0\r\nCSeq: {cseq++}\r\n{auth}User-Agent: Cinegy RTSP Relay\r\nSession: {session}\r\nRange: npt = 0.000 -\r\n\r\n";

                PrintToConsole(msg, true);

                ascii = Encoding.ASCII.GetBytes(msg);
                rtspControlClient.Client.Send(ascii);

                recvSize = rtspControlClient.Client.Receive(buf, 1024, SocketFlags.None);

                msg = Encoding.ASCII.GetString(buf, 0, recvSize);

                PrintToConsole(msg, true);

                while (true)
                {
                    msg =
                        $"GET_PARAMETER {strippedUri} RTSP/1.0\r\nCSeq: {cseq++}" +
                        $"\r\n{auth}User-Agent: Cinegy RTSP Relay\r\nSession: {session}\r\n\r\n";

                    PrintToConsole(msg, true);

                    ascii = Encoding.ASCII.GetBytes(msg);
                    rtspControlClient.Client.Send(ascii);

                    recvSize = rtspControlClient.Client.Receive(buf, 1024, SocketFlags.None);

                    msg = Encoding.ASCII.GetString(buf, 0, recvSize);

                    PrintToConsole(msg, true);
                    Thread.Sleep(50000);
                }
            }
            catch (Exception ex)
            {
                PrintToConsole($@"Unhandled exception within network receiver: {ex.Message}");
                Console.WriteLine("\nHit any key to quit");
                Console.ReadKey();
                Environment.Exit((int)ExitCodes.UnknownError);
            }
        }

        private static string GenerateAuthHeader(string input, Uri rtspUri)
        {
            var parts = input.Split('\n');
            foreach (var part in parts.Where(part => part.Contains("WWW-Authenticate")))
            {
                var auth = part.Split(':')[1].Trim();
                if (auth.Contains("Basic"))
                {
                    var plainTextBytes = Encoding.UTF8.GetBytes($"{_options.Username}:{_options.Password}");
                    return "Authorization: Basic " + Convert.ToBase64String(plainTextBytes) + "\r\n";
                }

                if (auth.Contains("Digest"))
                {
                    return GenerateDigestHeader(auth, rtspUri, _options.Username, _options.Password);
                }
            }

            return Empty;
        }

        private static string GenerateDigestHeader(string authHeaderValue, Uri rtspUri, string username, string password)
        {
            var keyValuePairs = authHeaderValue.Split(',');
            string realm = Empty, nonce = Empty;

            foreach (var keyValuePair in keyValuePairs)
            {
                if (!keyValuePair.Contains('=')) break;

                var key = keyValuePair.Split('=')[0].Trim();
                var value = keyValuePair.Split('=')[1].Trim();

                if (key.Contains("realm"))
                {
                    realm = value.Trim('"');
                }
                else if (key.Contains("nonce"))
                {
                    nonce = value.Trim('"');
                }
            }
          
            var digestHash = GenerateDigestHash(rtspUri, username, realm, password, "OPTIONS", nonce);

            return $"Authorization: Digest username=\"{username}\",realm=\"{realm}\",nonce=\"{nonce}\",uri=\"{rtspUri}\",response=\"{digestHash}\"\r\n";

        }
        
        private static UdpClient PrepareOutputClient(string multicastAddress, int multicastGroup)
        {
            var outputIp = _options.OutputAdapterAddress != null ? IPAddress.Parse(_options.OutputAdapterAddress) : IPAddress.Any;
            PrintToConsole($"Outputting multicast data to {multicastAddress}:{multicastGroup} via adapter {outputIp}");

            var client = new UdpClient { ExclusiveAddressUse = false };
            var localEp = new IPEndPoint(outputIp, multicastGroup);

            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            client.ExclusiveAddressUse = false;
            client.Client.Bind(localEp);

            var parsedMcastAddr = IPAddress.Parse(multicastAddress);
            client.Connect(parsedMcastAddr, multicastGroup);

            return client;
        }

        private static int StartListeningToNetwork()
        {
            _receiving = true;

            var inputIp = _options.AdapterAddress != null ? IPAddress.Parse(_options.AdapterAddress) : IPAddress.Any;

            var client = new UdpClient(0);
            var localEp = (IPEndPoint)client.Client.LocalEndPoint;

            PrintToConsole($"Looking for packets on port {localEp.Port} via adapter {inputIp}");

            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            client.Client.ReceiveBufferSize = 1024 * 256;
            localEp.Address = inputIp;
            
            var ts = new ThreadStart(delegate
            {
                ReceivingNetworkWorkerThread(client, localEp);
            });

            var receiverThread = new Thread(ts) { Priority = ThreadPriority.Highest };

            receiverThread.Start();

            return localEp.Port;
        }

        private static void PrepareRtpPacketizer()
        {
            //todo: recheck the RTP specs again, so see what the rules are about starting packet numbers, randomization, etc.
            _lastRtpSequenceNumber = 3000;
            
        }

        private static void ReceivingNetworkWorkerThread(UdpClient client, IPEndPoint localEp)
        {
            var packetsStarted = false;
            var startWriting = false;
            byte[] frameData = null;

            while (_receiving)
            {
                var data = client.Receive(ref localEp);

                if (data == null) continue;

                if (!packetsStarted)
                {
                    PrintToConsole("Started receiving packets...");
                    packetsStarted = true;
                }

                try
                {
                    var inboundPacket = new RtpPacket(data);
                    if(inboundPacket.PayloadType != 96) continue;

                    RtpInputReorderBuffer.PushNewRtpPacket(new RtpPacket(data));

                    var prevRtpSeqNum = RtpInputReorderBuffer.LastReturnedRtpSequenceNumber;
                    var bufferedPacket = RtpInputReorderBuffer.GetNextRtpPacket();

                    if (bufferedPacket == null)
                    {
                        frameData = null;
                    }
                    else
                    {
                        if (!startWriting & prevRtpSeqNum == 0)
                            prevRtpSeqNum = (ushort)(bufferedPacket.SequenceNumber - 1);
                                                    
                        if (RtpReorderBuffer.GetSequenceNumberDifference(prevRtpSeqNum,bufferedPacket.SequenceNumber)!=1) 
                        {
                            PrintToConsole(DateTime.Now + ": RTP debuffer had sequence skip");
                            frameData = null;
                            startWriting = false;
                        }

                        if (bufferedPacket.Payload[1] == 0x85) //this byte indicates start of I frame
                        {
                            startWriting = true;
                        }

                        if (bufferedPacket.Padding)
                        {
                            PrintToConsole("RTP Packet has padding... this needs to be removed - not yet implemented!!");
                        }

                        if (startWriting)
                        {
                            if ((bufferedPacket.Payload[0] & 0x1C) == 0x1c)
                            {
                                switch (bufferedPacket.Payload[1])
                                {
                                    case 0x85: //start of new I frame - should definately insert NMOS payload packet for in-stream signaling here
                                        PrintToConsole(
                                            $"I-frame start - SeqNum: {bufferedPacket.SequenceNumber}, LastTS: {bufferedPacket.Timestamp}",
                                            true);

                                        //sps
                                        frameData = AddToArray(frameData, new byte[] {0x0, 0x0, 0x0, 0x01});
                                        frameData = AddToArray(frameData, _spsData);
                                        //pps
                                        frameData = AddToArray(frameData, new byte[] {0x0, 0x0, 0x0, 0x01});
                                        frameData = AddToArray(frameData, _ppsData);
                                        //New IDR NAL
                                        frameData = AddToArray(frameData, new byte[] {0x0, 0x0, 0x0, 0x01});
                                        frameData = AddToArray(frameData, 0x45);
                                        frameData = AddToArray(frameData, bufferedPacket.Payload, 2);

                                        break;
                                    case 0x81: //start of P / B frame
                                        frameData = AddToArray(frameData, new byte[] {0x0, 0x0, 0x0, 0x01});
                                        frameData = AddToArray(frameData, 0x41);
                                        frameData = AddToArray(frameData, bufferedPacket.Payload, 2);

                                        break;
                                    case 0x05: //body of I frame
                                        frameData = AddToArray(frameData, bufferedPacket.Payload, 2);
                                        break;
                                    case 0x01: //body of P / B frame
                                        frameData = AddToArray(frameData, bufferedPacket.Payload, 2);
                                        break;
                                    case 0x41: //end of P / B frame

                                        frameData = AddToArray(frameData, bufferedPacket.Payload, 2);

                                        OutputData(frameData, bufferedPacket.Timestamp);

                                        _elemFileBinaryWriter?.Write(frameData);

                                        frameData = null;

                                        break;
                                    case 0x45: //end of I frame
                                        
                                        frameData = AddToArray(frameData, bufferedPacket.Payload, 2);

                                        OutputData(frameData, bufferedPacket.Timestamp);

                                        _elemFileBinaryWriter?.Write(frameData);

                                        frameData = null;

                                        break;
                                    default:
                                        var printLen = 3;

                                        if (printLen > bufferedPacket.Payload.Length)
                                            printLen = bufferedPacket.Payload.Length;

                                        var payloadString = BitConverter.ToString(bufferedPacket.Payload, 0, printLen);

                                        PrintToConsole(
                                            $"Unexpected indicator: 0x{bufferedPacket.Payload[1]:X}, Len: {bufferedPacket.Payload.Length}, First few bytes: {payloadString}",
                                            true);

                                        frameData = AddToArray(frameData, bufferedPacket.Payload, 2);

                                        break;
                                }
                            }
                            else //not an FU-A packed payload
                            {
                                if ((bufferedPacket.Payload[0] & 0x09) == 0x09)
                                {
                                    if (bufferedPacket.Payload.Length < 1300)
                                    {
                                        //access unit delimiter in plain NALU payload
                                        frameData = AddToArray(frameData, new byte[] {0x0, 0x0, 0x0, 0x01, 0x09});
                                        frameData = AddToArray(frameData, bufferedPacket.Payload, 2);
                                    }
                                }
                                else if ((bufferedPacket.Payload[0] & 0x07) == 0x07)
                                {
                                    //SPS
                                }
                                else if ((bufferedPacket.Payload[0] & 0x08) == 0x08)
                                {
                                    //PPS
                                }
                                else if ((bufferedPacket.Payload[0] & 0x06) == 0x06)
                                {
                                    //SEI data
                                    if (bufferedPacket.Payload.Length < 1380)
                                    {
                                        //access unit delimiter in plain NALU payload
                                        frameData = AddToArray(frameData, new byte[] {0x0, 0x0, 0x0, 0x01});
                                        frameData = AddToArray(frameData, bufferedPacket.Payload);
                                    }
                                }
                                else if ((bufferedPacket.Payload[0] & 0x01) == 0x01)
                                {
                                    //B or P frame (small payload case, total NAL in one packet
                                    if (bufferedPacket.Payload.Length < 1380)
                                    {
                                        //access unit delimiter in plain NALU payload
                                        frameData = null;

                                        frameData = AddToArray(frameData, new byte[] { 0x0, 0x0, 0x0, 0x01 });
                                        frameData = AddToArray(frameData, bufferedPacket.Payload);
                                        
                                        OutputData(frameData, bufferedPacket.Timestamp);

                                        _elemFileBinaryWriter?.Write(frameData);

                                        frameData = null;
                                    }
                                }
                                else
                                {
                                    //unknown / never seen so far
                                    var printLen = 3;

                                    if (printLen > bufferedPacket.Payload.Length)
                                        printLen = bufferedPacket.Payload.Length;

                                    var payloadString = BitConverter.ToString(bufferedPacket.Payload, 0, printLen);

                                    PrintToConsole(
                                        $"Non FU-A payload, Length: {bufferedPacket.Payload.Length}, First few bytes: {payloadString}",
                                        true);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    PrintToConsole($@"Unhandled exception within network receiver: {ex.Message}");
                }
            }
        }
        
        private static byte[] AddToArray(byte[] arr, byte[] add, int from_byte = 0)
        {
            var arr_size = 0;
            var add_size = add.Length - from_byte;
            byte[] result;

            if (arr == null)
            {
                result = new byte[add_size];
            }
            else
            {
                arr_size = arr.Length;
                result = new byte[arr_size + add_size];
                arr.CopyTo(result, 0);
            }

            Array.Copy(add, from_byte, result, arr_size, add_size);

            return result;
        }

        private static byte[] AddToArray(byte[] arr, byte val)
        {
            var result = new byte[arr.Length + 1];
            arr.CopyTo(result, 0);
            result[arr.Length] = val;
            
            return result;
        }

        private static void OutputData(byte[] data, uint timestamp)
        {
            //pack data into RTP packets:
            RtpPacket rtpPacket;

            var remainingData = data.Length;
            while(remainingData>0)
            {
                rtpPacket = new RtpPacket();
                rtpPacket.SequenceNumber = _lastRtpSequenceNumber++;
                rtpPacket.Ssrc = 123456;
                rtpPacket.PayloadType = 96;
                rtpPacket.Timestamp = timestamp;

                var serial = rtpPacket.GetPacket();

                var testRtpPacket = new RtpPacket(serial);

                //todo: look up again what the size should be to avoid fragments, and take into account extension headers - but today, just be inefficient
                if (remainingData > 1400)
                {
                    rtpPacket.Payload = new byte[1400];
                    Buffer.BlockCopy(data, data.Length - remainingData, rtpPacket.Payload, data.Length - remainingData, 1400);
                    _outputClient.Send(rtpPacket.GetPacket(), rtpPacket.PacketSize);
                    remainingData -= 1400;
                }
                else
                {
                    rtpPacket.Payload = new byte[data.Length];
                    remainingData = 0;
                    Buffer.BlockCopy(data, 0, rtpPacket.Payload, 0, data.Length);
                    _outputClient.Send(rtpPacket.GetPacket(), rtpPacket.PacketSize);
                }
            }

        }

        private static void PrepareOutputFiles(string fileName)
        {
            var file = Path.GetFileNameWithoutExtension(fileName);

            if (file == null) return;

            file = file.Replace("%T", DateTime.Now.ToString("HHmm"));
            file = file.Replace("%D", DateTime.Now.ToString("dd.MM.yy"));

            Array.ForEach(Path.GetInvalidFileNameChars(),
                c => file = file.Replace(c.ToString(), String.Empty));

            var path = Path.GetPathRoot(fileName);

            var fs = new FileStream(path + file + ".h264", FileMode.OpenOrCreate);

            _elemFileBinaryWriter = new BinaryWriter(fs);

            fs = new FileStream(path + file + ".ts", FileMode.OpenOrCreate);

            _rtpFileBinaryWriter = new BinaryWriter(fs);

            fs = new FileStream(path + file + ".txt", FileMode.OpenOrCreate);

            _logFileStreamWriter = new StreamWriter(fs);
        }

        private static void PrintToConsole(string message, bool verbose = false)
        {
            if (_logFileStreamWriter != null && _logFileStreamWriter.BaseStream.CanWrite)
            {
                _logFileStreamWriter.WriteLine("{0}\r\n------\r\n{1}", DateTime.Now.ToString("HH:mm:ss"), message);
                _logFileStreamWriter.Flush();
            }

            if (_options.Quiet)
                return;

            if ((!_options.Verbose) && verbose)
                return;

            Console.WriteLine(message);
        }

        private static string GenerateDigestHash(Uri location, string user, string realm, string pass, string method, string nonce)
        {
            var md5Hash = MD5.Create();
            
            var uriPart = location != null && location.IsAbsoluteUri ? location.AbsoluteUri : new string('\\', 1);
            
            var a1Hash = md5Hash.ComputeHash(Encoding.UTF8.GetBytes($"{user}:{realm}:{pass}"));
            var a2Hash = md5Hash.ComputeHash(Encoding.UTF8.GetBytes($"{method}:{uriPart}"));
            var a1NonceA2String = Format(System.Globalization.CultureInfo.InvariantCulture, "{0}:{1}:{2}",
                BitConverter.ToString(a1Hash).Replace("-", Empty).ToLowerInvariant(), nonce,
                BitConverter.ToString(a2Hash).Replace("-", Empty).ToLowerInvariant());

            var a1NonceA2Hash= md5Hash.ComputeHash(Encoding.UTF8.GetBytes(a1NonceA2String));

            var a1NonceA2HexHash = BitConverter.ToString(a1NonceA2Hash).Replace("-", "").ToLowerInvariant();

            return a1NonceA2HexHash;
        }


    }
}
