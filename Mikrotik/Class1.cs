using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net.Sockets;
using System.Management;
using System.Management.Automation;
using System.Xml;
using System.Text.RegularExpressions;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Mikrotik
{
    public class MikrotikConnectionObj
    {
        Stream connection;
        TcpClient con;
        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true; // Accept all certificates
        }

        public MikrotikConnectionObj(string ip,int port, bool UseSSL)
        {
            
            if (!UseSSL)
            {
                if (port == 0) { port = 8728; }
                con = new TcpClient();
                con.Connect(ip, port);
                connection = (Stream)con.GetStream();
            }
            else
            {
                if (port == 0) { port = 8729; }

                con = new TcpClient();
                con.Connect(ip, port);
                var sslStream = new SslStream((Stream)con.GetStream(), false,
                    new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                sslStream.AuthenticateAsClient(ip/*, cCollection, SslProtocols.Default, true*/);
                connection = sslStream;

            }
        }
        public void Close()
        {
            connection.Close();
            con.Close();
        }
        public bool Login(string username, string password)
        {
            //Send("/login", true);
            //string hash = Read()[0].Split(new string[] { "ret=" }, StringSplitOptions.None)[1];
            Send("/login");
            Send("=name=" + username);
            //Send("=response=00" + EncodePassword(password, hash), true);
            Send("=password=" + password, true);
            if (Read()[0] == "!done")
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        public void Send(string co)
        {
            byte[] bajty = Encoding.ASCII.GetBytes(co.ToCharArray());
            byte[] velikost = EncodeLength(bajty.Length);

            connection.Write(velikost, 0, velikost.Length);
            connection.Write(bajty, 0, bajty.Length);
        }
        public void Send(string co, bool endsentence)
        {
            byte[] bajty = Encoding.ASCII.GetBytes(co.ToCharArray());
            byte[] velikost = EncodeLength(bajty.Length);
            connection.Write(velikost, 0, velikost.Length);
            connection.Write(bajty, 0, bajty.Length);
            connection.WriteByte(0);
        }
        public List<string> Read()
        {
            List<string> output = new List<string>();
            string o = "";
            byte[] tmp = new byte[4];
            long count;
            while (true)
            {
                tmp[3] = (byte)connection.ReadByte();
                //if(tmp[3] == 220) tmp[3] = (byte)connection.ReadByte(); it sometimes happend to me that 
                //mikrotik send 220 as some kind of "bonus" between words, this fixed things, not sure about it though
                if (tmp[3] == 0)
                {
                    output.Add(o);
                    if (o.Substring(0, 5) == "!done")
                    {
                        break;
                    }
                    else
                    {
                        o = "";
                        continue;
                    }
                }
                else
                {
                    if (tmp[3] < 0x80)
                    {
                        count = tmp[3];
                    }
                    else
                    {
                        if (tmp[3] < 0xC0)
                        {
                            int tmpi = BitConverter.ToInt32(new byte[] { (byte)connection.ReadByte(), tmp[3], 0, 0 }, 0);
                            count = tmpi ^ 0x8000;
                        }
                        else
                        {
                            if (tmp[3] < 0xE0)
                            {
                                tmp[2] = (byte)connection.ReadByte();
                                int tmpi = BitConverter.ToInt32(new byte[] { (byte)connection.ReadByte(), tmp[2], tmp[3], 0 }, 0);
                                count = tmpi ^ 0xC00000;
                            }
                            else
                            {
                                if (tmp[3] < 0xF0)
                                {
                                    tmp[2] = (byte)connection.ReadByte();
                                    tmp[1] = (byte)connection.ReadByte();
                                    int tmpi = BitConverter.ToInt32(new byte[] { (byte)connection.ReadByte(), tmp[1], tmp[2], tmp[3] }, 0);
                                    count = tmpi ^ 0xE0000000;
                                }
                                else
                                {
                                    if (tmp[3] == 0xF0)
                                    {
                                        tmp[3] = (byte)connection.ReadByte();
                                        tmp[2] = (byte)connection.ReadByte();
                                        tmp[1] = (byte)connection.ReadByte();
                                        tmp[0] = (byte)connection.ReadByte();
                                        count = BitConverter.ToInt32(tmp, 0);
                                    }
                                    else
                                    {
                                        //Error in packet reception, unknown length
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                for (int i = 0; i < count; i++)
                {
                    o += (Char)connection.ReadByte();
                }
            }
            return output;
        }
        byte[] EncodeLength(int delka)
        {
            if (delka < 0x80)
            {
                byte[] tmp = BitConverter.GetBytes(delka);
                return new byte[1] { tmp[0] };
            }
            if (delka < 0x4000)
            {
                byte[] tmp = BitConverter.GetBytes(delka | 0x8000);
                return new byte[2] { tmp[1], tmp[0] };
            }
            if (delka < 0x200000)
            {
                byte[] tmp = BitConverter.GetBytes(delka | 0xC00000);
                return new byte[3] { tmp[2], tmp[1], tmp[0] };
            }
            if (delka < 0x10000000)
            {
                byte[] tmp = BitConverter.GetBytes(delka | 0xE0000000);
                return new byte[4] { tmp[3], tmp[2], tmp[1], tmp[0] };
            }
            else
            {
                byte[] tmp = BitConverter.GetBytes(delka);
                return new byte[5] { 0xF0, tmp[3], tmp[2], tmp[1], tmp[0] };
            }
        }

        public string EncodePassword(string Password, string hash)
        {
            byte[] hash_byte = new byte[hash.Length / 2];
            for (int i = 0; i <= hash.Length - 2; i += 2)
            {
                hash_byte[i / 2] = Byte.Parse(hash.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
            }
            byte[] heslo = new byte[1 + Password.Length + hash_byte.Length];
            heslo[0] = 0;
            Encoding.ASCII.GetBytes(Password.ToCharArray()).CopyTo(heslo, 1);
            hash_byte.CopyTo(heslo, 1 + Password.Length);

            Byte[] hotovo;
            System.Security.Cryptography.MD5 md5;

            md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();

            hotovo = md5.ComputeHash(heslo);

            //Convert encoded bytes back to a 'readable' string
            string navrat = "";
            foreach (byte h in hotovo)
            {
                navrat += h.ToString("x2");
            }
            return navrat;
        }
    }
    [System.Management.Automation.Cmdlet(System.Management.Automation.VerbsCommunications.Send, "Mikrotik")]
    public class Send_Mikrotik : System.Management.Automation.PSCmdlet
    {
        [System.Management.Automation.Parameter(Position = 0, Mandatory = true)]
        public MikrotikConnectionObj Connection;
        [System.Management.Automation.Parameter(Position = 1, Mandatory = true)]
        public string Command;

        [System.Management.Automation.Parameter(Position = 2, Mandatory = false)]
        public string[] Filters;
        [System.Management.Automation.Parameter(Position = 3, Mandatory = false)]
        public string[] Attributes;


        protected override void ProcessRecord()
        {
            Connection.Send(Command);
            if (Filters !=null )
            {

                foreach (string Filter in Filters)
                {
                    if (Filter[0] == '?')
                    {
                        Connection.Send(Filter);
                    }else
                    {
                        Connection.Send('?'+Filter);
                    }        
                }
            }

            if (Attributes != null)
            {

                foreach (string attr in Attributes)
                {
                    if (attr[0] == '=')
                    {
                        Connection.Send(attr);
                    }
                    else
                    {
                        Connection.Send('=' + attr);
                    }
                }
            }

            Connection.Send(".tag=MTPS", true);
            List<string> k = Connection.Read();
            string[] ret = k[0].Split('=');
                if (ret[0] == "!trap.tag" && ret[1] == "MTPS")
                {
                Console.WriteLine(ret[Array.IndexOf(ret, "message") + 1]);
                  WriteObject(null);
                    return;
                }
                else if (ret[0] == "!re.tag" && ret[1] == "MTPS")
                {
                List<string> retval=new List<string>();
                k.RemoveAt(k.Count - 1);

                foreach (string s in k)
                {
                    
                    string t=s.Substring(s.IndexOf("MTPS=") + 5, s.Length - s.IndexOf("MTPS=") -5);
                    retval.Add(t);
                }
                
                    WriteObject(retval);
               } 
                
            
        }
    }
    [System.Management.Automation.Cmdlet(System.Management.Automation.VerbsCommunications.Connect, "Mikrotik")]
    public class Connect_Mikrotik : System.Management.Automation.PSCmdlet
    {
        [System.Management.Automation.Parameter(Position = 0, Mandatory = true)]
        public string IPaddress;
        [System.Management.Automation.Parameter(Position = 1, Mandatory = false)]
        public int Port=0;

        [System.Management.Automation.Parameter(Position = 2, Mandatory = true)]
        public string UserName;
        [System.Management.Automation.Parameter(Position = 3, Mandatory = false)]
        public string Password;
        [System.Management.Automation.Parameter(Position = 4, Mandatory = false)]
        public SwitchParameter UseSSL;

        protected override void ProcessRecord()
        {
            MikrotikConnectionObj mikrotik = new MikrotikConnectionObj(IPaddress,Port,UseSSL);
            if (Password == null) { Password = ""; }
            if (!mikrotik.Login(UserName,Password))
            {
                Console.WriteLine("Could not log in");
                mikrotik.Close();
                return;
            }

            mikrotik.Send("/system/identity/getall");
            mikrotik.Send(".tag=MTPS", true);
            List<string> k = mikrotik.Read();
            string[] ret = k[0].Split('=');
            if (ret[0] == "!trap.tag" && ret[1] == "MTPS")
            {
                Console.WriteLine(ret[Array.IndexOf(ret, "message") + 1]);
                WriteObject(mikrotik);
                return;
            }
            else if (ret[0] == "!re.tag" && ret[1] == "MTPS")
            {
                List<string> retval = new List<string>();
                k.RemoveAt(k.Count - 1);

                foreach (string s in k)
                {

                    string t = s.Substring(s.IndexOf("MTPS=") + 5, s.Length - s.IndexOf("MTPS=") - 5);
                    retval.Add(t);
                }

                if (retval[0].Contains("name=")) { Console.WriteLine("Connected to {0} , Identity={1}", IPaddress,retval[0].Substring(5, retval[0].Length - 5)); }
            }

                WriteObject(mikrotik);           
        }
    }

    [System.Management.Automation.Cmdlet(System.Management.Automation.VerbsCommunications.Disconnect, "Mikrotik")]
    public class Disconnect_Mikrotik : System.Management.Automation.PSCmdlet
    {
        [System.Management.Automation.Parameter(Position = 0, Mandatory = true)]
        public MikrotikConnectionObj Connection;
        protected override void ProcessRecord()
        {
            Connection.Close();           
        }
    }
   
}
 