// Make sure to Add 
using System.Net.Mail;

// Usage
/*
MailService mailer = new MailService("CONTOSO", "Administrator", "PASSWORD", "exchange.contoso.com", 25);
string from = "Administrator [admin@contoso.com]";
string to = "Manager [manager@contoso.com]";
string subject = "Test Message to Manager";
string body = "This is the content of the message";
mailer.SendEmail(from, to, "", "", subject, body);
	public static string SecurityCode { get; set; }

	public static string Decrypt(string cryptedString)
	{
		byte[] bytes = System.Text.Encoding.ASCII.GetBytes(SecurityCode.ToString());
		if (String.IsNullOrEmpty(cryptedString))
		{
			throw new ArgumentNullException
			   ("The string which needs to be decrypted can not be null.");
		}
		DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
		MemoryStream memoryStream = new MemoryStream
				(Convert.FromBase64String(cryptedString));
		CryptoStream cryptoStream = new CryptoStream(memoryStream,
			cryptoProvider.CreateDecryptor(bytes, bytes), CryptoStreamMode.Read);
		StreamReader reader = new StreamReader(cryptoStream);
		return reader.ReadToEnd();
	}

	public static string Encrypt(string originalString)
	{
		byte[] bytes = System.Text.Encoding.ASCII.GetBytes(SecurityCode.ToString());
		if (String.IsNullOrEmpty(originalString))
		{
			throw new ArgumentNullException
				   ("The string which needs to be encrypted can not be null.");
		}
		DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
		MemoryStream memoryStream = new MemoryStream();
		CryptoStream cryptoStream = new CryptoStream(memoryStream,
			cryptoProvider.CreateEncryptor(bytes, bytes), CryptoStreamMode.Write);
		StreamWriter writer = new StreamWriter(cryptoStream);
		writer.Write(originalString);
		writer.Flush();
		cryptoStream.FlushFinalBlock();
		writer.Flush();
		return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length);
	}

	public static string StripPunctuation(this string s)
	{
		var sb = new StringBuilder();
		foreach (char c in s)
		{
			// if ((char.IsLetterOrDigit(c)) || (char.IsWhiteSpace(c)))
			if (char.IsLetterOrDigit(c))
				sb.Append(c);
		}
		return sb.ToString();
	}

	public static int ToInt(this Enum i)
	{
		return Convert.ToInt32(i);
	}

	public static string GenerateEmailAddressFromString(this string s, string prefix, string suffix)
	{
		string rc = System.Text.RegularExpressions.Regex.Replace(s, "[^a-zA-Z0-9]", "").ToLower();
		if (!string.IsNullOrEmpty(prefix))
			rc = prefix + "_" + rc;
		rc += "@" + suffix;
		return rc;
	}

	public static string BuildCRMRecordUrl(string organizationUrl, string organizationName, string entityName, Guid recordId)
	{
		bool hasErrors = false;
		StringBuilder sb = new StringBuilder();
		sb.Append(organizationUrl);
		if (!organizationUrl.EndsWith(@"/"))
			sb.Append(@"/");

		if (!string.IsNullOrEmpty(organizationName))
		{
			sb.Append(organizationName);
			if (!organizationUrl.EndsWith(@"/"))
				sb.Append(@"/");
		}

		sb.Append("main.aspx?pagetype=entityrecord&etn=" + entityName);
		sb.Append("&id=" + recordId.ToString());
		return sb.ToString();
	}

	//TODO: Generate Full Address Function
	public static string GenerateFullAddress(string line1, string line2, string line3, string department, string mailstop, string city, string state, string postalcode)
	{
		StringBuilder sb = new StringBuilder();
		// ADDRESS FORMAT:
		// Department
		// Street 1, Mail Stop
		// Street 2
		// City, State Zip

		if (!string.IsNullOrEmpty(department))
			sb.AppendLine(department);

		if (!String.IsNullOrEmpty(line1))
		{
			sb.Append(line1);
			if (!String.IsNullOrEmpty(mailstop))
				sb.AppendLine(", " + mailstop);
			else
				sb.AppendLine();
		}

		if (!String.IsNullOrEmpty(line2))
			sb.AppendLine(line2);

		if (!String.IsNullOrEmpty(city))
		{
			sb.Append(city);
			if (!String.IsNullOrEmpty(state))
			{
				sb.Append(", " + state);
				if (!String.IsNullOrEmpty(postalcode))
				{
					sb.Append(" " + postalcode);
				}
			}
			else
			{
				if (!String.IsNullOrEmpty(postalcode))
				{
					sb.Append(" " + postalcode);
				}
			}
		}
		else
		{
			if (!String.IsNullOrEmpty(state))
			{
				sb.Append(", " + state);
				if (!String.IsNullOrEmpty(postalcode))
				{
					sb.Append(" " + postalcode);
				}
			}
			else
			{
				if (!String.IsNullOrEmpty(postalcode))
				{
					sb.Append(" " + postalcode);
				}
			}
		}
		return sb.ToString();
	}

	public static bool IsEmailRegex(string emailAddress)
	{
		//  string patternLenient = @"\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*";
		//  Regex reLenient = new Regex(patternLenient);
		string patternStrict = @"^(([^<>()[\]\\.,;:\s@\""]+" + @"(\.[^<>()[\]\\.,;:\s@\""]+)*)|(\"".+\""))@"
			  + @"((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" + @"\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+" + @"[a-zA-Z]{2,}))$";
		Regex reStrict = new Regex(patternStrict);

		bool isStrictMatch = reStrict.IsMatch(emailAddress);
		return isStrictMatch;
	}
}
*/

public class MailService
{

	private string Domain = "";
	private string UserName = "";
	private string Password = "";
	private string MailServer = ""
	private int PortNumber = "";

	public MailService(string domain, string userName, string password, string mailServer, int portNumber = 25)
	{
		Domain = domain;
		UserName = userName;
		Password = password;
		MailServer = mailServer;
		PortNumber = portNumber;
	}
	
	public int SendEmail(string From, string To, string Cc, string Bcc, string Subject, string Body)
	{
		MailMessage message = new MailMessage();
		int BracketPos = 0; string eMailAddress = "", DisplayName = "";

		BracketPos = From.IndexOf("[");
		if (BracketPos > 0)
		{
			eMailAddress = From.Substring(BracketPos + 1, From.Length - BracketPos - 2);
			DisplayName = From.Substring(0, BracketPos);
			message.From = new MailAddress(eMailAddress, DisplayName);
		}
		else
			message.From = new MailAddress(From, From);

		BracketPos = To.IndexOf("[");
		if (BracketPos > 0)
		{
			eMailAddress = To.Substring(BracketPos + 1, To.Length - BracketPos - 2);
			DisplayName = To.Substring(0, BracketPos);
			message.To.Add(new MailAddress(eMailAddress, DisplayName));
		}
		else
			message.To.Add(new MailAddress(To, To));

		if (!string.IsNullOrEmpty(Cc))
		{
			BracketPos = Cc.IndexOf("[");
			if (BracketPos > 0)
			{
				eMailAddress = Cc.Substring(BracketPos + 1, Cc.Length - BracketPos - 2);
				DisplayName = Cc.Substring(0, BracketPos);
				message.CC.Add(new MailAddress(eMailAddress, DisplayName));
			}
			else
				message.CC.Add(new MailAddress(Cc, Cc));
		}
		if (!string.IsNullOrEmpty(Bcc))
		{
			BracketPos = Bcc.IndexOf("[");
			if (BracketPos > 0)
			{
				eMailAddress = Bcc.Substring(BracketPos + 1, Bcc.Length - BracketPos - 2);
				DisplayName = Bcc.Substring(0, BracketPos);
				message.Bcc.Add(new MailAddress(eMailAddress, DisplayName));
			}
			else
				message.Bcc.Add(new MailAddress(Bcc, Bcc));
		}

		message.Subject = Subject;
		message.Body = Body;
		message.IsBodyHtml = true;

		SmtpClient client = new SmtpClient(MailServer, PortNumber);
		client.DeliveryMethod = SmtpDeliveryMethod.Network;
		string user = Domain + @"\" + UserName;
		client.Credentials = new System.Net.NetworkCredential(user, Password);

		int retVal = 0;
		try
		{
			client.Send(message);
		}
		catch (System.Exception ex)
		{

		}

		return retVal;
	}
}

}

	// BriteOne
	public string Decrypt(string cryptedString)
	{
		byte[] bytes = System.Text.Encoding.ASCII.GetBytes(SecurityCode.ToString());
		if (String.IsNullOrEmpty(cryptedString))
		{
			throw new ArgumentNullException
			   ("The string which needs to be decrypted can not be null.");
		}
		DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
		MemoryStream memoryStream = new MemoryStream
				(Convert.FromBase64String(cryptedString));
		CryptoStream cryptoStream = new CryptoStream(memoryStream,
			cryptoProvider.CreateDecryptor(bytes, bytes), CryptoStreamMode.Read);
		StreamReader reader = new StreamReader(cryptoStream);
		return reader.ReadToEnd();
	}

	public string Encrypt(string originalString)
	{
		byte[] bytes = System.Text.Encoding.ASCII.GetBytes(SecurityCode.ToString());
		if (String.IsNullOrEmpty(originalString))
		{
			throw new ArgumentNullException
				   ("The string which needs to be encrypted can not be null.");
		}
		DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
		MemoryStream memoryStream = new MemoryStream();
		CryptoStream cryptoStream = new CryptoStream(memoryStream,
			cryptoProvider.CreateEncryptor(bytes, bytes), CryptoStreamMode.Write);
		StreamWriter writer = new StreamWriter(cryptoStream);
		writer.Write(originalString);
		writer.Flush();
		cryptoStream.FlushFinalBlock();
		writer.Flush();
		return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length);
	}

}
