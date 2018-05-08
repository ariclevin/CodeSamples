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
