using System;
using System.IO;
using System.Text;

using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

namespace BillionLaughsTester
{
    internal class Program
    {
		static void Main(string[] args)
		{

			Console.WriteLine(@"-------------------------------------------------
Testing for framework libraries vulnerable to the ""Billion Laughs"" vulnerability
See: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#net
-------------------------------------------------
");


			// Run the different experiments
			ExperimentXmlDictionaryReader(false);
			ExperimentXmlDictionaryReader(true);
			ExperimentXmlReader(false);
			ExperimentXmlReader(true);
			ExperimentXmlNodeReader(false);
			ExperimentXmlNodeReader(true);
			ExperimentXmlTextReader();
			ExperimentXDocument();
			ExperimentXPathDocument();
			ExperimentXmlDocument();

			Console.WriteLine("");
			Console.Write("Press any key to close.");
			_ = Console.ReadLine();
		}

		#region Experiment with Object Types

		static void ExperimentXmlDictionaryReader(bool withParse)
		{
			var settings = new XmlReaderSettings();
			var objName = "XmlDictionaryReader";

			WriteStart(objName, withParse, settings);





			foreach (int i in Enum.GetValues(typeof(XmlSizeEnum)))
			{
				try
				{
					var name = Enum.GetName(typeof(XmlSizeEnum), i);
					WriteAttempt(objName, name);
					var reader = XmlReader.Create(new MemoryStream(Encoding.ASCII.GetBytes(GetXml((XmlSizeEnum)i))), settings);
					WriteResults(objName, name, ReadFromReader(XmlDictionaryReader.CreateDictionaryReader(reader)).Length);
				}
				catch (Exception ex)
				{
					WriteException(ex);
				}
			}

			Console.WriteLine("-------------------------------------------------\n");

		}

		static void ExperimentXmlNodeReader(bool withParse)
		{
			var settings = new XmlReaderSettings();
			var objName = "XmlNodeReader";

			WriteStart(objName, withParse, settings);





			foreach (int i in Enum.GetValues(typeof(XmlSizeEnum)))
			{
				try
				{
					var doc = new XmlDocument();
					var name = Enum.GetName(typeof(XmlSizeEnum), i);
					WriteAttempt(objName, name);
					var reader = XmlReader.Create(new MemoryStream(Encoding.ASCII.GetBytes(GetXml((XmlSizeEnum)i))), settings);
					reader.MoveToContent();
					WriteResults(objName, name, ReadFromReader(new XmlNodeReader(doc.ReadNode(reader))).Length);
				}
				catch (Exception ex)
				{
					WriteException(ex);
				}
			}

			Console.WriteLine("-------------------------------------------------\n");

		}

		static void ExperimentXmlReader(bool withParse)
		{
			var settings = new XmlReaderSettings();
			var objName = "XmlReader";

			WriteStart(objName, withParse, settings);


			foreach (int i in Enum.GetValues(typeof(XmlSizeEnum)))
			{
				try
				{
					var name = Enum.GetName(typeof(XmlSizeEnum), i);
					WriteAttempt(objName, name);
					var reader = XmlReader.Create(new MemoryStream(Encoding.ASCII.GetBytes(GetXml((XmlSizeEnum)i))), settings);
					WriteResults(objName, name, ReadFromReader(reader).Length);
				}
				catch (Exception ex)
				{
					WriteException(ex);
				}
			}

			Console.WriteLine("-------------------------------------------------\n");

		}

		static void ExperimentXmlTextReader()
		{
			var objName = "XmlTextReader";

			WriteStart(objName);

			foreach (int i in Enum.GetValues(typeof(XmlSizeEnum)))
			{
				try
				{
					var name = Enum.GetName(typeof(XmlSizeEnum), i);
					WriteAttempt(objName, name);
					var reader = new XmlTextReader(new MemoryStream(Encoding.ASCII.GetBytes(GetXml((XmlSizeEnum)i))));
					WriteResults(objName, name, ReadFromReader(reader).Length);
				}
				catch (Exception ex)
				{
					WriteException(ex);
				}
			}

			Console.WriteLine("-------------------------------------------------\n");

		}

		static void ExperimentXDocument()
		{
			var objName = "XDocument";

			WriteStart(objName);


			foreach (int i in Enum.GetValues(typeof(XmlSizeEnum)))
			{
				try
				{
					var name = Enum.GetName(typeof(XmlSizeEnum), i);
					WriteAttempt(objName, name);
					WriteResults(objName, name, XDocument.Parse(GetXml((XmlSizeEnum)i)).ToString().Length);
				}
				catch (Exception ex)
				{
					WriteException(ex);
				}
			}

			Console.WriteLine("-------------------------------------------------\n");

		}

		static void ExperimentXPathDocument()
		{
			var objName = "XPathDocument";

			WriteStart(objName);


			foreach (int i in Enum.GetValues(typeof(XmlSizeEnum)))
			{
				try
				{
					var name = Enum.GetName(typeof(XmlSizeEnum), i);
					WriteAttempt(objName, name);
					WriteResults(objName, name, new XPathDocument(new MemoryStream(Encoding.ASCII.GetBytes(GetXml((XmlSizeEnum)i)))).CreateNavigator().InnerXml.ToString().Length);
				}
				catch (Exception ex)
				{
					WriteException(ex);
				}
			}

			Console.WriteLine("-------------------------------------------------\n");

		}

		static void ExperimentXmlDocument()
		{


			var xml = new XmlDocument();
			var objName = "XmlDocument";

			WriteStart(objName);

			foreach (int i in Enum.GetValues(typeof(XmlSizeEnum)))
			{
				try
				{
					var name = Enum.GetName(typeof(XmlSizeEnum), i);
					WriteAttempt(objName, name);
					xml.LoadXml(GetXml((XmlSizeEnum)i));
					WriteResults(objName, name, xml.InnerText.Length);
				}
				catch (Exception ex)
				{
					WriteException(ex);
				}
			}

			Console.WriteLine("-------------------------------------------------\n");

		}

		#endregion

		#region Write and Read Utility methods

		private static void WriteException(Exception ex)
		{
			Console.WriteLine(ex.Message);
			Console.WriteLine();
		}

		private static void WriteStart(string objName, bool withParse = false, XmlReaderSettings settings = null)
		{
			Console.WriteLine("\n-------------------------------------------------");
			Console.WriteLine($"Testing using the \"{objName}\" object.");

			if (withParse)
			{
				Console.WriteLine($"DTD parsing and XmlUrlResolver is explicitly enabled.");
				if (settings != null)
				{
					settings.DtdProcessing = DtdProcessing.Parse;
					settings.XmlResolver = new XmlUrlResolver();
				}
			}
			Console.WriteLine("-------------------------------------------------");
			Console.WriteLine();
		}

		static void WriteResults(string objName, string size, int length)
		{
			Console.WriteLine($"{size} XML using \"{objName}\" object had length: {length}");
			Console.WriteLine();

		}

		static void WriteAttempt(string objName, string size)
		{
			Console.WriteLine($"Attempting {size} XML using \"{objName}\" object");

		}

		static string ReadFromReader(XmlReader xmlReader)
		{
			var sb = new StringBuilder();

			while (xmlReader.Read())
			{

				if (xmlReader is XmlTextReader)
				{
					if (xmlReader.NodeType == XmlNodeType.Element)
					{
						sb.Append(xmlReader.ReadElementContentAsString());
					}
				}
				else
				{
					sb.Append(xmlReader.Value);
				}

			}

			return sb.ToString();
		}

		#endregion

		#region XML Prep methods

		static string GetSmallXml(bool withoutLast = false)
		{
			return @"<?xml version=""1.0""?>
<!DOCTYPE lolz [
<!ENTITY lol ""lol1"" >
<!ELEMENT lolz (#PCDATA)>
<!ENTITY lol1 ""&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"">
<!ENTITY lol2 ""&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"">
<!ENTITY lol3 ""&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"">" + GetLast(withoutLast, 3);
		}

		static string GetMediumXml(bool withoutLast = false)
		{
			return $"{GetSmallXml(true)}" + @"
<!ENTITY lol4 ""&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"">
<!ENTITY lol5 ""&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"">
<!ENTITY lol6 ""&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"">" + GetLast(withoutLast, 6);
		}

		static string GetLargeXml()
		{
			return $"{GetMediumXml(true)}" + @"
<!ENTITY lol7 ""&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"" >
<!ENTITY lol8 ""&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"" >
<!ENTITY lol9 ""&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;"" >" + GetLast(false, 9);
		}

		static string GetXml(XmlSizeEnum size)
		{
			switch (size)
			{
				case XmlSizeEnum.Large:
					return GetLargeXml();
				case XmlSizeEnum.Medium:
					return GetMediumXml();
				case XmlSizeEnum.Small:
					return GetSmallXml();
				default:
					return "";

			}

		}

		static string GetLast(bool returnBlank, int lastID)
		{
			if (returnBlank)
			{
				return "";
			}
			else
			{
				return $"\n]><lolz>&lol{lastID};</lolz>";
			}
		}

		public enum XmlSizeEnum
		{
			Small,
			Medium,
			Large
		}



		static void TestXmlItems()
		{
			Console.WriteLine(GetSmallXml());
			Console.WriteLine("");
			Console.WriteLine(GetMediumXml());
			Console.WriteLine("");
			Console.WriteLine(GetLargeXml());
			Console.WriteLine("");
			Console.ReadLine();
		}

		#endregion

	}
}
