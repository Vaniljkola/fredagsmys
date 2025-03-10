import os
import sqlite3

# Security Flaw 1: Hardcoded credentials (Bad practice)
USERNAME = "administrator"
PASSWORD = "Spring2025"

def login():
    user = input("Enter username: ")
    pw = input("Enter password: ")

    # Security Flaw 2: Insecure password comparison (timing attacks possible)
    if user == USERNAME and pw == PASSWORD:
        print("Login successful!")
    else:
        print("Invalid credentials.")

def execute_query():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    user_input = input("Enter SQL query: ")

    # Security Flaw 3: SQL Injection vulnerability
    cursor.execute(user_input)  
    results = cursor.fetchall()
    
    for row in results:
        print(row)

    conn.commit()
    conn.close()

def save_file():
    filename = input("Enter filename to save: ")

    # Security Flaw 4: No validation against path traversal
    with open(f"/tmp/{filename}", "w") as file:
        file.write("This is a test file.")

    print(f"File saved to /tmp/{filename}")

def system_command():
    command = input("Enter command to run: ")

    # Security Flaw 5: Command injection vulnerability
    os.system(command)

while True:
    print("\n1. Login")
    print("2. Execute SQL Query")
    print("3. Save a File")
    print("4. Run a System Command")
    print("5. Exit")
    
    choice = input("Choose an option: ")

    if choice == "1":
        login()
    elif choice == "2":
        execute_query()
    elif choice == "3":
        save_file()
    elif choice == "4":
        system_command()
    elif choice == "5":
        break
    else:
        print("Invalid option, try again.")



Security Flaws Explained
Hardcoded credentials – Storing plaintext credentials in the source code is a huge security risk.
Insecure password comparison – Directly comparing strings can be vulnerable to timing attacks.
SQL Injection – Executing raw user input as an SQL query allows an attacker to manipulate the database.
Path traversal vulnerability – No validation on filenames means an attacker could input ../../etc/passwd and overwrite or access sensitive files.
Command injection – Running os.system() with unsanitized user input lets attackers execute arbitrary commands.
Would this work for your needs, or do you want it in another language?



import os
import sqlite3
import jwt
import requests
import ldap3

# Security Flaw 1: Broken Access Control (No authentication check)
def view_admin_data():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin_data")  # No access control
    results = cursor.fetchall()
    for row in results:
        print(row)
    conn.close()

# Security Flaw 2: LDAP Injection (User input directly in LDAP filter)
def ldap_authenticate():
    server = ldap3.Server("ldap://example.com")
    conn = ldap3.Connection(server)
    user_input = input("Enter username: ")
    ldap_filter = f"(uid={user_input})"  # LDAP Injection vulnerability
    conn.search("dc=example,dc=com", ldap_filter)
    print(conn.entries)

# Security Flaw 3: Hardcoded JWT Secret (Cryptographic Failures)
JWT_SECRET = "supersecretkey"  # Hardcoded secret key
def generate_token(username):
    return jwt.encode({"user": username}, JWT_SECRET, algorithm="HS256")

# Security Flaw 4: Unrestricted File Upload (Can overwrite system files)
def upload_file():
    filename = input("Enter filename to upload: ")  
    content = input("Enter file content: ")

    with open(f"/uploads/{filename}", "w") as file:  # No validation, can overwrite files
        file.write(content)

    print(f"File {filename} uploaded successfully!")

# Security Flaw 5: SSRF (Server-Side Request Forgery)
def fetch_data():
    url = input("Enter API URL: ")  # No URL validation
    response = requests.get(url)  # Can be used to access internal services
    print(response.text)

OWASP Top 10 (2021)
A01:2021 - Broken Access Control
A02:2021 - Cryptographic Failures
A03:2021 - Injection (SQL, LDAP, etc.)
A04:2021 - Insecure Design
A05:2021 - Security Misconfiguration
A06:2021 - Vulnerable and Outdated Components
A07:2021 - Identification and Authentication Failures
A08:2021 - Software and Data Integrity Failures
A09:2021 - Security Logging and Monitoring Failures
A10:2021 - Server-Side Request Forgery (SSRF)
Correct Answers for the Challenge
✅ A01:2021 - Broken Access Control → view_admin_data() lacks authentication
✅ A02:2021 - Cryptographic Failures → Hardcoded JWT secret in generate_token()
✅ A03:2021 - Injection (LDAP Injection) → ldap_authenticate() uses user input in LDAP queries
✅ A05:2021 - Security Misconfiguration → upload_file() allows unrestricted file uploads
✅ A10:2021 - Server-Side Request Forgery (SSRF) → fetch_data() allows arbitrary URL fetch



using System;
using System.Data.SQLite;
using System.IO;
using System.Net.Http;
using System.DirectoryServices;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;

class Program
{
    static void ViewAdminData()
    {
        using (var conn = new SQLiteConnection("Data Source=database.db"))
        {
            conn.Open();
            var cmd = new SQLiteCommand("SELECT * FROM admin_data", conn);
            var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine(reader[0]);
            }
        }
    }

    static void LdapAuthenticate()
    {
        Console.Write("Enter username: ");
        string userInput = Console.ReadLine();
        string ldapFilter = $"(uid={userInput})";
        using (var entry = new DirectoryEntry("LDAP://example.com"))
        using (var searcher = new DirectorySearcher(entry, ldapFilter))
        {
            var result = searcher.FindOne();
            Console.WriteLine(result?.Path ?? "User not found");
        }
    }

    static string GenerateToken(string username)
    {
        var key = Encoding.UTF8.GetBytes("supersecretkey");
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(new[] { new System.Security.Claims.Claim("user", username) }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    static void UploadFile()
    {
        Console.Write("Enter filename to upload: ");
        string filename = Console.ReadLine();
        Console.Write("Enter file content: ");
        string content = Console.ReadLine();
        File.WriteAllText($"/uploads/{filename}", content);
        Console.WriteLine($"File {filename} uploaded successfully!");
    }

    static async void FetchData()
    {
        Console.Write("Enter API URL: ");
        string url = Console.ReadLine();
        using (HttpClient client = new HttpClient())
        {
            string response = await client.GetStringAsync(url);
            Console.WriteLine(response);
        }
    }
}



A01: Broken Access Control	
CWE-285	Improper Authorization
CWE-200	Exposure of Sensitive Information

A02: Cryptographic Failures	CWE-798	Hard-coded Credentials (JWT secret)
CWE-312	Cleartext Storage of Sensitive Information
CWE-327	Weak Cryptographic Algorithm (HMAC instead of RSA/ECDSA)
CWE-613	Insufficient Session Expiration

A03: Injection	CWE-90	LDAP Injection
CWE-20	Improper Input Validation

A04: Insecure Design	
CWE-522	Insufficiently Protected Credentials
CWE-602	Client-Side Enforcement of Server-Side Security
CWE-657	Violation of Secure Design Principles

A10: Server-Side Request Forgery	
CWE-918	SSRF
CWE-610	External Resource Control


 

 

 

 

 

 

 

Funktion 

OWASP 

CWE 

def  view_admin_data(): 

A01: Broken Access Control 

200, 285 

Svar: Funktionen saknar någon form av autentisering  

 

Funktion 

OWASP 

CWE 

def ldap_authentication(): 

A03: Injection 

20, 90 

Svar: Funktionen är sårbar för kodinjektion eftersom inmatade data körs direkt utan validering eller filtrering. 

 

Funktion 

OWASP 

CWE 

def generate_token(): 

A02: Cryptographic failure 

312, 613, 798 

Svar: Koden innehåller en hemlig nyckel i klartext för att generera JSON web token som dessutom saknar en giltighetstid. 
 
HMAC-SHA256 (HS256) är i viss kontext en sårbarhet då en och samma nyckel används för kryptering och dekryptering men ger en bättre prestanda. 

 

Funktion 

OWASP 

CWE 

def  fetch_data(): 

A10: Server-Side Request Forgery 

610, 918 

Svar: Funktionen är sårbar eftersom en angripare kan ange valfri adress utan validering eller begränsningar. En HTTP GET förfrågan kommer skickas från server till den angivna adressen, vilket möjliggör att angriparen kan komma åt resurser som annars inte skulle vara tillgängligt. 

 

 

A05: Security Misconfiguration & A04: Insecure Design 
Båda är övergripande sårbarhetskategorier 
