# app/custom_alerts.py
# Mapping of pluginId (alert id) -> exact description/recommendation text to use (unchanged)
CUSTOM_ALERTS = {
    "90037": {
        "description": """An attacker can inject malicious input into application-controlled command strings or shell invocations, causing the server to execute arbitrary OS commands. Time-based techniques (for example sleep or ping delays) may be used to confirm blind injections by observing delayed responses. This occurs when untrusted data is concatenated into commands or passed to shell-interpreting APIs without proper separation of data and code""",
        "recommendation": """
        
        Avoid shells: Replace shell calls with native library functions or APIs that perform the desired operation.
        Use argument arrays: When running external programs is necessary, invoke them with APIs that accept argument lists (no single-string shell invocation)
        Strict allow-listing & validation: Validate input by type, length, and an explicit allow-list of acceptable values; reject everything else.
        Proper escaping/quoting: If dynamic arguments cannot be avoided, escape and quote every argument using safe language/runtime facilities.
        Sandbox & least privilege: Run processes with minimal privileges in a restricted environment (chroot/containers, AppArmor/SELinux) to limit impact.
        Defense-in-depth: Combine validation, safe invocation, runtime sandboxing, and logging/monitoring of anomalous inputs and timing anomalies.
        """
    },
    "90028": { 
        "description": """Attackers commonly perform reconnaissance by enumerating the target’s web presence to identify technologies, configurations, and versions in use. This process, known as multi-tier fingerprinting, focuses on the Application Layer to build a detailed profile of the platform, web application, backend database, and network setup information that can later be used to plan targeted attacks.""", 
        "recommendation": """ 
        
        Restrict HTTP methods: Allow only required methods such as GET, POST, and HEAD. Disable others like PUT, DELETE, TRACE, and TRACK.
        Obfuscate system details: Hide or randomize headers and error messages that reveal software versions or technologies.
        Firewall protection: Configure firewalls or WAFs to block or limit fingerprinting attempts.
        Response randomization: Randomize non-critical response elements to hinder consistent identification.
        Regular updates: Keep all web servers, frameworks, and databases updated to reduce exposure to known vulnerabilities.
        Layered defense: Combine these techniques to reduce information leakage and prevent attackers from accurately profiling the system.
        """ 
    },
    "90020": {
        "description": """Attack technique used for unauthorized execution of operating system commands. This attack is possible when an application accepts untrusted input to build operating system commands in an insecure manner involving improper data sanitization and/or improper calling of external programs.""",
        "recommendation": """ 
        
        Prefer libraries over shells: Replace external command invocation with native library/API calls whenever possible.
        Use argument-array APIs: Invoke processes with APIs that accept argument lists (no single-string shell invocation) to avoid shell interpretation.
        Strict allow-listing & validation: Validate inputs by type, length, and an explicit allow-list; reject anything that does not strictly conform.
        Escape/quote conservatively: If dynamic arguments are unavoidable, escape and quote every argument using safe runtime facilities.
        Pass data via stdin/files: Where supported, provide input through stdin or files rather than embedding it in a command line.
        Sandbox & least privilege: Run code in restricted environments (chroot/container, AppArmor/SELinux) and with minimal privileges.
        Use vetted frameworks/tools: Leverage security libraries (e.g., ESAPI or language equivalents) that enforce separation of data and code.
        Defense-in-depth: Combine validation, safe invocation, sandboxing, logging and timing/anomaly monitoring to detect and limit exploitation."""
   
    },
    "40031": {
        "description": """Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user’s browser instance. The code, often written in HTML or JavaScript, executes in the context of the hosting site, allowing attackers to read, modify, or transmit sensitive data. Successful exploitation can result in account hijacking, cookie theft, content injection, or full compromise of the user’s session.""",
        "recommendation": """
        
        Use secure frameworks/libraries: Employ vetted frameworks or libraries (e.g., OWASP ESAPI, Microsoft Anti-XSS) that handle proper encoding automatically.
        Context-aware encoding: Encode all untrusted data before output according to its context (HTML, attribute, JavaScript, URL, CSS).
        Validate input: Use a strict allow-list to accept only well-formed and expected input; reject or sanitize everything else.
        Server-side validation: Repeat any client-side checks on the server to prevent bypass.
        Specify encoding: Set a consistent character encoding such as UTF-8 to avoid interpretation-based attacks.
        Secure cookies: Use HttpOnly, Secure, and SameSite flags to protect session cookies.
        Structured mechanisms: Use APIs or template engines that enforce separation of data and code to prevent injection at output points.
        """
    },
    "40027": {
        "description": """SQL injection may be possible. An attacker can supply malicious input that is concatenated into SQL statements (including time-based techniques that infer data via response delays), allowing unauthorized data access or modification when queries are built insecurely.""",
        "recommendation": """
        
        Use parameterized queries: Prefer PreparedStatement / CallableStatement (JDBC) or ADO Command objects (ASP) and bind parameters rather than concatenating strings.
        Stored procedures carefully: Use stored procedures but do not construct SQL by concatenating strings inside them or call exec/exec immediate with untrusted input.
        Server-side type checking & validation: Validate and type-check all input on the server; apply strict allow-lists where feasible.
        Avoid client-side trust: Never rely on client-side validation alone—treat all client input as untrusted.
        Escape when necessary: If parameterization is impossible, escape inputs correctly for the target DB — but treat this as last resort.
        Least privilege: Use the minimum database privileges required (avoid sa/db_owner); limit what each DB account can do to reduce impact.
        Monitor & test: Log suspicious queries, perform regular security testing (including time-based and blind SQLi checks), and patch DB servers and libraries.
        """
    },
    "40026":{
        "description": """Cross-site Scripting (XSS) is an attack technique that involves injecting and executing malicious code (commonly HTML or JavaScript) in a user's browser within the context of a trusted website. DOM-based XSS occurs when the vulnerability exists in client-side scripts that process data from an untrusted source (e.g., URL or DOM) without proper validation or encoding, allowing attackers to manipulate the page dynamically and execute arbitrary code.""",
        "recommendation": """
        
        Use secure frameworks/libraries: Implement frameworks or libraries that automatically handle encoding and separation of data and code (e.g., OWASP ESAPI, Microsoft Anti-XSS).
        Encode output properly: Apply the correct output encoding based on the context (HTML, attribute, JavaScript, or URL) before rendering untrusted data.
        Validate input (allow-list): Use strict allow-list validation for all input data — length, type, and allowed characters. Reject or sanitize all other data.
        Avoid client-side trust: Replicate client-side validation on the server to prevent bypassing.
        Specify encoding: Always define a consistent character encoding (e.g., UTF-8) for all web pages to prevent interpretation-based vulnerabilities.
        Set secure cookies: Use HttpOnly, Secure, and SameSite cookie attributes to mitigate session theft via XSS.
        Avoid dangerous DOM operations: Prevent direct use of innerHTML, document.write(), eval(), or similar functions with untrusted data.
        Defense-in-depth: Combine validation, encoding, secure cookie flags, and safe DOM handling to minimize XSS exposure and mitigate attacks effectively.
        """
    },
    "40024":{
        "description": """SQL injection may be possible. An attacker can supply malicious input that is incorporated into SQL statements (including time-based techniques that infer data via response delays), allowing unauthorized access or modification when queries are constructed insecurely.""",
        "recommendation": """
        
        Use parameterized/prepared statements: Always use parameter binding (e.g., ? placeholders) instead of concatenating user data into SQL.
        Avoid dynamic SQL: Do not build SQL by concatenating strings; never use mechanisms that evaluate SQL built from untrusted input.
        Server-side type checks & allow-lists: Validate and type-check all input on the server; apply strict allow-lists for expected values.
        Escape only as last resort: If parameterization is impossible, apply proper escaping for SQLite — treat this as a fallback only.
        Least privilege & file protections: Limit the application’s access to the SQLite file (file system permissions); run with minimal OS privileges to reduce impact.
        Logging & testing: Log suspicious queries, perform regular security testing (including time-based and blind SQLi tests), and keep DB libraries up to date.
        """
    },
    "40022": {
        "description": """SQL injection may be possible. An attacker can supply malicious input that is incorporated into SQL statements (including time-based techniques that infer data via response delays) when queries are constructed insecurely for PostgreSQL.""",
        "recommendation": """
        
        Use parameterized queries: Always bind parameters instead of concatenating strings (e.g., PreparedStatement/driver-specific parameter binding).
        Use stored procedures safely: Use stored procedures where appropriate, but do not build SQL by string concatenation inside them or call EXEC/EXECUTE with untrusted input.
        Server-side validation & type checking: Validate and type-check all inputs on the server; apply strict allow-lists for expected values.
        Never trust client validation: Treat all client input as malicious — enforce checks server-side.
        Escape only as last resort: If parameterization cannot be used, apply correct escaping for PostgreSQL as a fallback only.
        Principle of least privilege: Run DB connections with the minimum required privileges (avoid superuser/db_owner accounts) to reduce impact.
        Log, test & patch: Log suspicious queries, perform regular security testing (including time-based and blind SQLi), and keep DB servers/drivers patched.
        """
    },
    "40021":{
        "description": """SQL injection may be possible. An attacker can supply malicious input that is incorporated into SQL statements (including time-based techniques that infer data via response delays), allowing unauthorized access or modification when queries are constructed insecurely for Oracle.""",
        "recommendation": """
        
        Use parameterized statements / bind variables: Prefer PreparedStatement / CallableStatement (JDBC) or driver-specific parameter binding instead of concatenating user input into SQL.
        Use stored procedures safely: If using stored procedures, do not build SQL by string concatenation inside them or call EXECUTE IMMEDIATE/EXEC with untrusted input.
        Server-side type checking & validation: Validate and type-check all inputs on the server; apply strict allow-lists for expected values.
        Never trust client validation: Treat all client input as untrusted — enforce checks on the server.
        Escape only as last resort: If parameterization is impossible, apply correct escaping for Oracle as a fallback (not a primary defense).
        Least privilege: Use the minimal database privileges required for the application (avoid highly privileged accounts) to reduce impact.
        Logging, testing & patching: Log suspicious activity, perform regular security testing (including time-based and blind SQLi), and keep DB drivers and servers up to date.
        """
    },
    "40020": {
        "description": """SQL injection may be possible . An attacker can supply malicious input that is incorporated into SQL statements (including time-based techniques that infer data by observing response delays), allowing unauthorized access or modification when queries are constructed insecurely for Hypersonic SQL.""",
        "recommendation": """
        
        Use parameterized queries / bind variables: Prefer PreparedStatement / CallableStatement or driver-specific parameter binding rather than concatenating user input into SQL.
        Avoid dynamic SQL: Do not build SQL by concatenating strings or using EXEC/EXECUTE IMMEDIATE with untrusted input (including inside stored procedures).
        Server-side validation & type checking: Validate and type-check all inputs on the server; apply strict allow-lists for expected values.
        Never trust client-side checks: Enforce all validation server-side; treat client input as malicious.
        Escape only as last resort: If parameterization is impossible, apply proper escaping for the target DB as a fallback (not primary defense).
        Principle of least privilege: Use minimally privileged DB accounts and restrict access to the Hypersonic DB file to reduce impact.
        Log, test & patch: Log suspicious activity, perform regular security testing (including time-based and blind SQLi checks), and keep DB drivers and software updated.
        """
    },
    "40019": {
        "description": """SQL injection may be possible. An attacker can supply malicious input that is incorporated into SQL statements (including time-based techniques that infer data via response delays), allowing unauthorized access or modification when queries are built insecurely for MySQL""",
        "recommendation": """
        
        Use parameterized queries / bind variables: Prefer PreparedStatement/driver parameter binding instead of concatenating user input into SQL.
        Avoid dynamic SQL: Do not construct SQL by string concatenation or call EXEC/EXECUTE IMMEDIATE with untrusted input (including inside stored procedures).
        Server-side validation & type checks: Validate and type-check all input on the server; apply strict allow-lists for expected values.
        Never trust client-side validation: Treat all client input as malicious and enforce checks server-side.
        Escape only as a fallback: If parameterization is impossible, apply correct escaping for MySQL as a last resort.
        Principle of least privilege: Use minimally privileged DB accounts (avoid root/DB-owner) and restrict permissions to reduce impact.
        Logging, testing & patching: Log suspicious activity, perform regular security testing (including time-based/blind SQLi), and keep DB engines/drivers patched.
        """
    },
    "40018": {
        "description": """SQL injection may be possible. An attacker can supply malicious input that is incorporated into SQL statements (including time-based or blind techniques) when queries are built insecurely, allowing unauthorized access, modification, or disclosure of database data.""",
        "recommendation": """
        
        Use parameterized queries / bind variables: Prefer PreparedStatement / parameter binding (or driver-specific equivalents) instead of concatenating user input into SQL.
        Avoid dynamic SQL: Do not build SQL by string concatenation or use EXEC/EXECUTE IMMEDIATE with untrusted input (including inside stored procedures).
        Server-side validation & type checking: Validate and type-check all inputs on the server; apply strict allow-lists for expected values.
        Do not trust client-side checks: Enforce all validation server-side; treat client input as malicious.
        Escape only as last resort: If parameterization is not possible, apply correct escaping for the target DB — but treat this as fallback only.
        Principle of least privilege: Use minimally privileged DB accounts (avoid highly privileged users) and grant only necessary permissions.
        Test, log & patch: Log suspicious activity, perform regular security testing (including time-based/blind SQLi checks), and keep DB servers/drivers patched.
        """
    },
    "40014": {
        "description": """Cross-site Scripting (XSS) occurs when attacker-supplied code (commonly HTML/JavaScript or other browser-supported technologies) is stored by the application and later served to users’ browsers, where it executes in the context of the hosting site, allowing cookie theft, account hijacking, content spoofing, or broader compromise.""",
        "recommendation": """
        
        Use vetted frameworks/libraries: Employ libraries or frameworks that separate data from code and provide proper encoding (e.g., OWASP ESAPI, Microsoft Anti-XSS, framework templating).
        Context-aware encoding: Encode all untrusted output according to its context (HTML body, attributes, JavaScript, URL, CSS). Consult the XSS Prevention Cheat Sheet.
        Server-side validation (allow-list): Validate and type-check inputs on the server using strict allow-lists for length, type and allowed characters; reject or normalize others.
        Don’t rely on client checks: Duplicate/verify client-side validation on the server to prevent bypass (avoid CWE-602).
        Specify character encoding: Explicitly set and use a consistent page encoding (e.g., UTF-8) to avoid charset-related issues.
        Harden cookies & sessions: Use HttpOnly, Secure and SameSite cookie attributes to reduce session exposure to scripts.
        Avoid unsafe DOM APIs: Prevent use of innerHTML, document.write(), eval() and similar with untrusted data (especially for DOM XSS).
        Defense-in-depth: Combine secure frameworks, encoding, validation, secure cookie flags, logging and monitoring to detect and mitigate XSS.
        """ 
    },
    "40013": {
        "description": """Session Fixation may be possible if an attacker can supply or force a known session identifier to a victim (via URL, cookie or form field) so that, after the victim authenticates, the attacker can reuse that same session id to assume the victim’s identity. When the fixation vector is a non-login page the attacker can track an unauthenticated user; if the vector is a cookie or POST field, additional vulnerabilities may be required to set it on the victim’s browser.""", 
        "recommendation": """
        
        Issue session IDs securely: Allocate session identifiers only on the server and preferably only after successful authentication.
        Rotate on login: Always create a new session id (session regeneration) immediately after authentication, regardless of an existing session.
        Bind session to client attributes: Where feasible, tie the session to client properties (e.g., IP address range, TLS client cert) to reduce reuse risk.
        Use cookies (not URLs): Prefer cookie- or form-based session identifiers over URL-based ids to avoid easy fixation via shared links.
        Destroy sessions server- and client-side: Ensure session invalidation removes server state and clears client cookies.
        Provide logout & timeouts: Implement logout that invalidates prior sessions and enforce absolute and idle session timeouts.
        Harden cookie flags: Use Secure, HttpOnly, and SameSite attributes for session cookies to reduce client-side manipulation and cross-site attacks.
        """
    },
    "40012": {
        "description": """Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user’s browser instance. Reflected XSS occurs when malicious input is immediately returned in the application’s response (e.g., via URL parameters or form submissions) and executed in the victim’s browser, allowing theft of cookies, account hijacking, or unauthorized redirection.""",
        "recommendation": """
        
        Use secure frameworks/libraries: Employ libraries or frameworks that automatically handle encoding and escaping (e.g., OWASP ESAPI, Microsoft Anti-XSS).
        Contextual output encoding: Encode all untrusted output based on its context (HTML, JavaScript, attribute, or URL) before rendering.
        Input validation (allow-list): Validate and type-check input on the server using strict allow-lists; reject or sanitize unexpected values.
        Duplicate client checks server-side: Do not rely solely on client-side validation; enforce equivalent checks on the server.
        Specify character encoding: Always define a consistent page encoding (e.g., UTF-8) to avoid misinterpretation.
        Secure cookies: Use HttpOnly, Secure, and SameSite flags to protect session cookies from being accessed by scripts.
        Avoid unsafe reflection: Ensure user-supplied data is never reflected in responses without proper sanitization or encoding.
        Layered defense: Combine input validation, output encoding, secure frameworks, and cookie protection for effective XSS mitigation.
        """
    },
    "20019-4": {
        "description": """URL redirectors are used by websites to forward requests to alternate resources for purposes such as load balancing or link tracking. However, when unvalidated user input controls the redirect target, attackers can exploit it for phishing or social engineering, tricking users into visiting malicious sites that appear legitimate.""", 
        "recommendation": """
        
        Validate redirect targets: Use an allow-list of approved URLs or domains for redirection. Reject or sanitize all unrecognized inputs.
        Use intermediate warning pages: Display a disclaimer before redirecting users off-site and require manual confirmation (e.g., click).
        Avoid unsafe user input: Never use untrusted input directly in redirect URLs; validate parameters by type, length, and format.
        Apply mapping logic: Implement fixed mappings (e.g., numeric IDs → predefined URLs) instead of accepting arbitrary redirect paths.
        Combine validation strategies: Use allow-lists primarily, with deny-lists as secondary detection for malformed or suspicious inputs.
        Input validation scope: Validate all potential input sources (query parameters, headers, cookies, forms, environment variables).
        Timeout or delay: If possible, introduce a short delay before redirecting to improve user awareness and reduce automated exploitation.
        """
    },
    "20019-3": {
        "description": """URL redirectors are common features that forward users to alternate resources, such as moved pages or external links. However, if the redirect target is based on unvalidated user input, attackers can exploit it to perform phishing or social engineering attacks, tricking users into visiting malicious sites that appear to be legitimate.""",
        "recommendation": """
        
        Validate redirect destinations: Use an allow-list of approved URLs or domains for redirection; reject or sanitize all unrecognized inputs.
        Use intermediate warning pages: Display a clear disclaimer before users are redirected off-site, requiring manual confirmation.
        Avoid direct user input: Do not use untrusted input directly in redirect URLs; validate all parameters for type, length, and expected values.
        Implement fixed mappings: Use predefined mappings (e.g., ID-to-URL references) to control allowable redirect destinations.
        Apply strong input validation: Validate all input sources — including parameters, headers, cookies, and form fields — using allow-list logic.
        Introduce redirect delay: Add a short timeout or click requirement before redirecting to enhance user awareness.
        Combine protections: Use both input validation and user warnings to prevent external redirect abuse and phishing attempts
        """
    },
    "20019-2": {
        "description": """URL redirectors are commonly used by websites to forward requests to alternate resources for purposes such as reorganizing content or tracking outgoing links. However, if user input controls the redirect destination without proper validation, attackers can exploit it for phishing or social engineering, misleading users into visiting malicious external sites.""",
        "recommendation": """
        
        Validate redirect URLs: Use an allow-list of approved URLs or domains for redirection; reject or sanitize all others.
        Use intermediate disclaimer pages: Warn users they are leaving the site and require confirmation before redirecting.
        Avoid direct user input in redirects: Do not use untrusted input directly in redirect parameters; validate input for type, format, and length.
        Implement fixed mapping: Map known identifiers (e.g., numeric IDs) to specific URLs and reject unknown inputs.
        Perform comprehensive input validation: Check all potential input sources, including parameters, headers, cookies, and form data.
        Delay automatic redirects: Introduce a short timeout or manual click to prevent silent redirects.
        Combine defenses: Apply layered validation, warning pages, and mapping techniques to prevent open redirect abu
        """
    },
    "20019-1": {
        "description": """URL redirectors are commonly used by websites to forward users to alternate resources for purposes such as reorganizing content, load balancing, or tracking outgoing links. However, if the redirect destination is based on unvalidated user input, attackers can exploit it for phishing or social engineering, tricking victims into visiting malicious sites that appear legitimate.""", 
        "recommendation": """
        
        Validate redirect inputs: Use an allow-list of approved URLs or domains for redirection; reject or sanitize all unapproved inputs.
        Use warning or disclaimer pages: Display a message informing users they are leaving the site and require manual confirmation before redirecting.
        Avoid direct user-controlled redirects: Never use untrusted input directly in redirect URLs; validate format, type, and length.
        Apply fixed URL mapping: Map predefined IDs or tokens to known URLs (e.g., ID 1 → /login, ID 2 → https://example.com).
        Perform full input validation: Validate all potential sources of user input, including query parameters, headers, cookies, and form data.
        Delay or confirm redirects: Introduce a short timeout or require a user action (e.g., click) before completing an external redirect.
        Combine multiple defenses: Use validation, warning pages, and mapping mechanisms together to mitigate open redirect abuse and phishing risks.
        """
    },
    "20012": {
        "description": """Cross-Site Request Forgery (CSRF) is an attack that tricks a victim’s browser into sending unauthorized requests to a trusted web application in which they are authenticated. This occurs when predictable or repeatable form actions allow attackers to perform actions as the victim, exploiting the trust a website has in the user’s session.""",
        "recommendation": """
        
        Use anti-CSRF frameworks: Implement vetted CSRF protection libraries (e.g., OWASP CSRFGuard or built-in framework defenses).
        Generate unique tokens: Include an unpredictable, per-session or per-request nonce (token) in each form or state-changing request and verify it on submission.
        Avoid unsafe methods: Do not use GET requests for actions that modify application state.
        Confirm sensitive actions: Require re-authentication or user confirmation for critical operations.
        Combine with XSS protection: Fix all XSS issues, as CSRF protections can be bypassed via injected scripts.
        Check request origin: Optionally verify the Referer or Origin header, while considering privacy-related limitations.
        Use secure session controls: Employ frameworks or APIs (e.g., ESAPI Session Management) that include built-in CSRF protection mechanisms.
        """
    },
    "10202": {
        "description": """No Anti-CSRF tokens were found in an HTML submission form. A Cross-Site Request Forgery (CSRF) attack forces a victim’s browser to send unauthorized requests to a trusted web application where the victim is authenticated. This occurs when forms or URLs use predictable actions without unique, verifiable tokens, allowing attackers to perform actions as the victim.""", 
        "recommendation": """
        
        Implement anti-CSRF tokens: Use vetted libraries or frameworks (e.g., OWASP CSRFGuard) to automatically generate and validate CSRF tokens.
        Use unique nonces: Include an unpredictable, per-request or per-session token in each form and verify it upon submission.
        Avoid unsafe methods: Do not use GET for state-changing actions; use POST or other secure methods with token validation.
        Combine with XSS prevention: Fix all XSS issues since attacker-controlled scripts can bypass CSRF protections.
        Reconfirm sensitive actions: Require user confirmation or re-authentication for critical operations.
        Check request origin (optional): Validate the Referer or Origin header where feasible, but be aware of privacy limitations.
        Use secure session management: Employ secure frameworks (e.g., ESAPI Session Management) with built-in CSRF protection mechanisms.
        """
    },
    "10102": {
        "description": """Insufficient Authorization occurs when an application fails to enforce proper access control, allowing users to perform actions or access data beyond their intended permissions. This happens when the system does not verify whether the authenticated user has the right to access a specific function or resource, leading to unauthorized viewing, modification, or misuse of data and functionality.""",
        "recommendation": """
        
        Enforce authorization checks: Apply strict, role-based access control (RBAC) to verify permissions for every request to sensitive functions or data.
        Implement least privilege: Grant users, services, and applications only the minimum privileges required for their roles.
        Validate data access: Ensure users can access only their own data by verifying ownership or explicit access rights for each record.
        Control function-level access: Restrict functionality (e.g., admin panels, editing, publishing) to authorized roles only.
        Secure identifiers: Avoid exposing predictable identifiers (like numeric IDs) in URLs; use indirect references or access mappings.
        Compartmentalize privileges: Design the system architecture to isolate privileges and enforce privilege separation between components.
        Monitor and audit: Log authorization checks and regularly review permissions to detect and prevent privilege misuse.
        """
    },
    "10049-1": {
        "description": """The response contents are not storable by caching components such as proxy servers. If the response does not include sensitive or user-specific data, enabling caching could improve performance by allowing responses to be reused instead of regenerated for every request""",
        "recommendation": """
        
        Allow caching where appropriate: Mark content as storable if it is static or non-sensitive.
        Ensure cacheable methods: Use HTTP methods defined as cacheable (GET, HEAD, and POST).
        Use valid status codes: Confirm response status codes are recognized by caches (e.g., 2XX, 3XX, 4XX, 5XX).
        Adjust cache directives: Remove no-store and private directives for public resources; ensure proper Cache-Control settings.
        Set caching headers: Include at least one of the following in responses:
           - Expires header
           - Cache-Control: max-age
           - Cache-Control: s-maxage (for shared caches)
           - A defined cacheable status code (e.g., 200, 301, 404, 410)
        Avoid caching sensitive data: Ensure responses containing personal or session-specific content remain non-storable.
        """
    }, 
    "7": {
        "description": """Remote File Inclusion (RFI) occurs when a web application dynamically includes external files based on user input without proper validation. Attackers can exploit this flaw to include and execute malicious code from remote servers. This can lead to remote code execution on the server or injection of malicious content in client responses. PHP applications are particularly vulnerable due to common file inclusion practices and insecure default configurations.""", 
        "recommendation": """
        
        Validate input strictly: Use an allow list of permitted filenames or IDs; reject all other inputs.
        Use fixed mappings: Map trusted input values (e.g., IDs) to specific files instead of using raw user input.
        Isolate code execution: Run the application in a sandbox or jail environment (e.g., chroot, AppArmor, SELinux).
        Restrict PHP features: Enable open_basedir, disable dangerous functions, and consider using the Suhosin extension.
        Store include files securely: Keep library and utility files outside the web root or restrict direct access via server configuration.
        Limit file access: Use stringent filename validation — allow only safe characters, restrict extensions, and avoid directory traversal.
        Minimize privileges: Ensure the web server and scripts operate with the least privileges required.
        Review untrusted inputs: Validate all external data sources such as parameters, cookies, and environment variables.
        """
    },
    "6-5": {
        "description": """The Path Traversal attack lets an attacker manipulate file path input (e.g., using ../, encoded or double-encoded sequences, backslashes, or NULL bytes) to access files or directories outside the web document root potentially revealing source code, configuration files, or executing unintended resources on the server.""",
        "recommendation": """
        
        Accept-known-good: Use strict allow-lists for filenames/paths (allowed characters, extensions, length) and reject everything else.
        Canonicalize before validate: Decode and canonicalize input once (e.g., realpath() or equivalent), then validate the canonical path against allowed directories.
        Disallow directory separators: Where feasible, forbid ../, /, \ and %00 in filename inputs; allow only a single dot for extensions when necessary.
        Fixed mapping: Map user inputs (IDs/tokens) to server-side filenames/URLs instead of using raw user-supplied paths.
        Store outside web root: Keep include/library/data files outside the web document root or restrict direct access via server config.
        Least privilege & sandboxing: Run processes with minimal OS privileges and, if possible, in chroot/containers or AppArmor/SELinux sandboxes.
        Avoid double-decoding pitfalls: Ensure inputs are decoded exactly once and validated after decoding to prevent bypasses.
        Use safe APIs: Prefer platform path APIs that normalize/canonicalize paths rather than manual string handling.
        Limit file access scope: Restrict file operations to an explicitly allowed directory tree and deny path traversal attempts at the boundary.
        Logging & monitoring: Log abnormal path requests and alert on repeated traversal attempts; test regularly (fuzzing) for traversal variants.
        """
    },
    "6-4": {
        "description": """The Path Traversal attack allows an attacker to access files, directories, or commands outside the web document root by manipulating input paths (e.g., using ../, encoded characters, or null bytes). This can expose sensitive files, source code, or configuration data. Even when web servers restrict traversal in URLs, applications may still be vulnerable if they handle user-supplied input improperly.""", 
        "recommendation": """
        
        Validate input strictly: Use an allow list for filenames and paths; reject all unexpected input.
        Canonicalize paths: Decode and normalize inputs (e.g., with realpath()) before validation to eliminate traversal sequences.
        Restrict directory access: Forbid directory separators (/, \) and multiple dots in file names; limit access to specific directories.
        Use fixed mappings: Map numeric IDs or tokens to actual filenames/URLs instead of using raw user input.
        Store files securely: Place include and resource files outside the web root or restrict access via server configuration.
        Run with least privilege: Execute code with minimal permissions and use sandboxing (e.g., chroot, AppArmor, SELinux) to contain impact.
        Avoid double-decoding: Ensure inputs are decoded only once and validated afterward to prevent filter bypasses.
        Use safe APIs: Prefer built-in functions that handle canonicalization and path resolution securely.
        Monitor for attacks: Log and alert on suspicious traversal patterns to detect exploitation attempts early.
        """
    },
    
    "6-3": {
        "description": """The Path Traversal attack lets an attacker manipulate path input (e.g., ../, encoded / double-encoded sequences, backslashes or %00) to access files or directories outside the web document root, potentially exposing source, config or other sensitive files.""", 
        "recommendation": """
        
        Accept-known-good: Use strict allow-lists for filenames/paths (characters, extensions, length); reject everything else.
        Canonicalize then validate: Decode once and normalize the path (e.g., realpath() or equivalent) before validating it.
        Disallow traversal chars: Forbid ../, /, \, NULL (%00) and dangerous encodings in filename inputs where feasible.
        Fixed mapping: Map user inputs (IDs/tokens) to server-side filenames/URLs instead of using raw user-supplied paths.
        Store outside web root: Keep include/library/data files outside the document root or restrict direct access via server config.
        Least privilege & sandboxing: Run processes with minimal OS privileges and, where possible, in chroot/containers or AppArmor/SELinux.
        Avoid double-decoding pitfalls: Ensure inputs are decoded exactly once and validated post-decoding to prevent bypasses.
        Use safe APIs: Prefer platform path APIs that normalize/canonicalize paths rather than manual string handling.
        Log & test: Log abnormal path requests, alert on repeated traversal patterns, and test (fuzz) for encoded/alternate traversal variants.
        """
    },
    "6-2": {
        "description": """The Path Traversal attack lets an attacker manipulate a path (e.g., ../, encoded/double-encoded sequences, backslashes or %00) to access files or directories outside the web document root, potentially exposing source code, configuration, or other sensitive files.""", 
        "recommendation": """
        
        Accept-known-good: Use strict allow-lists for filenames/paths (allowed characters, extensions, length) and reject all others.
        Canonicalize then validate: Decode once and normalize the path (e.g., realpath() or equivalent) before validating it.
        Disallow traversal characters: Forbid ../, directory separators (/, \), null bytes (%00) and dangerous encodings in filename inputs where feasible.
        Fixed mapping: Map limited, known input values (e.g., numeric IDs) to server-side filenames/URLs instead of using raw user-supplied paths.
        Store outside web root: Keep include/library/data files out of the document root or restrict direct access via server configuration.
        Least privilege & sandboxing: Run code with minimal OS privileges and, where possible, in chroot/containers or AppArmor/SELinux sandboxes.
        Avoid double-decoding pitfalls: Ensure inputs are decoded only once and validated after decoding to prevent bypasses.
        Use safe APIs: Prefer built-in path/canonicalization functions rather than ad-hoc string manipulation.
        Log & monitor: Log abnormal path requests and alert on repeated traversal patterns; regularly test for encoded/double-encoded variants.
        """
    },
    "6-1": {
        "description": """The Path Traversal attack lets an attacker manipulate path input (e.g. ../, encoded or double-encoded sequences, backslashes, or %00) to access files, directories or commands outside the web document root, potentially revealing source, configuration or other sensitive files.""",
        "recommendation": """
        
        Accept-known-good: Validate against a strict allow-list for filenames/paths (allowed characters, extensions, length); reject everything else.
        Canonicalize then validate: Decode once and normalize the path (e.g. realpath() or equivalent) before validating it.
        Disallow traversal characters: Where feasible forbid ../, directory separators (/, \), NULL (%00) and dangerous encodings in filename inputs.
        Fixed mapping: Map user inputs (IDs/tokens) to server-side filenames/URLs rather than using raw user input.
        Store outside web root: Keep include/library/data files out of the document root or restrict direct access via server configuration.
        Least privilege & sandboxing: Run code with minimal OS privileges and, where possible, in chroot/containers or AppArmor/SELinux sandboxes.
        Avoid double-decoding: Ensure inputs are decoded exactly once and validated after decoding to prevent bypasses.
        Use safe APIs: Prefer platform path/canonicalization functions rather than manual string manipulation.
        Limit file access scope: Restrict file operations to an explicit allowed directory tree and deny attempts outside that boundary.
        Log & test: Log abnormal path requests, alert on repeated traversal attempts, and regularly test (fuzz) for encoded/double-encoded variants.
        """
    }
}