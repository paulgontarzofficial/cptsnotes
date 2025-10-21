
Often referred to as spidering, is the automated process of systemically browsing the World Wide Web. 



**Breadth-first vs Depth-first Crawling:**

Breadth-first refers to the prioritizing of a websites width before going deep into the application. Starts by crawling all the links on the seed URL and goes through the others first before going deep. 

Depth-first refers to the following of a single path of links as far as possible before backtracking and exploring other paths. 

## Extracting Valuable Information:

Crawlers can extract a diverse array of data, each serving a specific purpose in the reconnaissance process:

- `Links (Internal and External)`: These are the fundamental building blocks of the web, connecting pages within a website (`internal links`) and to other websites (`external links`). Crawlers meticulously collect these links, allowing you to map out a website's structure, discover hidden pages, and identify relationships with external resources.
- `Comments`: Comments sections on blogs, forums, or other interactive pages can be a goldmine of information. Users often inadvertently reveal sensitive details, internal processes, or hints of vulnerabilities in their comments.
- `Metadata`: Metadata refers to `data about data`. In the context of web pages, it includes information like page titles, descriptions, keywords, author names, and dates. This metadata can provide valuable context about a page's content, purpose, and relevance to your reconnaissance goals.
- `Sensitive Files`: Web crawlers can be configured to actively search for sensitive files that might be inadvertently exposed on a website. This includes `backup files` (e.g., `.bak`, `.old`), `configuration files` (e.g., `web.config`, `settings.php`), `log files` (e.g., `error_log`, `access_log`), and other files containing passwords, `API keys`, or other confidential information. Carefully examining the extracted files, especially backup and configuration files, can reveal a trove of sensitive information, such as `database credentials`, `encryption keys`, or even source code snippets.

