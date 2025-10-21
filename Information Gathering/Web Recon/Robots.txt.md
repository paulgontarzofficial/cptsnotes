
- The basic list of where bots are allowed to interact with and other locations where the bots are disallowed. 

```txt
User-agent: *
Disallow: /private/
```
- All user-agents are not allowed to view /private/ 

## Structure

User-agent: Specifies which crawler or bot the following rules apply to. A wildcard indicate rules apply to all bots. 

Directives: Provide specific instructions to the identified user-agent. 

| Directive     | Description                                                                                                        | Example                                                      |
| ------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| `Disallow`    | Specifies paths or patterns that the bot should not crawl.                                                         | `Disallow: /admin/` (disallow access to the admin directory) |
| `Allow`       | Explicitly permits the bot to crawl specific paths or patterns, even if they fall under a broader `Disallow` rule. | `Allow: /public/` (allow access to the public directory)     |
| `Crawl-delay` | Sets a delay (in seconds) between successive requests from the bot to avoid overloading the server.                | `Crawl-delay: 10` (10-second delay between requests)         |
| `Sitemap`     | Provides the URL to an XML sitemap for more efficient crawling.                                                    | `Sitemap: https://www.example.com/sitemap.xml`               |

Example of robots.txt:
```txt
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/

User-agent: Googlebot
Crawl-delay: 10

Sitemap: https://www.example.com/sitemap.xml
```
- All users are disallowed from accessing /admin/ and /private/ however can access /public/
- Googlebot (Googles Web Crawler) is specifically instructed to wait 10 seconds between requests.
- Sitemap is located at https://www.example.com/sitemap.xml for faster and easier web crawling. 