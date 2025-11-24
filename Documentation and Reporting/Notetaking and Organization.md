
Some notetaking structures that we cover when we are taking notes are as follows: 
- Attack Path: An outline of the entire path if you gain a foothold during an external pen test or compromise one or more hosts during an internal pentest. Outline the path using screenshots and commnd output. 
- Credentials: A centralized place to keep your compromised creds and secrets. 
- Findings: Recommend creating a subfolder for each finding and then writing our narrative and saving it in the folder aling with any evidence. 
- Vulnerability Scan Research: Section that is used document the vulnerabilities that have been researched and tried to avoid doing work over again. 
- Service Enumeration Research: A section to take notes on which services you've investigated, failed exploitation attempts, promising vulnerabilities/misconfigurations. 
- Web Application Research: Section of notes that we can note down any interesting web applications found through various methods. Scanning for common web ports, and running tools such as Aquatone or EyeWitness to screenshot all applications. As we review the screenshot report, note down apps of interest, commno/default credential pairs you tried. 
- AD Enumeration Research: A section to show, step-by-step, what Active Directory enumeration you've already performed. Note down any areas of interest you need to run down later in the assessment. 
- OSINT: A section to keep track of interesting information you've gathered via OSINT. 
- Administrative Information: Some may find that it is helpful to have centralized location to staore contact information for other project stakeholders like Project Managers or client Points of Contacts, unique objectives/flags  defined in the Rules of Engagement (RoE), and other items that you find yourself often referencing throughout the project. 
- Scoping Information: Here, we can store information about in-scope IP addresses/CIDR ranges, web application, URLs, and any credentials for web applications, VPN, or AD provided by the client. 
- Activity Log: High-level tracking of everything you did during the assessment for possible event correlation. 
- Payload Log: Similar to the activity log, tracking the payloads you're using (and a file hash for anything uploaded and the upload location) in a client environment is critical.

-----
### Notetaking Tools

|   |   |   |
|---|---|---|
|[CherryTree](https://www.giuspen.com/cherrytree/)|[Visual Studio Code](https://code.visualstudio.com/)|[Evernote](https://evernote.com/)|
|[Notion](https://www.notion.so/)|[GitBook](https://www.gitbook.com/)|[Sublime Text](https://www.sublimetext.com/)|
|[Notepad++](https://notepad-plus-plus.org/downloads/)|[OneNote](https://www.onenote.com/?public=1)|[Outline](https://www.getoutline.com/)|
|[Obsidian](https://obsidian.md/)|[Cryptpad](https://cryptpad.fr/)|[Standard Notes](https://standardnotes.com/)|

---
### Logging 

This is an essential part of notetaking where we can use terminal output to show results of commands. This can also be used to look back in case we forget a part of our notes. 

**Exploitation Attempts**
[Tmux logging](https://github.com/tmux-plugins/tmux-logging) is an excellent choice for terminal logging, and we should absolutely be using Tmux along with logging as this will save every single thing that we type into a Tmux pane to a log file. 

**Cloning the Tmux Plugin Manager**
```shell-session
realCustampin@htb[/htb]$ git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

**Creating the tmux.conf**
```shell-session
realCustampin@htb[/htb]$ touch .tmux.conf
```

**Inserting tmux.conf Configurations into File**
```shell-session
realCustampin@htb[/htb]$ cat .tmux.conf 

# List of plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# Initialize TMUX plugin manager (keep at bottom)
run '~/.tmux/plugins/tpm/tpm'
```

**Sourcing the tmux.conf After Config Changes**
```shell-session
realCustampin@htb[/htb]$ tmux source ~/.tmux.conf 
```

Next, we can start a new Tmux session (i.e., `tmux new -s setup`).

Once in the session, type `[Ctrl] + [B]` and then hit `[Shift] + [I]` (or `prefix` + `[Shift] + [I]` if you are not using the default prefix key), and the plugin will install (this could take around 5 seconds to complete).

Once the plugin is installed, start logging the current session (or pane) by typing `[Ctrl] + [B]` followed by `[Shift] + [P]` (`prefix` + `[Shift] + [P]`) to begin logging. If all went as planned, the bottom of the window will show that logging is enabled and the output file. To stop logging, repeat the `prefix` + `[Shift] + [P]` key combo or type `exit` to kill the session. Note that the log file will only be populated once you either stop logging or exit the Tmux session.

Once logging is complete, you can find all commands and output in the associated log file. See the demo below for a short visual on starting and stopping Tmux logging and viewing the results.

If we forget to enable Tmux logging and are deep into a project, we can perform retroactive logging by typing `[Ctrl] + [B]` and then hitting `[Alt] + [Shift] + [P]` (`prefix` + `[Alt] + [Shift] + [P]`), and the entire pane will be saved. The amount of saved data depends on the Tmux `history-limit` or the number of lines kept in the Tmux scrollback buffer. If this is left at the default value and we try to perform retroactive logging, we will most likely lose data from earlier in the assessment. To safeguard against this situation, we can add the following lines to the `.tmux.conf` file (adjusting the number of lines as we please):

