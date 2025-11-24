The findings section is our meat of the report. This is where we showcase the what we found, how we exploited them, and the give the client guidance on how we can remediate the finding. 

### Breakdown of Findings
- Each finding should have the same general type of information that should be customized to your client's specific circumstances. At a minimum, the following information should be included for each finding: 
	- Description of the finding and what platform the vulnerability affects. 
	- Impact if the finding is left unresolved
	- Affected systems, networks, environments, or applications. 
	- Recommendation for how to address the problem. 
	- Reference links with additional information about the finding and resolving it. 
	- Steps to reproduce the issue and the evidence that you collected. 

--------
### Showing Finding Reproduction Steps Adequately
- When we are showing our findings, we can easily get caught up in being too complex. Most likely, if the client is not a penetration tester themselves, it is going to be hard for them to understand where the beginning of a test is all the way to the end. Some concepts to consider are:
	- Break each step into its own figure. If you perform multiple steps in the same figure, a reader unfamiliar with the tools being used may not understand what is taking place, much less have an idea of how to reproduce it themselves.
    
	- If setup is required (e.g., Metasploit modules), capture the full configuration so the reader can see what the exploit config should look like before running the exploit. Create a second figure that shows what happens when you run the exploit.
    
	- Write a narrative between figures describing what is happening and what is going through your head at this point in the assessment. Do not try to explain what is happening in the figure with the caption and have a bunch of consecutive figures.
    
	- After walking through your demonstration using your preferred toolkit, offer alternative tools that can be used to validate the finding if they exist (just mention the tool and provide a reference link, don't do the exploit twice with more than one tool).

---------
### Effective Remediation Recommendations 

**Example 1:**
- Bad: Reconfigure registry settings to harden against X. 
- Good: To fully remediate this finding, the following registry hives should be updated with the specified values. Note that changes to critical components like the registry should be approached with caution and tested in a small group prior to making large-scale changes. 

**Rationale**

While the "bad" example is at least somewhat helpful, it's fairly lazy, and you're squandering a learning opportunity. Once again, the reader of this report may not have the depth of experience in Windows as you, and giving them a recommendation that will require hours' worth of work for them to figure out how to do it is only going to frustrate them. Do your homework and be as specific as reasonably possible. Doing so has the following benefits:

- You learn more this way and will be much more comfortable answering questions during the report review. This will reinforce the client's confidence in you and will be knowledge that you can leverage on future assessments and to help level up your team.
    
- The client will appreciate you doing the research for them and outlining specifically what needs to be done so they can be as efficient as possible. This will increase the likelihood that they will ask you to do future assessments and recommend you and your team to their friends.
    

It's also worth drawing attention to the fact that the "good" example includes a warning that changing something as important as the registry carries its own set of risks and should be performed with caution. Again, this indicates to the client that you have their best interests in mind and genuinely want them to succeed. For better or worse, there will be clients that will blindly do whatever you tell them to and will not hesitate to try and hold you accountable if doing so ends up breaking something.