# XML sucks. We all know, but sometimes that's all there is.





### Goal: Do the world a favor by converting weird XML to less weird JSON





Redhat regularly publishes XML files that contain information about security advisories with criteria that allow a host to be checked for vulnerabilities.  


The full set containing all vulnerability information can be downloaded here: http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml  


The file uses the Open Vulnerability and Assessment Language to describe security updates and their meta data.  


Your task is to convert that hard-to-handle XML into easier-to-handle JSON. Pay special attention to the structure of the 'criteria' - your output must follow this format:





```


{


	"advisory": [{


		"title": "RHSA-2013:0696: firefox security update (Critical)",


		"fixes_cve": ["CVE-2013-0788", "CVE-2013-0793", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0800"],


		"severity": "Critical",


		"affected_cpe": ["cpe:/o:redhat:enterprise_linux:5", "cpe:/o:redhat:enterprise_linux:6"],


		"criteria": [


			{"or": [


				{"and": [


					["version", "redhat-release", "pattern_match", "^5[^\\d]"],


					{"or": [


						{"AND": [


							["arch", "xulrunner", "pattern_match", "i386|ia64|ppc|ppc64|s390|s390x|x86_64"],


							["evr", "xulrunner", "less_than", "0:17.0.5-1.el5_9"],


							["signature_key_id", "xulrunner", "equals", "5326810137017186"]


						]},


						{"AND": [


							["arch", "xulrunner-devel", "pattern_match", "i386|ia64|ppc|ppc64|s390|s390x|x86_64"],


							["evr", "xulrunner-devel", "less_than", "0:17.0.5-1.el5_9"],


							["signature_key_id", "xulrunner-devel", "equals", "5326810137017186"]


						]},


						{"AND": [


							["arch", "firefox", "pattern_match", "i386|ia64|ppc|s390|s390x|x86_64"],


							["evr", "firefox", "less_than", "0:17.0.5-1.el5_9"],


							["signature_key_id", "firefox", "equals", "5326810137017186"]


						]}


					]}


				]},


				{"and": [


					{"or": [


						["version", "redhat-release-client", "pattern_match", "^6[^\\d]"],


						["version", "redhat-release-server", "pattern_match", "^6[^\\d]"],


						["version", "redhat-release-workstation", "pattern_match", "^6[^\\d]"],


						["version", "redhat-release-computenode", "pattern_match", "^6[^\\d]"]


					]},


					{"or": [


						{"and": [


							["arch", "xulrunner", "pattern_match", "i386|ia64|ppc|ppc64|s390|s390x|x86_64"],


							["evr", "xulrunner", "less_than", "0:17.0.5-1.el6_4"],


							["signature_key_id", "xulrunner", "equals", "199e2f91fd431d51"]


						]},


						{"and": [


							["arch", "xulrunner-devel", "pattern_match", "i386|ia64|ppc|ppc64|s390|s390x|x86_64"],


							["evr", "xulrunner-devel", "less_than", "0:17.0.5-1.el6_4"],


							["signature_key_id", "xulrunner-devel", "equals", "199e2f91fd431d51"]


						]},


						{"and": [


							["arch", "firefox", "pattern_match", "i386|ia64|ppc|s390|s390x|x86_64"],


							["evr", "firefox", "less_than", "0:17.0.5-1.el6_4"],


							["signature_key_id", "firefox", "equals", "199e2f91fd431d51"]


						]}


					]}


				]}


			]}


		]


	},


	{


		"title": "..."


	}


]}


```


(If you come across cases that are not handled in the above example output, choose an implementation that you think makes sense)





### Deliveries


- Your conversion script and the result when ran on the linked file containing all advisories


- A short writeup that explains your approach, any obstacles you encountered and how you would continue/improve the script in case you did not finish the challenge





The script and resulting JSON file should be delivered 4 hours after starting the challenge. The writeup can be completed after the challenge and should be delivered by the end of the day. You're free in your choices of programming language and libraries.





### Have fun and good luck!