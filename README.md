# SickProdigy Adguard Home Filter List

My personal adguard home blocker/unblocker list

Installation
## adblocker filters

Options
1. Use a browser which supports extensions/add-ons and install an adblocker (like uBlock Origin or AdGuard).
2. Use software like adguard home or pi-hole
Now add custom (content)filter from here: [(copy link)](https://gitea.rcs1.xyz/sickprodigy/adguard-list/raw/branch/main/assets/Filter-1.txt):

This is mainly to block out some of the missing trackers and bad actors that are still able to load into my network.
Use in congruent with any other filters. This filter actually unblocks some sites to make them usable ex t.co, you can't navigate twitter/x links without expecting a t.co transfer link. 

A lot of time for paywall sites you can just disable javascript and a lot of functions will disappear.
Other times you will need userscripts i believe. magnolia1234 has explained it well in their scripts if interested. 

Newest issue on iphone is random error-report.com website showing up and not being able to see what's going on. Or maybe sites just not working because the domain is blocked or something? Not sure. Added additional filters to allow error-report.com and html-load.com to improve site accessibility

html-load.com was for sourceforge not working and wanted to download templeos. May want to access that site later so trying to block but also allow it. 
Need to selfhost their min.json file to fake it but never finished that. Really complicated but there is 1-2 lines I think you can add/remove to bypass or at least force checks true html-load.com