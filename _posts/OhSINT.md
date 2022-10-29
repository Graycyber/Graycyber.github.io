- So I download the and view it using `eog` tool
![](OhSINT_assets/Pasted%20image%2020221025133409.png)
- then i view the metadata of the image using exiftool and then got the name of the person as OWoodflint
![](OhSINT_assets/Pasted%20image%2020221025113608.png)
- checking google for the name found, i see different results from twitter, github and wordpress
![](OhSINT_assets/Pasted%20image%2020221025133600.png)
- viewing the twitter page of the person, I can see the persons profile
![](OhSINT_assets/Pasted%20image%2020221025113639.png)
- scrolling through the tweets, I get a BSSID of an access point
![](OhSINT_assets/Pasted%20image%2020221025113654.png)
- so using Wigle.net I search for the BSSID, and i discover the locations London and also the SSID of that access point as UnileverWiFi
![](OhSINT_assets/Pasted%20image%2020221025120342.png)
- Looking at the github page, I got the gmail of the user
![](OhSINT_assets/Pasted%20image%2020221025120139.png)
- then looking at the wordpress site of the user, i dicscoverd the current location of the user
![](OhSINT_assets/Pasted%20image%2020221025120754.png)
- looking at the /robots.txt of the site, i got some directories
![](OhSINT_assets/Pasted%20image%2020221025121426.png)
- viewing the /next directory, i got a clue to look at the monthly archives
![](OhSINT_assets/Pasted%20image%2020221025121448.png)
- then going further, i then noted the username of the user as owoodflint, which is a valid username
![](OhSINT_assets/Pasted%20image%2020221025121825.png)
- now i'll be bruteforcing for the password and the username as owoodflint and could verify it by trying to login with a false password
![](OhSINT_assets/Pasted%20image%2020221025134829.png)
- now looking for the password, i noticed from the google results a word pennYDr0pper but i couldn't see it on the page
![](OhSINT_assets/Pasted%20image%2020221025131047.png)
- so using the find feature, i found that it was hidden and could be viewed if highlighted and also can be viewed if the page is inspected, then i got the password
![](OhSINT_assets/Pasted%20image%2020221025131001.png)


